"""Shared plumbing for the scanner adapters: types, subprocess exec, parsing.

Moved here from the Rotsy server (``backend/app/modules/nexus/base.py``) when
scanner execution left it. The guarantees travelled with the code:

  * **Static analysis only.** :func:`assert_static_ref` refuses any reference
    that would read from a container runtime or the local filesystem, checked
    at the last moment before a scanner starts. Nothing is ever run as a
    container; the runner has no container runtime to run one with.
  * **Credentials never on the command line.** Scanners receive the job's
    registry credential through environment variables only, so it stays out of
    the process table; the operator-facing command line is redacted anyway.
  * **Bounded.** Every invocation has a wall-clock limit, and a timeout or a
    cancellation kills the child process before returning — a cancelled job
    never leaves a scanner running.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
from dataclasses import dataclass, field
from typing import Any

# Stereoscope/Trivy source prefixes that would read from a container runtime or
# the local filesystem instead of the registry.
_RUNTIME_SCHEMES = (
    "docker:",
    "podman:",
    "containerd:",
    "docker-archive:",
    "oci-archive:",
    "oci-dir:",
    "singularity:",
    "dir:",
    "file:",
    "sbom:",
)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")

#: Environment variables a scanner subprocess inherits from the runner. Nothing
#: else passes through: not the runner credential (it is never in the
#: environment anyway), not an ambient HTTP(S)_PROXY that could route the
#: registry pull somewhere other than the Rotsy server.
_INHERITED_ENV = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ", "SSL_CERT_FILE", "SSL_CERT_DIR")


@dataclass
class Credentials:
    """The job-scoped registry credential for the Rotsy registry proxy."""

    username: str
    password: str


@dataclass
class ScanOutcome:
    """Result of one scanner invocation against one image."""

    scanner: str
    ok: bool
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""
    detail: str = ""  # redacted command + exit code + output tail, for the operator
    duration_ms: int = 0
    tool_version: str = ""
    db_version: str = ""


def assert_static_ref(image_ref: str) -> None:
    """Guard the no-runtime invariant at the last possible moment."""
    lowered = image_ref.lower()
    for scheme in _RUNTIME_SCHEMES:
        if lowered.startswith(scheme):
            raise ValueError(
                f"refusing to scan '{image_ref}': the '{scheme.rstrip(':')}' source reads from a "
                "container runtime or the local filesystem. This system performs registry-only "
                "static analysis and never starts containers."
            )


def redact(args: list[str], secrets: list[str]) -> str:
    """Render a command line for operator display with secrets removed."""
    rendered = " ".join(args)
    for secret in secrets:
        if secret:
            rendered = rendered.replace(secret, "***")
    return rendered


def scanner_env(extra: dict[str, str]) -> dict[str, str]:
    base = {k: v for k, v in os.environ.items() if k in _INHERITED_ENV}
    return {**base, **extra}


async def exec_scanner(
    args: list[str],
    env: dict[str, str],
    timeout: float,  # NOSONAR
) -> tuple[int, str, str]:
    """Run a scanner (argv, never a shell), capturing stdout and stderr apart.

    ``timeout`` and the kill-on-expiry are one unit: only this function holds
    the process handle, so only it can guarantee the child is gone. The same
    holds for cancellation — a cancelled job kills its scanner here, then
    re-raises.
    """
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        # Its own process group, so a kill reaches anything it spawned too —
        # a surviving grandchild would hold the pipes open and the job with them.
        start_new_session=True,
    )
    try:
        async with asyncio.timeout(timeout):
            stdout, stderr = await proc.communicate()
    except TimeoutError:
        await kill_tree(proc)
        raise TimeoutError(f"scanner exceeded {timeout:.0f}s") from None
    except asyncio.CancelledError:
        await kill_tree(proc)
        raise
    return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")


async def kill_tree(proc: asyncio.subprocess.Process) -> None:
    """SIGKILL a subprocess's whole process group and reap it."""
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        async with asyncio.timeout(10):
            await proc.wait()
    except TimeoutError:  # pragma: no cover - a process that survives SIGKILL is not ours to fix
        pass


def tail(text: str, limit: int = 2000) -> str:
    """Last ``limit`` characters of scanner output — the part that explains why."""
    cleaned = text.strip()
    return cleaned if len(cleaned) <= limit else "…" + cleaned[-limit:]


def parse_json_report(text: str) -> dict[str, Any]:
    """Parse a scanner's JSON report, tolerating log lines printed before it.

    Grype logs warnings to stdout when talking to a plaintext registry (e.g.
    ``[0000] WARN registry communication is insecure``), ahead of the document.
    """
    if not text or not text.strip():
        return {}
    start = text.find("{")
    if start <= 0:
        return json.loads(text)
    return json.loads(text[start:])


def first_error_line(stderr: str) -> str:
    """Most explanatory single line of a scanner's stderr."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    for line in reversed(lines):
        lowered = line.lower()
        if any(
            token in lowered
            for token in ("error", "fatal", "failed", "denied", "refused", "unauthorized", "not found", "no such host")
        ):
            return line[:500]
    return lines[-1][:500] if lines else ""
