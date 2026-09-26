"""Trivy adapter: invoke the binary, parse its JSON report.

Moved from the Rotsy server with its guarantees intact, plus the ones an
offline runner needs:

  * ``--image-src remote`` — read the image from the registry (the Rotsy proxy)
    only, never a local docker/containerd/podman daemon;
  * ``--skip-db-update`` / ``--skip-java-db-update`` — the database is the one
    the Rotsy server published and the runner installed; Trivy must never try
    to fetch one mid-scan (on an offline runner that would fail the scan);
  * ``--offline-scan`` — no lookups against Maven Central or any other API to
    identify dependencies;
  * ``--skip-version-check`` — no call home to check for a newer Trivy.

Trivy's cache is a BoltDB file one process can hold at a time, so runs are
serialised with :data:`TRIVY_LOCK` (a runner with concurrency > 1 overlaps
Grype scans, not Trivy scans).
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

from .base import (
    Credentials,
    ScanOutcome,
    assert_static_ref,
    exec_scanner,
    first_error_line,
    parse_json_report,
    redact,
    scanner_env,
    tail,
)

TRIVY_LOCK = asyncio.Lock()
_METADATA = "metadata.json"


def cvss(entry: dict[str, Any]) -> float:
    """Highest CVSS score any vendor assigned, preferring v3 over v2."""
    best = 0.0
    for vendor in (entry.get("CVSS") or {}).values():
        if not isinstance(vendor, dict):
            continue
        for key in ("V3Score", "V2Score"):
            try:
                best = max(best, float(vendor.get(key) or 0))
            except (TypeError, ValueError):
                continue
    return best


def parse(raw: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in raw.get("Results") or []:
        for entry in result.get("Vulnerabilities") or []:
            findings.append(
                {
                    "cve": entry.get("VulnerabilityID") or entry.get("CVE") or "UNKNOWN",
                    "severity": (entry.get("Severity") or "UNKNOWN").upper(),
                    "package": entry.get("PkgName") or "",
                    "installed_version": entry.get("InstalledVersion") or "",
                    "fixed_version": entry.get("FixedVersion") or "",
                    "title": entry.get("Title") or (entry.get("Description") or "")[:200],
                    "cvss": cvss(entry),
                }
            )
    return findings


def build_args(binary: str, cache_dir: Path, image_ref: str, *, insecure: bool, tool_timeout: str) -> list[str]:
    args = [
        binary,
        "image",
        "--quiet",
        "--format",
        "json",
        # OS packages + language dependencies; secret/misconfig scanning needs
        # neither and would slow every scan down.
        "--scanners",
        "vuln",
        "--image-src",
        "remote",
        "--skip-db-update",
        "--offline-scan",
        "--skip-version-check",
        "--cache-dir",
        str(cache_dir),
        "--timeout",
        tool_timeout,
    ]
    # --skip-java-db-update is only valid once a Java DB is present (Trivy
    # rejects it on a "first run"); the runner installs the server's Java DB
    # when one is published.
    if (cache_dir / "java-db" / _METADATA).is_file():
        args.append("--skip-java-db-update")
    if insecure:
        args.append("--insecure")
    args.append(image_ref)
    return args


def db_version(cache_dir: Path) -> str:
    try:
        meta = json.loads((cache_dir / "db" / _METADATA).read_text())
    except (OSError, ValueError):
        return ""
    return str(meta.get("UpdatedAt") or "")[:64]


async def run(
    binary: str,
    cache_dir: Path,
    image_ref: str,
    creds: Credentials,
    *,
    insecure: bool,
    timeout: float,
    tool_version: str = "",
) -> ScanOutcome:
    """Scan ``image_ref`` with Trivy, reading it from the registry only."""
    assert_static_ref(image_ref)
    args = build_args(binary, cache_dir, image_ref, insecure=insecure, tool_timeout=f"{max(30, int(timeout) - 15)}s")
    env = scanner_env(
        {
            # Credentials via the environment so they stay out of the process table.
            "TRIVY_USERNAME": creds.username,
            "TRIVY_PASSWORD": creds.password,
            "TRIVY_NO_PROGRESS": "true",
            "TRIVY_SKIP_VERSION_CHECK": "true",
            **({"TRIVY_INSECURE": "true", "TRIVY_NON_SSL": "true"} if insecure else {}),
        }
    )
    shown = redact(args, [creds.password])
    started = time.monotonic()
    async with TRIVY_LOCK:
        try:
            code, stdout, stderr = await exec_scanner(args, env, timeout)
        except TimeoutError as exc:
            return ScanOutcome(
                "trivy",
                False,
                error=str(exc),
                detail=f"$ {shown}",
                duration_ms=int((time.monotonic() - started) * 1000),
                tool_version=tool_version,
            )
    elapsed = int((time.monotonic() - started) * 1000)
    detail = redact([f"$ {shown}\nexit {code}\n{tail(stderr or stdout)}"], [creds.password])
    common = {
        "detail": detail,
        "duration_ms": elapsed,
        "tool_version": tool_version,
        "db_version": db_version(cache_dir),
    }
    if code != 0:
        return ScanOutcome("trivy", False, error=first_error_line(stderr) or f"trivy exited {code}", **common)
    try:
        raw = parse_json_report(stdout)
    except json.JSONDecodeError as exc:
        return ScanOutcome("trivy", False, error=f"could not parse trivy JSON output: {exc}", **common)
    return ScanOutcome("trivy", True, parse(raw), **common)
