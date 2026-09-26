"""Install and track the scanner binaries and databases the server hands out.

The server publishes a manifest: for this runner's platform, which artifact
(by SHA-256) of each tool it should have. :meth:`ToolManager.sync` reconciles
towards it. The rules, each enforced here:

* **Only from the Rotsy server.** Artifacts are downloaded through
  :class:`~rotsy_runner.client.ServerClient`, which refuses any path that is
  not the server's artifact endpoint. No vendor URL exists in this codebase.
* **Verified before use.** The download's SHA-256 must equal the manifest's,
  or it is deleted. A binary must additionally run and report the version the
  server said it is before it is activated; a Grype database must pass
  ``grype db status``.
* **Atomic.** A new version is unpacked beside the old one and switched in with
  a single rename (a symlink swap for binaries, a directory swap for
  databases). A failed or partial install never replaces a working version —
  the previous one keeps scanning, and the failure is reported.
* **Rollback is cheap.** The previous binary version stays on disk; if the
  server's desired version goes back to it, activation is a symlink swap with
  no download.
* **Backoff.** A failing install is retried with exponential backoff, not on
  every heartbeat.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import tarfile
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..client import ClientError, ServerClient
from ..config import Config
from ..protocol import DesiredArtifact, DesiredTools
from ..scanners.base import kill_tree, scanner_env
from ..scanners.grype import db_env as grype_db_env
from .locks import RWLock
from .specs import BINARY, SPECS, ToolSpec, install_order, required_for

logger = logging.getLogger(__name__)

_MAX_BINARY_BYTES = 800 * 1024 * 1024
_PROBE_TTL = 300.0
_BACKOFF_MAX = 1800.0


class InstallError(Exception):
    """An artifact could not be installed; the working version is untouched."""


@dataclass
class InstalledTool:
    name: str
    kind: str
    version: str = ""
    sha256: str = ""
    status: str = "missing"  # installed | installing | failed | missing
    error: str = ""
    path: str = ""
    installed_at: float = 0.0
    previous: dict[str, Any] | None = None
    # Backoff for a failing target artifact.
    failed_sha256: str = ""
    failures: int = 0
    next_retry: float = 0.0
    extra: dict[str, Any] = field(default_factory=dict)


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", value).strip(".-")[:100]
    if not cleaned:
        raise InstallError(f"unusable name {value!r}")
    return cleaned


class ToolManager:
    def __init__(self, config: Config) -> None:
        self._config = config
        self._state_file = config.state_dir / "tools.json"
        self._inventory: dict[str, InstalledTool] = {}
        self._probe_cache: dict[str, tuple[float, bool, str]] = {}
        self.locks: dict[str, RWLock] = {"trivy": RWLock(), "grype": RWLock()}
        self._sync_lock = asyncio.Lock()
        self.syncing = False
        self._load()

    # --- paths --------------------------------------------------------------------
    @property
    def trivy_cache_dir(self) -> Path:
        return self._config.cache_dir / "trivy"

    @property
    def grype_db_dir(self) -> Path:
        return self._config.cache_dir / "grype"

    def _tool_dir(self, name: str) -> Path:
        return self._config.tools_dir / _safe_name(name)

    # --- persistence ------------------------------------------------------------------
    def _load(self) -> None:
        try:
            data = json.loads(self._state_file.read_text())
        except (OSError, ValueError):
            return
        for name, record in (data or {}).items():
            if name in SPECS and isinstance(record, dict):
                known = {k: v for k, v in record.items() if k in InstalledTool.__dataclass_fields__}
                self._inventory[name] = InstalledTool(**known)
        # An install that was running when the runner died is not installed.
        for record in self._inventory.values():
            if record.status == "installing":
                record.status = "installed" if record.path and Path(record.path).exists() else "failed"
                record.error = record.error or "interrupted by a runner restart"

    def _save(self) -> None:
        self._state_file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state_file.with_name("tools.json.tmp")
        tmp.write_text(json.dumps({n: asdict(r) for n, r in self._inventory.items()}, indent=2))
        os.replace(tmp, self._state_file)

    def record(self, name: str) -> InstalledTool | None:
        return self._inventory.get(name)

    # --- readiness -----------------------------------------------------------------------
    def binary(self, name: str) -> Path | None:
        record = self._inventory.get(name)
        if record is None or not record.path or record.kind != BINARY:
            return None
        path = Path(record.path)
        return path if path.is_file() and os.access(path, os.X_OK) else None

    def _present(self, name: str) -> tuple[bool, str]:
        spec = SPECS[name]
        record = self._inventory.get(name)
        if record is None or not record.sha256 or record.status not in ("installed", "failed"):
            return False, "not installed"
        if spec.installer == "binary":
            return (self.binary(name) is not None), "executable missing"
        if spec.installer == "trivy-db":
            target = self.trivy_cache_dir / spec.target_subdir
            missing = [f for f in spec.required_files if not (target / f).is_file()]
            return (not missing), f"missing {', '.join(missing)}"
        if spec.installer == "grype-db":
            # Never shell out here (this runs on the event loop, e.g. for every
            # heartbeat): use the last probe, refreshed off-loop by refresh_probes.
            cached = self._probe_cache.get(str(self.grype_db_dir))
            return (cached[1], cached[2]) if cached else (False, "database not verified yet")
        return False, "unknown installer"

    def _grype_db_usable(self, db_dir: Path, *, fresh: bool = False) -> tuple[bool, str]:
        key = str(db_dir)
        cached = self._probe_cache.get(key)
        if cached and not fresh and time.monotonic() - cached[0] < _PROBE_TTL:
            return cached[1], cached[2]
        grype = self.binary("grype")
        has_db = db_dir.exists() and any(db_dir.rglob("vulnerability.db"))
        if grype is None:
            result = (False, "grype binary not installed")
        elif not has_db:
            result = (False, "no grype database installed")
        else:
            import subprocess  # local: the only synchronous subprocess, run off the event loop by callers

            try:
                proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                    [str(grype), "db", "status"], capture_output=True, text=True, timeout=60,
                    env=scanner_env(grype_db_env(db_dir)),
                )
                output = f"{proc.stdout}\n{proc.stderr}"
                ok = proc.returncode == 0 and "invalid" not in output.lower()
                result = (ok, "" if ok else (output.strip().splitlines() or ["grype db status failed"])[-1][:300])
            except (OSError, subprocess.SubprocessError) as exc:
                result = (False, f"grype db status failed: {exc}")
        self._probe_cache[key] = (time.monotonic(), *result)
        return result

    def ready_for(self, scanner: str) -> tuple[bool, str]:
        for name in required_for(scanner):
            ok, why = self._present(name)
            if not ok:
                return False, f"{name}: {why}"
        return True, ""

    async def refresh_probes(self, *, force: bool = False) -> None:
        """Re-check database usability off the event loop (it shells out).

        Cheap to call often: it only probes when the last result is older than
        the probe TTL, or when forced (after an install).
        """
        if "grype-db" not in self._inventory:
            return
        cached = self._probe_cache.get(str(self.grype_db_dir))
        if force or cached is None or time.monotonic() - cached[0] >= _PROBE_TTL:
            await asyncio.to_thread(self._grype_db_usable, self.grype_db_dir, fresh=True)

    def report(self) -> list[dict[str, Any]]:
        """Inventory in the heartbeat's ``tools`` shape."""
        out = []
        for name in install_order(list(self._inventory)):
            record = self._inventory[name]
            ready, why = self._present(name)
            status = record.status
            if status == "failed" and ready:
                status = "installed"  # the previous version still works; the error says what did not
            out.append({
                "name": name, "kind": record.kind, "version": record.version[:64], "sha256": record.sha256,
                "status": status, "ready": bool(ready and status == "installed"),
                "error": (record.error or ("" if ready else why))[:2000],
            })
        return out

    # --- sync -------------------------------------------------------------------------
    async def sync(self, client: ServerClient, manifest: DesiredTools | None = None, *, force: bool = False) -> dict:
        """Reconcile installed tools with the server's manifest. One at a time."""
        async with self._sync_lock:
            self.syncing = True
            try:
                manifest = manifest or await client.desired_tools()
                return await self._sync(client, manifest, force=force)
            finally:
                self.syncing = False

    async def _sync(self, client: ServerClient, manifest: DesiredTools, *, force: bool) -> dict:
        # Know what actually works before deciding what to (re)install.
        await self.refresh_probes()
        by_name = {a.name: a for a in manifest.artifacts}
        summary: dict[str, str] = {}
        for name in install_order(list(by_name)):
            artifact = by_name[name]
            spec = SPECS[name]
            record = self._inventory.get(name)
            if not artifact.available or not artifact.download_path or not artifact.sha256:
                summary[name] = "unavailable"
                if record is None:
                    self._inventory[name] = InstalledTool(name=name, kind=spec.kind, status="missing",
                                                          error=artifact.reason[:500])
                continue
            if record and record.sha256 == artifact.sha256 and record.status == "installed" and self._present(name)[0]:
                summary[name] = "current"
                continue
            if (record and record.failed_sha256 == artifact.sha256 and not force
                    and time.time() < record.next_retry):
                summary[name] = "backoff"
                continue
            if spec.installer == "binary" and await self._reactivate(spec, artifact):
                summary[name] = "reactivated"
                continue
            summary[name] = await self._install_one(client, spec, artifact)
        self._save()
        await self.refresh_probes(force=True)
        logger.info("Tool sync finished: %s", ", ".join(f"{k}={v}" for k, v in summary.items()) or "nothing to do")
        return summary

    async def _install_one(self, client: ServerClient, spec: ToolSpec, artifact: DesiredArtifact) -> str:
        record = self._inventory.get(spec.name) or InstalledTool(name=spec.name, kind=spec.kind)
        self._inventory[spec.name] = record
        before = asdict(record)
        record.status = "installing" if not record.sha256 else record.status
        self._save()
        download = self._config.downloads_dir / f"{artifact.sha256[:16]}-{_safe_name(artifact.filename or spec.name)}"
        logger.info("Installing %s %s (sha256 %s…)", spec.name, artifact.version, artifact.sha256[:12])
        try:
            await client.download(artifact.download_path, download, expected_sha256=artifact.sha256,
                                  expected_size=artifact.size_bytes)
            path = await self._install(spec, artifact, download)
        except (ClientError, InstallError, OSError, tarfile.TarError) as exc:
            reason = f"install of {spec.name} {artifact.version} failed: {exc}"
            logger.warning("%s", reason)
            restored = InstalledTool(**{k: v for k, v in before.items() if k in InstalledTool.__dataclass_fields__})
            restored.status = "installed" if restored.sha256 and self._present_record(restored) else "failed"
            restored.error = reason[:2000]
            restored.failed_sha256 = artifact.sha256
            restored.failures = (before.get("failures", 0) or 0) + 1 if before.get("failed_sha256") == artifact.sha256 else 1
            restored.next_retry = time.time() + min(_BACKOFF_MAX, 30.0 * (2 ** (restored.failures - 1)))
            self._inventory[spec.name] = restored
            self._save()
            return "failed"
        finally:
            download.unlink(missing_ok=True)
        previous = {k: before[k] for k in ("version", "sha256", "path")} if before.get("sha256") else None
        self._inventory[spec.name] = InstalledTool(
            name=spec.name, kind=spec.kind, version=artifact.version, sha256=artifact.sha256, status="installed",
            path=str(path), installed_at=time.time(), previous=previous,
        )
        self._save()
        logger.info("Installed %s %s", spec.name, artifact.version)
        return "installed"

    def _present_record(self, record: InstalledTool) -> bool:
        current = self._inventory.get(record.name)
        self._inventory[record.name] = record
        try:
            return self._present(record.name)[0]
        finally:
            if current is not None:
                self._inventory[record.name] = current

    async def _reactivate(self, spec: ToolSpec, artifact: DesiredArtifact) -> bool:
        """Switch back to an already-unpacked version (rollback) without downloading."""
        version_dir = self._tool_dir(spec.name) / f"{_safe_name(artifact.version)}-{artifact.sha256[:12]}"
        exe = version_dir / (spec.executable or spec.name)
        marker = version_dir / ".sha256"
        if not exe.is_file() or not marker.is_file() or marker.read_text().strip() != artifact.sha256:
            return False
        await self._probe_version(spec, exe, artifact.version)
        record = self._inventory.get(spec.name)
        previous = {"version": record.version, "sha256": record.sha256, "path": record.path} if record else None
        self._switch_current(spec.name, version_dir)
        self._inventory[spec.name] = InstalledTool(
            name=spec.name, kind=spec.kind, version=artifact.version, sha256=artifact.sha256, status="installed",
            path=str(exe), installed_at=time.time(), previous=previous,
        )
        logger.info("Re-activated %s %s from disk", spec.name, artifact.version)
        return True

    # --- installers ---------------------------------------------------------------------
    async def _install(self, spec: ToolSpec, artifact: DesiredArtifact, archive: Path) -> Path:
        if spec.installer == "binary":
            return await self._install_binary(spec, artifact, archive)
        if spec.installer == "trivy-db":
            return await self._install_trivy_db(spec, archive)
        if spec.installer == "grype-db":
            return await self._install_grype_db(archive)
        raise InstallError(f"no installer for {spec.name}")

    async def _install_binary(self, spec: ToolSpec, artifact: DesiredArtifact, archive: Path) -> Path:
        tool_dir = self._tool_dir(spec.name)
        tool_dir.mkdir(parents=True, exist_ok=True)
        staging = tool_dir / f".staging-{uuid.uuid4().hex[:8]}"
        staging.mkdir()
        try:
            exe = staging / (spec.executable or spec.name)
            await asyncio.to_thread(_extract_single, archive, spec.executable or spec.name, exe)
            await self._probe_version(spec, exe, artifact.version)
            (staging / ".sha256").write_text(artifact.sha256)
            version_dir = tool_dir / f"{_safe_name(artifact.version)}-{artifact.sha256[:12]}"
            if version_dir.exists():
                shutil.rmtree(version_dir)
            os.replace(staging, version_dir)
        except BaseException:
            shutil.rmtree(staging, ignore_errors=True)
            raise
        async with self.locks[spec.scanner].write():
            self._switch_current(spec.name, version_dir)
        self._prune_versions(spec.name, keep={version_dir.name, self._previous_dir_name(spec.name)})
        return version_dir / (spec.executable or spec.name)

    def _previous_dir_name(self, name: str) -> str:
        record = self._inventory.get(name)
        return Path(record.path).parent.name if record and record.path else ""

    def _switch_current(self, name: str, version_dir: Path) -> None:
        link = self._tool_dir(name) / "current"
        tmp = link.with_name(f".current-{uuid.uuid4().hex[:8]}")
        os.symlink(version_dir.name, tmp)
        os.replace(tmp, link)  # atomic: scans see the old or the new binary, never neither

    def _prune_versions(self, name: str, keep: set[str]) -> None:
        for entry in self._tool_dir(name).iterdir():
            if entry.is_dir() and not entry.name.startswith(".") and entry.name not in keep:
                shutil.rmtree(entry, ignore_errors=True)

    async def _probe_version(self, spec: ToolSpec, exe: Path, expected: str) -> None:
        """Run the new binary once; it must work and be the version promised."""
        try:
            proc = await asyncio.create_subprocess_exec(
                str(exe), *spec.version_args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
                env=scanner_env({}), start_new_session=True,
            )
            try:
                async with asyncio.timeout(60):
                    out, _ = await proc.communicate()
            except (TimeoutError, asyncio.CancelledError):
                await kill_tree(proc)
                raise
        except (OSError, TimeoutError) as exc:
            raise InstallError(f"{spec.name} does not run on this host: {exc}") from exc
        text = out.decode(errors="replace")
        if proc.returncode != 0:
            raise InstallError(f"{spec.name} {' '.join(spec.version_args)} exited {proc.returncode}: {text[-200:]}")
        if expected and not re.search(rf"(?<![\d.]){re.escape(expected)}(?![\d])", text):
            raise InstallError(f"{spec.name} reports a different version than {expected}: {text.strip()[:200]}")

    async def _install_trivy_db(self, spec: ToolSpec, archive: Path) -> Path:
        cache = self.trivy_cache_dir
        cache.mkdir(parents=True, exist_ok=True)
        staging = cache / f".staging-{spec.target_subdir}-{uuid.uuid4().hex[:8]}"
        try:
            await asyncio.to_thread(_extract_all, archive, staging)
            missing = [f for f in spec.required_files if not (staging / f).is_file()]
            if missing:
                raise InstallError(f"{archive.name} is missing {', '.join(missing)} — not a Trivy database")
            target = cache / spec.target_subdir
            async with self.locks["trivy"].write():
                _swap_dir(staging, target)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return target

    async def _install_grype_db(self, archive: Path) -> Path:
        grype = self.binary("grype")
        if grype is None:
            raise InstallError("the grype binary must be installed before its database")
        staging = self._config.cache_dir / f".staging-grype-{uuid.uuid4().hex[:8]}"
        staging.mkdir(parents=True)
        try:
            env = scanner_env(grype_db_env(staging))
            proc = await asyncio.create_subprocess_exec(
                str(grype), "db", "import", str(archive),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
                start_new_session=True,
            )
            try:
                async with asyncio.timeout(1800):
                    out, _ = await proc.communicate()
            except TimeoutError:
                await kill_tree(proc)
                raise InstallError("grype db import timed out") from None
            except asyncio.CancelledError:
                await kill_tree(proc)
                raise
            if proc.returncode != 0:
                raise InstallError(f"grype db import exited {proc.returncode}: "
                                   f"{out.decode(errors='replace').strip()[-300:]}")
            ok, why = await asyncio.to_thread(self._grype_db_usable, staging, fresh=True)
            if not ok:
                raise InstallError(f"imported grype database is not usable: {why}")
            async with self.locks["grype"].write():
                _swap_dir(staging, self.grype_db_dir)
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        self._probe_cache.pop(str(self.grype_db_dir), None)
        return self.grype_db_dir


# --- archive helpers (run in a thread) -----------------------------------------------------
def _extract_single(archive: Path, member_name: str, dest: Path) -> None:
    """Extract one regular file from a tar archive, refusing anything odd."""
    with tarfile.open(archive, "r:*") as tf:
        for member in tf:
            if member.name.lstrip("./") != member_name:
                continue
            if not member.isfile():
                raise InstallError(f"{member_name} in the archive is not a regular file")
            if member.size <= 0 or member.size > _MAX_BINARY_BYTES:
                raise InstallError(f"{member_name} has an implausible size ({member.size} bytes)")
            source = tf.extractfile(member)
            if source is None:
                raise InstallError(f"cannot read {member_name} from the archive")
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
            with os.fdopen(fd, "wb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(dest, 0o755)  # noqa: S103 - an executable the runner user must be able to run
            return
    raise InstallError(f"the archive does not contain {member_name}")


def _extract_all(archive: Path, dest: Path) -> None:
    dest.mkdir(parents=True)
    with tarfile.open(archive, "r:*") as tf:
        # "data" filter: no absolute paths, no "..", no links out, no devices.
        tf.extractall(dest, filter="data")


def _swap_dir(new: Path, target: Path) -> None:
    """Replace ``target`` with ``new`` using renames only."""
    old = target.with_name(f".old-{target.name}-{uuid.uuid4().hex[:8]}")
    if target.exists():
        os.replace(target, old)
    try:
        os.replace(new, target)
    except OSError:
        if old.exists():
            os.replace(old, target)  # put the working one back
        raise
    shutil.rmtree(old, ignore_errors=True)
