"""The runner's identity: which server, which runner, and its credential.

Written once by ``rotsy-runner register``, read on every start:

  ``<data>/state/runner.json``  server URL, runner uid and name (not secret)
  ``<data>/state/credential``   the runner credential (``rrt_…``), mode 0600

The credential file is created with 0600 permissions *before* the secret is
written (``os.open`` with a mode, not ``open`` then ``chmod``), inside a 0700
directory, and replaced atomically — there is never a moment when it exists
world-readable or half-written. It is never logged and never passed to a
subprocess.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from pathlib import Path

IDENTITY_FILE = "runner.json"
CREDENTIAL_FILE = "credential"


@dataclass(frozen=True)
class Identity:
    server_url: str
    runner_uid: str
    name: str
    registered_at: str
    protocol_version: int


def _write_private(path: Path, content: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def ensure_state_dir(state_dir: Path) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, 0o700)


def save(state_dir: Path, identity: Identity, credential: str) -> None:
    ensure_state_dir(state_dir)
    _write_private(state_dir / CREDENTIAL_FILE, credential)
    _write_private(state_dir / IDENTITY_FILE, json.dumps(asdict(identity), indent=2))


def load(state_dir: Path) -> tuple[Identity, str] | None:
    """``(identity, credential)``, or ``None`` if this runner is not registered."""
    identity_path = state_dir / IDENTITY_FILE
    credential_path = state_dir / CREDENTIAL_FILE
    if not identity_path.is_file() or not credential_path.is_file():
        return None
    mode = credential_path.stat().st_mode & 0o777
    if mode & 0o077:
        raise PermissionError(
            f"{credential_path} is readable by other users (mode {mode:o}); run `chmod 600 {credential_path}`"
        )
    data = json.loads(identity_path.read_text())
    credential = credential_path.read_text().strip()
    return Identity(**{k: data[k] for k in Identity.__dataclass_fields__}), credential


def clear(state_dir: Path) -> bool:
    removed = False
    for name in (CREDENTIAL_FILE, IDENTITY_FILE):
        path = state_dir / name
        if path.exists():
            path.unlink()
            removed = True
    return removed
