"""The runner host's OS/architecture, in the server's vocabulary.

Artifacts are built per platform; a binary for one is never offered to (or
installed on) another. The server refuses to register a platform it does not
support, so an unknown one fails at registration, not at first scan.
"""

from __future__ import annotations

import platform as _platform

_ARCH = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}


def current() -> tuple[str, str]:
    os_name = _platform.system().lower()
    machine = _platform.machine().lower()
    return os_name, _ARCH.get(machine, machine)


def hostname() -> str:
    return _platform.node()[:255]
