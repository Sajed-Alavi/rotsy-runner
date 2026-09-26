"""What the runner knows about each tool it can install.

One entry per tool, mirroring the Rotsy server's catalogue
(``backend/app/core/tools.py``). The server says *which version, by
checksum*; this table says *how to install and verify it*. Adding a scanner
(Syft, Dockle, Semgrep, …) is an entry here with an existing installer — a
single executable in a tar.gz is the ``binary`` installer — plus its adapter
in :mod:`rotsy_runner.scanners`. Nothing else in the manager changes.
"""

from __future__ import annotations

from dataclasses import dataclass

BINARY = "binary"
DATABASE = "database"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    kind: str
    scanner: str
    #: Which installer handles it — see ToolManager._install.
    installer: str
    optional: bool = False
    #: binary: the executable's path inside the vendor archive.
    executable: str | None = None
    #: binary: the arguments that make it print its version (checked against
    #: the version the server says it is, before it is activated).
    version_args: tuple[str, ...] = ()
    #: trivy-db: files that must be in the archive, and where it is installed
    #: under the Trivy cache directory.
    required_files: tuple[str, ...] = ()
    target_subdir: str = ""


SPECS: dict[str, ToolSpec] = {
    "trivy": ToolSpec("trivy", BINARY, "trivy", "binary", executable="trivy", version_args=("--version",)),
    "grype": ToolSpec("grype", BINARY, "grype", "binary", executable="grype", version_args=("version",)),
    "trivy-db": ToolSpec("trivy-db", DATABASE, "trivy", "trivy-db",
                         required_files=("trivy.db", "metadata.json"), target_subdir="db"),
    "trivy-java-db": ToolSpec("trivy-java-db", DATABASE, "trivy", "trivy-db", optional=True,
                              required_files=("trivy-java.db", "metadata.json"), target_subdir="java-db"),
    "grype-db": ToolSpec("grype-db", DATABASE, "grype", "grype-db"),
}


def install_order(names: list[str]) -> list[str]:
    """Binaries before databases: installing Grype's database uses Grype."""
    known = [n for n in names if n in SPECS]
    return sorted(known, key=lambda n: (SPECS[n].kind != BINARY, n))


def required_for(scanner: str) -> list[str]:
    return [s.name for s in SPECS.values() if s.scanner == scanner and not s.optional]
