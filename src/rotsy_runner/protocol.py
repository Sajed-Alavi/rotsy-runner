"""The runner agent protocol, from the runner's side.

Mirror of ``backend/app/schemas/runners.py`` in the Rotsy repository; see
docs/PROTOCOL.md for the full description.

Two different postures, on purpose:

* **Work the server hands us** (:class:`JobAssignment`) is validated strictly —
  a closed set of job types, a closed set of scanners, an image name that
  matches the Docker reference grammar. Anything else is refused *before*
  anything executes. There is no job type, field or command that carries a
  command line; the runner decides every argument it passes to a scanner.
* **Everything else from the server** tolerates unknown fields, so a newer
  server can add information without breaking older runners. Unknown
  *commands* are ignored (and logged), never guessed at.
"""

from __future__ import annotations

import logging
import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

logger = logging.getLogger(__name__)

SCANNERS = ("trivy", "grype")
JOB_TYPES = ("SCAN_IMAGE",)
COMMAND_TYPES = ("SYNC_TOOLS", "CANCEL_JOB", "SHUTDOWN")

_NAME_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
IMAGE_NAME = re.compile(rf"{_NAME_COMPONENT}(?:/{_NAME_COMPONENT})*", re.ASCII)
IMAGE_TAG = re.compile(r"[\w][\w.-]{0,127}", re.ASCII)
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


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- registration / heartbeat -------------------------------------------------------
class RegisterResponse(_Lenient):
    runner_uid: str
    name: str
    credential: str
    heartbeat_interval_seconds: int = 15
    protocol_version: int
    server_version: str = ""


class Command(_Lenient):
    type: str
    job_uid: str | None = None
    reason: str = ""


class HeartbeatResponse(_Lenient):
    runner_status: Literal["active", "disabled"]
    heartbeat_interval_seconds: int = Field(default=15, ge=1, le=3600)
    desired_tools_revision: str = ""
    commands: list[Command] = Field(default_factory=list)
    #: Optional heartbeat fields this server accepts ("metrics", "events");
    #: absent on servers that predate them.
    features: list[str] = Field(default_factory=list, max_length=32)

    def known_commands(self) -> list[Command]:
        known = []
        for command in self.commands:
            if command.type in COMMAND_TYPES:
                known.append(command)
            else:
                logger.warning("Ignoring unknown command %r from the server", command.type[:32])
        return known


class DesiredArtifact(_Lenient):
    name: str
    kind: Literal["binary", "database"]
    version: str
    os: str
    arch: str
    available: bool
    artifact_id: int | None = None
    filename: str = ""
    sha256: str = ""
    size_bytes: int = 0
    download_path: str = ""
    optional: bool = False
    reason: str = ""

    @field_validator("sha256")
    @classmethod
    def _hex(cls, value: str) -> str:
        if value and not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("sha256 must be 64 lowercase hex characters")
        return value


class DesiredTools(_Lenient):
    platform: str
    revision: str
    artifacts: list[DesiredArtifact]


# --- jobs -------------------------------------------------------------------------
class RegistryAccess(_Strict):
    username: str = Field(pattern=r"^rotsy-job-[0-9a-f]{32}$")
    password: str = Field(pattern=r"^rrj_[A-Za-z0-9_-]{20,128}$")


class ScanTarget(_Strict):
    repo: str = Field(min_length=1, max_length=255)
    image: str = Field(min_length=3, max_length=512)
    name: str = Field(min_length=1, max_length=384)
    tag: str = Field(min_length=1, max_length=128)
    registry: RegistryAccess

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        if not IMAGE_NAME.fullmatch(value):
            raise ValueError("image name outside the Docker reference grammar")
        return value

    @field_validator("tag")
    @classmethod
    def _tag(cls, value: str) -> str:
        if not IMAGE_TAG.fullmatch(value):
            raise ValueError("image tag outside the Docker reference grammar")
        return value

    @field_validator("image")
    @classmethod
    def _image(cls, value: str) -> str:
        if value.lower().startswith(_RUNTIME_SCHEMES):
            raise ValueError("runtime/filesystem sources are never scanned")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> "ScanTarget":
        if self.image != f"{self.name}:{self.tag}":
            raise ValueError("image does not match name:tag")
        return self


class JobAssignment(_Strict):
    job_uid: str = Field(pattern=r"^[0-9a-f]{32}$")
    type: Literal["SCAN_IMAGE"]
    attempt: int = Field(ge=1, le=100)
    lease_seconds: int = Field(ge=10, le=86400)
    timeout_seconds: int = Field(ge=30, le=86400)
    scanners: list[Literal["trivy", "grype"]] = Field(min_length=1, max_length=2)
    target: ScanTarget

    @field_validator("scanners")
    @classmethod
    def _unique(cls, value: list[str]) -> list[str]:
        if len(set(value)) != len(value):
            raise ValueError("duplicate scanners")
        return value


def parse_assignment(raw: dict) -> tuple[JobAssignment | None, str]:
    """``(assignment, "")`` or ``(None, reason)`` — never raises."""
    try:
        return JobAssignment.model_validate(raw), ""
    except ValidationError as exc:
        reasons = "; ".join(f"{'.'.join(str(p) for p in e['loc']) or 'job'}: {e['msg']}" for e in exc.errors())
        return None, reasons[:500]
    except (ValueError, TypeError) as exc:
        return None, str(exc)[:500]


class ProgressResponse(_Lenient):
    cancel_requested: bool = False
    lease_seconds: int = 120


# --- results: trimmed to the server's limits before sending ---------------------------
LIMITS = {"cve": 128, "severity": 16, "package": 512, "installed_version": 256, "fixed_version": 256, "title": 1024}
MAX_FINDINGS = 100_000


def clean_finding(finding: dict) -> dict:
    out = {key: str(finding.get(key) or "")[:limit] for key, limit in LIMITS.items()}
    out["cve"] = out["cve"] or "UNKNOWN"
    try:
        cvss = float(finding.get("cvss") or 0.0)
    except (TypeError, ValueError):
        cvss = 0.0
    out["cvss"] = min(10.0, max(0.0, cvss))
    return out
