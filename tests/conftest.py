"""Test fixtures: an in-memory Rotsy server and fake scanner releases.

:class:`FakeServer` implements the runner agent API (``/api/runner-agent/v1``)
closely enough to exercise the real client, tool manager, executor and agent
over HTTP semantics — status codes, Range requests, JSON shapes — via httpx's
``MockTransport``. It also records every request, so tests can assert that the
runner never talked to anything but the server.

The fake scanners are small shell scripts packaged exactly like the vendors'
release archives (a tar.gz containing one executable). They answer the version
probe, implement ``grype db import/status``, and for scans emit a canned JSON
report while recording the argv and environment they were given.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import pytest

from rotsy_runner.client import ServerClient
from rotsy_runner.config import Config

SERVER = "http://rotsy.test:8000"

FAKE_TRIVY = """#!/bin/sh
if [ "$1" = "--version" ]; then echo "Version: {version}"; exit 0; fi
printf '%s\\n' "$@" > "$HOME/trivy-args"
env | grep -E '^(TRIVY_|HTTP|HTTPS|NO_PROXY)' | sort > "$HOME/trivy-env"
mode=$(cat "$HOME/trivy-mode" 2>/dev/null)
[ "$mode" = "sleep" ] && sleep 30
[ "$mode" = "fail" ] && {{ echo "FATAL: unable to fetch manifest: unauthorized" >&2; exit 1; }}
cat <<'JSON'
{{"Results":[{{"Vulnerabilities":[{{"VulnerabilityID":"CVE-2024-0001","Severity":"CRITICAL","PkgName":"openssl","InstalledVersion":"3.0.0","FixedVersion":"3.0.1","Title":"bad","CVSS":{{"nvd":{{"V3Score":9.8}}}}}},{{"VulnerabilityID":"CVE-2024-0002","Severity":"LOW","PkgName":"zlib","InstalledVersion":"1.0","FixedVersion":"","Title":"meh"}}]}}]}}
JSON
"""

FAKE_GRYPE = """#!/bin/sh
case "$1" in
  version) echo "Application: grype"; echo "Version: {version}"; exit 0;;
  db)
    case "$2" in
      import) [ "$(head -c 7 "$3")" = "corrupt" ] && {{ echo "invalid archive" >&2; exit 1; }}
              mkdir -p "$GRYPE_DB_CACHE_DIR/6" && cp "$3" "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" \\
              && echo '{{}}' > "$GRYPE_DB_CACHE_DIR/6/import.json"; exit 0;;
      status) if [ -f "$GRYPE_DB_CACHE_DIR/6/vulnerability.db" ]; then echo "Status: valid"; exit 0; fi
              echo "Status: invalid"; exit 1;;
    esac;;
esac
printf '%s\\n' "$@" > "$HOME/grype-args"
env | grep -E '^(GRYPE_|HTTP|HTTPS|NO_PROXY)' | sort > "$HOME/grype-env"
mode=$(cat "$HOME/grype-mode" 2>/dev/null)
[ "$mode" = "sleep" ] && sleep 30
cat <<'JSON'
{{"matches":[{{"vulnerability":{{"id":"CVE-2024-0003","severity":"Negligible","fix":{{"versions":["1.1"]}}}},"artifact":{{"name":"busybox","version":"1.0"}}}}]}}
JSON
"""


def tarball(
    members: dict[str, bytes], *, modes: dict[str, int] | None = None, links: dict[str, str] | None = None
) -> bytes:
    """A tar.gz, byte-for-byte deterministic for the same members (like a real
    release artifact, whose checksum does not change between downloads)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = (modes or {}).get(name, 0o755)
            tf.addfile(info, io.BytesIO(data))
        for name, target in (links or {}).items():
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tf.addfile(info)
    return gzip.compress(buf.getvalue(), mtime=0)


def trivy_release(version: str = "0.73.0") -> bytes:
    return tarball({"trivy": FAKE_TRIVY.format(version=version).encode(), "LICENSE": b"Apache-2.0"})


def grype_release(version: str = "0.117.0") -> bytes:
    return tarball({"grype": FAKE_GRYPE.format(version=version).encode(), "README.md": b"grype"})


def trivy_db(built: str = "2026-09-25T00:00:00Z") -> bytes:
    return tarball(
        {"trivy.db": b"bolt-db-bytes", "metadata.json": json.dumps({"Version": 2, "UpdatedAt": built}).encode()}
    )


def grype_db() -> bytes:
    return b"sqlite-db-bytes-" + uuid.uuid4().hex.encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Artifact:
    id: int
    name: str
    kind: str
    version: str
    data: bytes
    filename: str
    os: str = "linux"
    arch: str = "amd64"
    optional: bool = False

    def entry(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "version": self.version,
            "os": self.os,
            "arch": self.arch,
            "available": True,
            "artifact_id": self.id,
            "filename": self.filename,
            "sha256": sha(self.data),
            "size_bytes": len(self.data),
            "download_path": f"/api/runner-agent/v1/artifacts/{self.id}",
            "optional": self.optional,
        }


@dataclass
class FakeServer:
    """The runner agent API, in memory."""

    credential: str = "rrt_" + "c" * 43
    token: str = "rre_" + "t" * 43
    token_used: bool = False
    enabled: bool = True
    revoked: bool = False
    artifacts: dict[str, Artifact] = field(default_factory=dict)
    commands: list[dict] = field(default_factory=list)
    jobs: list[dict] = field(default_factory=list)
    progress: list[dict] = field(default_factory=list)
    completed: dict[str, list] = field(default_factory=dict)
    failed: dict[str, dict] = field(default_factory=dict)
    heartbeats: list[dict] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)
    cancel: set[str] = field(default_factory=set)
    claimed: dict[str, dict] = field(default_factory=dict)
    fail_next: int = 0  # answer this many requests with 503
    features: list[str] = field(default_factory=list)  # optional heartbeat fields accepted
    corrupt_downloads: bool = False

    def publish(
        self, name: str, kind: str, version: str, data: bytes, filename: str, optional: bool = False
    ) -> Artifact:
        artifact = Artifact(len(self.artifacts) + 1, name, kind, version, data, filename, optional=optional)
        if kind == "database":
            artifact.os = artifact.arch = "any"
        self.artifacts[name] = artifact
        return artifact

    def publish_standard(self) -> None:
        self.publish("trivy", "binary", "0.73.0", trivy_release(), "trivy_0.73.0_Linux-64bit.tar.gz")
        self.publish("grype", "binary", "0.117.0", grype_release(), "grype_0.117.0_linux_amd64.tar.gz")
        self.publish("trivy-db", "database", "20260925T000000Z", trivy_db(), "db.tar.gz")
        self.publish("grype-db", "database", "20260925T000000Z", grype_db(), "vulnerability-db.tar.zst")

    def job(self, scanners=("trivy", "grype"), image="team/app:1.0", **overrides) -> dict:
        name, tag = image.rsplit(":", 1)
        job = {
            "job_uid": uuid.uuid4().hex,
            "type": "SCAN_IMAGE",
            "attempt": 1,
            "lease_seconds": 120,
            "timeout_seconds": 600,
            "scanners": list(scanners),
            "target": {
                "repo": "docker-hosted",
                "image": image,
                "name": name,
                "tag": tag,
                "registry": {"username": "", "password": "rrj_" + "p" * 43},
            },
        }
        job["target"]["registry"]["username"] = f"rotsy-job-{job['job_uid']}"
        job.update(overrides)
        self.jobs.append(job)
        return job

    # --- the transport ---------------------------------------------------------------
    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host != "rotsy.test":
            raise AssertionError(f"the runner tried to reach {request.url} — only the Rotsy server is allowed")
        if self.fail_next > 0:
            self.fail_next -= 1
            return httpx.Response(503, json={"detail": "restarting"})
        path = request.url.path
        if path == "/api/runner-agent/v1/register":
            body = json.loads(request.content)
            if body["token"] != self.token:
                return httpx.Response(401, json={"detail": {"code": "invalid_token", "message": "Invalid token."}})
            if self.token_used:
                return httpx.Response(410, json={"detail": {"code": "token_used", "message": "already used"}})
            self.token_used = True
            return httpx.Response(
                201,
                json={
                    "runner_uid": "u" * 32,
                    "name": "runner-01",
                    "credential": self.credential,
                    "heartbeat_interval_seconds": 1,
                    "protocol_version": 1,
                    "server_version": "test",
                },
            )
        if request.headers.get("authorization") != f"Bearer {self.credential}" or self.revoked:
            return httpx.Response(401, json={"detail": {"code": "invalid_credential", "message": "revoked"}})
        if path == "/api/runner-agent/v1/heartbeat":
            body = json.loads(request.content)
            self.heartbeats.append(body)
            commands, self.commands = self.commands, []
            for uid in body.get("running_jobs", []):
                if uid in self.cancel:
                    commands.append({"type": "CANCEL_JOB", "job_uid": uid})
            return httpx.Response(
                200,
                json={
                    "runner_status": "active" if self.enabled else "disabled",
                    "heartbeat_interval_seconds": 1,
                    "desired_tools_revision": "r1",
                    "commands": commands,
                    **({"features": self.features} if self.features else {}),
                },
            )
        if not self.enabled:
            return httpx.Response(403, json={"detail": {"code": "runner_disabled", "message": "disabled"}})
        if path == "/api/runner-agent/v1/tools/desired":
            return httpx.Response(
                200,
                json={
                    "platform": "linux/amd64",
                    "revision": "r1",
                    "artifacts": [a.entry() for a in self.artifacts.values()],
                },
            )
        if path.startswith("/api/runner-agent/v1/artifacts/"):
            artifact_id = int(path.rsplit("/", 1)[1])
            artifact = next((a for a in self.artifacts.values() if a.id == artifact_id), None)
            if artifact is None:
                return httpx.Response(404, json={"detail": {"code": "not_allowed", "message": "no"}})
            data = b"X" + artifact.data[1:] if self.corrupt_downloads else artifact.data
            start = 0
            if request.headers.get("range"):
                start = int(request.headers["range"].split("=")[1].rstrip("-"))
                return httpx.Response(206, content=data[start:])
            return httpx.Response(200, content=data)
        if path == "/api/runner-agent/v1/jobs/claim":
            if self.jobs:
                job = self.jobs.pop(0)
                self.claimed[job["job_uid"]] = job
                return httpx.Response(200, json=job)
            return httpx.Response(204)
        if path.endswith("/progress"):
            uid = path.split("/")[-2]
            self.progress.append({"job_uid": uid, **json.loads(request.content)})
            return httpx.Response(200, json={"cancel_requested": uid in self.cancel, "lease_seconds": 120})
        if path.endswith("/complete"):
            self.completed[path.split("/")[-2]] = json.loads(request.content)["results"]
            return httpx.Response(200, json={"status": "succeeded"})
        if path.endswith("/fail"):
            uid = path.split("/")[-2]
            body = json.loads(request.content)
            self.failed[uid] = body
            if body.get("retryable") and uid not in self.cancel:
                # Like the real server: hand a retryable job back to the queue.
                job = self.claimed.get(uid)
                if job is not None:
                    self.jobs.append(job)
                return httpx.Response(200, json={"status": "queued"})
            return httpx.Response(200, json={"status": "failed"})
        return httpx.Response(404)


@pytest.fixture
def server() -> FakeServer:
    return FakeServer()


@pytest.fixture
def config(tmp_path, monkeypatch) -> Config:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    return Config.from_env({}, data_dir=str(tmp_path / "data"), allow_insecure_http=True, shutdown_grace_seconds=2)


@pytest.fixture
async def client(config, server):
    c = ServerClient(config, SERVER, server.credential, transport=httpx.MockTransport(server))
    yield c
    await c.aclose()


def home(tmp_path: Path) -> Path:
    return tmp_path / "home"
