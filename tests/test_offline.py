"""The restricted-network guarantee, pinned.

A runner must work with no Internet access: it may talk to its Rotsy server
and nothing else. These tests fail if code that could reach anywhere else —
a vendor download URL, the Telegram API, an update check — creeps in, and
prove the whole cycle (sync tools, scan, report) touches only the server.
"""

from __future__ import annotations

import re
from pathlib import Path

import httpx
import pytest
from conftest import SERVER

from rotsy_runner.agent import Agent
from rotsy_runner.client import ServerClient
from rotsy_runner.state import Identity

SRC = Path(__file__).resolve().parent.parent / "src" / "rotsy_runner"

FORBIDDEN = [
    r"github\.com",
    r"githubusercontent",
    r"api\.telegram\.org",
    r"telegram",
    r"grype\.anchore\.io",
    r"ghcr\.io",
    r"docker\.io",
    r"mirror\.gcr\.io",
    r"public\.ecr\.aws",
    r"aquasec",
    r"check\.trivy",
    r"toolbox-data\.anchore\.io",
]


@pytest.mark.parametrize("pattern", FORBIDDEN)
def test_no_external_endpoint_in_runner_code(pattern):
    hits = [
        f"{path.relative_to(SRC)}:{n}"
        for path in SRC.rglob("*.py")
        for n, line in enumerate(path.read_text().splitlines(), 1)
        if re.search(pattern, line, re.IGNORECASE)
        and not line.strip().startswith("#")
        and "never" not in line.lower()
        and "no " not in line.lower()
    ]
    assert hits == [], f"{pattern} referenced in runner code: {hits}"


def test_scanners_are_told_never_to_update_or_phone_home():
    trivy = (SRC / "scanners" / "trivy.py").read_text()
    grype = (SRC / "scanners" / "grype.py").read_text()
    for flag in ("--skip-db-update", "--offline-scan", "--skip-version-check", "TRIVY_SKIP_VERSION_CHECK"):
        assert flag in trivy
    for setting in ('"GRYPE_DB_AUTO_UPDATE": "false"', '"GRYPE_CHECK_FOR_APP_UPDATE": "false"'):
        assert setting in grype


async def test_a_full_cycle_touches_only_the_rotsy_server(config, server):
    """Register-to-result with a transport that fails any other destination.

    FakeServer raises on any host that is not the Rotsy server; the scanner
    subprocesses are fakes that would fail loudly if asked to fetch anything.
    Tool binaries, databases and the scan all flow through the one origin.
    """
    server.publish_standard()
    job = server.job()
    client = ServerClient(config, SERVER, server.credential, transport=httpx.MockTransport(server))
    agent = Agent(config, Identity(SERVER, "u" * 32, "runner-01", "now", 1), server.credential, client=client)

    import asyncio

    task = asyncio.create_task(agent.run())
    for _ in range(300):
        if job["job_uid"] in server.completed:
            break
        await asyncio.sleep(0.05)
    agent.request_stop("done")
    await asyncio.wait_for(task, 15)

    assert job["job_uid"] in server.completed
    hosts = {r.url.host for r in server.requests}
    assert hosts == {"rotsy.test"}
    paths = {
        r.url.path.split("/")[4] if r.url.path.startswith("/api/runner-agent/v1/") else r.url.path
        for r in server.requests
    }
    assert paths <= {"heartbeat", "tools", "artifacts", "jobs"}


def test_the_image_reference_points_at_the_rotsy_proxy(config):
    from rotsy_runner.executor import Executor
    from rotsy_runner.protocol import JobAssignment
    from rotsy_runner.tools import ToolManager

    client = ServerClient(config, "https://rotsy.example.com:8443", "rrt_x")
    executor = Executor(config, client, ToolManager(config))
    job = JobAssignment.model_validate(
        {
            "job_uid": "a" * 32,
            "type": "SCAN_IMAGE",
            "attempt": 1,
            "lease_seconds": 60,
            "timeout_seconds": 60,
            "scanners": ["trivy"],
            "target": {
                "repo": "r",
                "image": "team/app:1",
                "name": "team/app",
                "tag": "1",
                "registry": {"username": "rotsy-job-" + "a" * 32, "password": "rrj_" + "x" * 43},
            },
        }
    )
    assert executor.image_ref(job) == "rotsy.example.com:8443/team/app:1"
    assert executor.insecure_registry is False
