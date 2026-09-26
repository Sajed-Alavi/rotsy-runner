"""Metrics and events the runner pushes to the server on its heartbeat."""

from __future__ import annotations

import types

import httpx
import pytest
from conftest import SERVER

from rotsy_runner import telemetry
from rotsy_runner.agent import Agent
from rotsy_runner.client import ServerClient, ServerError
from rotsy_runner.state import Identity
from rotsy_runner.telemetry import SystemSampler, Telemetry


@pytest.fixture
def clock(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(telemetry, "time", types.SimpleNamespace(monotonic=lambda: now[0]))
    return now


def test_cgroup_cpu_and_memory_are_the_containers_own(tmp_path, monkeypatch, clock):
    cg = tmp_path / "cgroup"
    cg.mkdir()
    monkeypatch.setattr(telemetry, "CGROUP", cg)
    (cg / "cpu.max").write_text("200000 100000\n")  # a 2-core quota
    (cg / "cpu.stat").write_text("usage_usec 5000000\nuser_usec 1\n")
    (cg / "memory.current").write_text(str(600 * 2**20))
    (cg / "memory.max").write_text(str(2**30))
    (cg / "memory.stat").write_text(f"anon 1\ninactive_file {100 * 2**20}\n")

    sampler = SystemSampler(tmp_path)
    assert sampler.cpu() == (None, "cgroup")  # a rate needs two samples
    clock[0] += 2.0
    (cg / "cpu.stat").write_text("usage_usec 7000000\n")  # 2 CPU-seconds in 2s on 2 cores
    assert sampler.cpu() == (50.0, "cgroup")

    used, total, scope = sampler.memory()
    assert scope == "cgroup" and used == 500 * 2**20 and total <= 2**30
    assert telemetry.available_cores() == 2.0


def test_host_figures_without_a_cgroup(tmp_path, monkeypatch):
    monkeypatch.setattr(telemetry, "CGROUP", tmp_path / "missing")
    sampler = SystemSampler(tmp_path)
    sampler.sample()
    snap = sampler.sample()
    assert snap["cpu_scope"] == "host" and snap["memory_scope"] == "host"
    assert snap["disk_total_bytes"] > 0 and snap["process_rss_bytes"] > 0
    assert snap["cpu_percent"] is None or 0 <= snap["cpu_percent"] <= 100


def test_directory_sizes_are_measured_occasionally(tmp_path, clock):
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "trivy").write_bytes(b"x" * 1000)
    sampler = SystemSampler(tmp_path)
    sampler.refresh_dir_sizes()
    assert sampler.sample()["tools_bytes"] == 1000
    (tmp_path / "tools" / "grype").write_bytes(b"x" * 500)
    clock[0] += 60
    sampler.refresh_dir_sizes()
    assert sampler.sample()["tools_bytes"] == 1000  # not re-walked within 10 minutes
    clock[0] += 600
    sampler.refresh_dir_sizes()
    assert sampler.sample()["tools_bytes"] == 1500


def test_events_are_bounded_and_survive_a_failed_delivery(tmp_path):
    t = Telemetry(tmp_path)
    for i in range(telemetry.EVENT_BUFFER + 5):
        t.event("job.completed", f"job {i}")
    assert t.pending_events == telemetry.EVENT_BUFFER and t.dropped_events == 5
    batch = t.drain_events(10)
    assert [e["message"] for e in batch] == [f"job {i}" for i in range(5, 15)]
    t.restore_events(batch)
    assert t.drain_events(1)[0]["message"] == "job 5"  # back at the front, in order


def test_snapshot_counts_jobs_and_scanner_timings(tmp_path):
    t = Telemetry(tmp_path)
    t.job_finished("completed")
    t.job_finished("cancelled")
    t.scan_result("trivy", True, 1000, 3)
    t.scan_result("trivy", False, 3000, 0)
    t.heartbeat_failed()
    t.heartbeat_ok(12.34)
    snap = t.snapshot(running_jobs=1)
    assert snap["jobs_completed"] == 1 and snap["jobs_cancelled"] == 1 and snap["jobs_running"] == 1
    assert snap["scanners"]["trivy"] == {
        "ok": 1,
        "failed": 1,
        "last_duration_ms": 3000,
        "avg_duration_ms": 2000,
        "last_findings": 0,
    }
    assert snap["heartbeat_rtt_ms"] == 12.3 and snap["reconnects"] == 1 and snap["heartbeat_failures"] == 0


def _agent(config, server) -> Agent:
    client = ServerClient(config, SERVER, server.credential, transport=httpx.MockTransport(server))
    return Agent(config, Identity(SERVER, "u" * 32, "runner-01", "now", 1), server.credential, client=client)


async def test_metrics_and_events_only_go_to_a_server_that_accepts_them(config, server):
    agent = _agent(config, server)
    agent.telemetry.event("agent.started", "hello")
    await agent.heartbeat_once()
    assert "metrics" not in server.heartbeats[-1] and "events" not in server.heartbeats[-1]
    assert agent.telemetry.pending_events == 1  # kept for a server that wants them

    server.features = ["metrics", "events"]
    await agent.heartbeat_once()  # learns the features
    await agent.heartbeat_once()
    body = server.heartbeats[-1]
    assert body["metrics"]["jobs_running"] == 0 and "cpu_scope" in body["metrics"]
    assert [e["kind"] for e in body["events"]] == ["agent.started"]
    assert agent.telemetry.pending_events == 0


async def test_a_failed_heartbeat_keeps_its_events_and_reports_the_outage(config, server):
    server.features = ["metrics", "events"]
    agent = _agent(config, server)
    await agent.heartbeat_once()
    agent.telemetry.event("job.completed", "team/app:1.0: trivy ok")
    server.fail_next = 1
    with pytest.raises(ServerError):
        await agent.heartbeat_once()
    await agent.heartbeat_once()
    assert [e["kind"] for e in server.heartbeats[-1]["events"]] == ["job.completed", "connection.lost"]
    # "restored" is known only once that heartbeat succeeded: it rides on the next.
    await agent.heartbeat_once()
    assert [e["kind"] for e in server.heartbeats[-1]["events"]] == ["connection.restored"]
    assert server.heartbeats[-1]["metrics"]["reconnects"] == 1


async def test_a_job_is_reported_as_events_and_counters(config, server):
    from test_agent import _run_until

    server.publish_standard()
    server.features = ["metrics", "events"]
    job = server.job()
    agent = _agent(config, server)
    await _run_until(
        agent,
        lambda: job["job_uid"] in server.completed
        and any(e["kind"] == "job.completed" for h in server.heartbeats for e in h.get("events", [])),
    )
    events = [e for h in server.heartbeats for e in h.get("events", [])]
    kinds = [e["kind"] for e in events]
    assert "agent.started" in kinds and "tool.installed" in kinds
    started = next(e for e in events if e["kind"] == "job.started")
    assert started["job_uid"] == job["job_uid"] and "team/app:1.0" in started["message"]
    metrics = [h["metrics"] for h in server.heartbeats if "metrics" in h]
    assert metrics[-1]["jobs_completed"] == 1
    assert set(metrics[-1]["scanners"]) == {"trivy", "grype"}
