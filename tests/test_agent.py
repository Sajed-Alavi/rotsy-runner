"""The agent: registration, heartbeat, commands, reconnects, shutdown, auth failure."""

from __future__ import annotations

import asyncio

import httpx
import pytest
from conftest import SERVER

from rotsy_runner import cli, state
from rotsy_runner.agent import EXIT_AUTH, Agent, Backoff
from rotsy_runner.client import ServerClient
from rotsy_runner.state import Identity


def _identity() -> Identity:
    return Identity(SERVER, "u" * 32, "runner-01", "now", 1)


def _agent(config, server) -> Agent:
    client = ServerClient(config, SERVER, server.credential, transport=httpx.MockTransport(server))
    return Agent(config, _identity(), server.credential, client=client)


async def _run_until(agent: Agent, predicate, timeout: float = 15.0) -> None:
    task = asyncio.create_task(agent.run())
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        if task.done():
            break
        if loop.time() > deadline:
            agent.request_stop("test timeout")
            await task
            raise AssertionError("condition never became true")
        await asyncio.sleep(0.05)
    agent.request_stop("test done")
    await asyncio.wait_for(task, 15)


# --- registration (CLI) -------------------------------------------------------------
def test_register_stores_identity_and_credential(config, server, monkeypatch):
    real = ServerClient.__init__

    def with_fake(self, cfg, url, credential=None, transport=None):
        real(self, cfg, url, credential, transport=httpx.MockTransport(server))

    monkeypatch.setattr(ServerClient, "__init__", with_fake)
    token_file = config.data_dir.parent / "token"
    token_file.write_text(server.token)
    args = cli.build_parser().parse_args(["register", "--server", SERVER, "--token-file", str(token_file)])
    assert cli.cmd_register(args, config) == 0
    identity, credential = state.load(config.state_dir)
    assert identity.name == "runner-01" and credential == server.credential
    # A second use of the same token is refused.
    args = cli.build_parser().parse_args(["register", "--server", SERVER, "--token-file", str(token_file), "--force"])
    assert cli.cmd_register(args, config) == 3


def test_register_refuses_plain_http_without_opt_in(tmp_path):
    from rotsy_runner.config import Config, ConfigError

    config = Config.from_env({}, data_dir=str(tmp_path))
    args = cli.build_parser().parse_args(["register", "--server", "http://rotsy.example.com", "--token", "x"])
    with pytest.raises(ConfigError):
        cli.cmd_register(args, config)


def test_version_command(capsys):
    assert cli.main(["version"]) == 0
    assert "rotsy-runner" in capsys.readouterr().out


# --- the running agent ---------------------------------------------------------------
async def test_agent_syncs_tools_and_reports_them(config, server):
    server.publish_standard()
    agent = _agent(config, server)
    await _run_until(agent, lambda: any(len([t for t in hb["tools"] if t["ready"]]) == 4 for hb in server.heartbeats))
    last = [hb for hb in server.heartbeats if hb["tools"]][-1]
    assert {t["name"] for t in last["tools"]} == {"trivy", "grype", "trivy-db", "grype-db"}
    assert last["os"] == "linux" and last["protocol_version"] == 1


async def test_agent_claims_and_completes_a_job(config, server):
    server.publish_standard()
    job = server.job()
    agent = _agent(config, server)
    await _run_until(agent, lambda: job["job_uid"] in server.completed)
    assert {r["scanner"] for r in server.completed[job["job_uid"]]} == {"trivy", "grype"}


async def test_sync_tools_command_triggers_a_sync(config, server):
    agent = _agent(config, server)
    server.commands.append({"type": "SYNC_TOOLS"})
    server.publish_standard()
    await _run_until(agent, lambda: agent.tools.ready_for("trivy")[0])


async def test_unknown_commands_are_ignored(config, server):
    agent = _agent(config, server)
    server.commands.append({"type": "RUN_SHELL", "script": "rm -rf /"})
    await _run_until(agent, lambda: len(server.heartbeats) >= 2)
    assert agent.exit_code == 0


async def test_shutdown_command_stops_the_agent(config, server):
    agent = _agent(config, server)
    server.commands.append({"type": "SHUTDOWN", "reason": "maintenance"})
    code = await asyncio.wait_for(agent.run(), 15)
    assert code == 0
    assert server.heartbeats[-1]["state"] == "draining"


async def test_revoked_credential_stops_the_agent(config, server):
    server.revoked = True
    agent = _agent(config, server)
    code = await asyncio.wait_for(agent.run(), 15)
    assert code == EXIT_AUTH


async def test_agent_survives_a_server_outage(config, server, monkeypatch):
    monkeypatch.setattr(Backoff, "next", lambda self: 0.05)
    server.fail_next = 5
    agent = _agent(config, server)
    await _run_until(agent, lambda: len(server.heartbeats) >= 2)
    assert agent.exit_code == 0


async def test_disabled_runner_takes_no_work(config, server):
    server.publish_standard()
    server.enabled = False
    job = server.job()
    agent = _agent(config, server)
    await _run_until(agent, lambda: len(server.heartbeats) >= 3)
    assert job["job_uid"] not in server.completed
    assert not agent.enabled


async def test_cancel_job_command_reaches_the_running_scan(config, server, tmp_path):
    server.publish_standard()
    (tmp_path / "home" / "trivy-mode").write_text("sleep")
    job = server.job()
    server.cancel.add(job["job_uid"])
    agent = _agent(config, server)
    await _run_until(agent, lambda: job["job_uid"] in server.failed)
    assert server.failed[job["job_uid"]]["error"] == "cancelled"


async def test_shutdown_hands_back_running_work(config, server, tmp_path):
    server.publish_standard()
    (tmp_path / "home" / "trivy-mode").write_text("sleep")
    job = server.job()
    agent = _agent(config, server)
    await _run_until(agent, lambda: job["job_uid"] in agent._running)
    # _run_until stopped the agent; the grace period (2s) expired with the scan still running.
    assert server.failed[job["job_uid"]] == {"error": "runner shutting down", "detail": "", "retryable": True}


def test_backoff_grows_and_caps():
    backoff = Backoff(base=1.0, cap=10.0)
    delays = [backoff.next() for _ in range(8)]
    assert delays[0] <= 1.0 and max(delays) <= 10.0
    backoff.reset()
    assert backoff.next() <= 1.0
