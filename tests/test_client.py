"""The server client: error mapping, downloads, and the one-origin rule."""

from __future__ import annotations

import httpx
import pytest
from conftest import SERVER, sha

from rotsy_runner.client import (
    AuthError,
    ChecksumError,
    DisabledError,
    JobGone,
    RequestError,
    ServerClient,
    ServerError,
    TokenError,
)


async def test_register_exchanges_the_token(config, server):
    client = ServerClient(config, SERVER, transport=httpx.MockTransport(server))
    resp = await client.register(server.token, {"os": "linux", "arch": "amd64", "protocol_version": 1})
    assert resp.credential == server.credential
    with pytest.raises(TokenError):  # one-time
        await client.register(server.token, {})
    with pytest.raises(AuthError):
        await client.register("rre_wrong", {})
    await client.aclose()


async def test_status_codes_map_to_actions(config):
    def answer(status):
        return lambda request: httpx.Response(status, json={"detail": {"code": "x", "message": f"status {status}"}})

    for status, error in (
        (401, AuthError),
        (403, DisabledError),
        (404, JobGone),
        (409, JobGone),
        (410, TokenError),
        (422, RequestError),
        (413, RequestError),
        (500, ServerError),
        (503, ServerError),
    ):
        client = ServerClient(config, SERVER, "rrt_x", transport=httpx.MockTransport(answer(status)))
        with pytest.raises(error):
            await client.heartbeat({})
        await client.aclose()


async def test_network_failures_are_transient(config):
    def boom(request):
        raise httpx.ConnectError("connection refused")

    client = ServerClient(config, SERVER, "rrt_x", transport=httpx.MockTransport(boom))
    with pytest.raises(ServerError, match="cannot reach"):
        await client.heartbeat({})
    await client.aclose()


async def test_redirects_are_never_followed(config):
    def redirect(request):
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    client = ServerClient(config, SERVER, "rrt_x", transport=httpx.MockTransport(redirect))
    with pytest.raises(RequestError, match="redirect"):
        await client.heartbeat({})
    await client.aclose()


async def test_the_credential_is_sent_as_a_bearer_header(client, server):
    await client.heartbeat({"state": "idle"})
    assert server.requests[-1].headers["authorization"] == f"Bearer {server.credential}"
    assert server.requests[-1].headers["user-agent"].startswith("rotsy-runner/")


async def test_download_verifies_and_resumes(client, server, tmp_path):
    server.publish_standard()
    artifact = server.artifacts["trivy"]
    dest = tmp_path / "dl" / "trivy.tar.gz"
    partial = dest.with_name(dest.name + ".partial")
    partial.parent.mkdir()
    partial.write_bytes(artifact.data[:100])
    await client.download(
        artifact.entry()["download_path"], dest, expected_sha256=sha(artifact.data), expected_size=len(artifact.data)
    )
    assert dest.read_bytes() == artifact.data
    assert server.requests[-1].headers["range"] == "bytes=100-"
    assert not partial.exists()


async def test_corrupt_download_is_discarded(client, server, tmp_path):
    server.publish_standard()
    server.corrupt_downloads = True
    artifact = server.artifacts["trivy"]
    dest = tmp_path / "trivy.tar.gz"
    with pytest.raises(ChecksumError):
        await client.download(artifact.entry()["download_path"], dest, expected_sha256=sha(artifact.data))
    assert not dest.exists()
    assert not dest.with_name(dest.name + ".partial").exists()


@pytest.mark.parametrize(
    "path",
    [
        "https://github.com/aquasecurity/trivy/releases/download/v0.73.0/trivy.tar.gz",
        "//github.com/x",
        "/api/runner-agent/v1/artifacts/../../etc/passwd",
        "/api/runner-agent/v1/heartbeat",
        "/etc/passwd",
        "/api/runner-agent/v1/artifacts/1?redirect=https://evil",
    ],
)
async def test_download_paths_must_be_server_artifacts(client, tmp_path, path):
    with pytest.raises(RequestError, match="only from the Rotsy server"):
        await client.download(path, tmp_path / "x", expected_sha256="0" * 64)


async def test_client_ignores_ambient_proxy_settings(config, monkeypatch):
    """The runner talks to its server directly; an HTTPS_PROXY in the
    environment must not reroute the credential through somebody else."""
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.evil:3128")
    client = ServerClient(config, SERVER, "rrt_x")
    assert client._http._trust_env is False
    await client.aclose()
