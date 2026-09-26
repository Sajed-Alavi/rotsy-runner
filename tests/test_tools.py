"""Tool installation: verified, atomic, upgradable, recoverable."""

from __future__ import annotations

import os
import time

from conftest import sha, tarball, trivy_db, trivy_release

from rotsy_runner.tools import ToolManager
from rotsy_runner.tools.specs import install_order, required_for


async def _sync(config, client, server, **kwargs):
    manager = ToolManager(config)
    summary = await manager.sync(client, **kwargs)
    return manager, summary


def test_install_order_puts_binaries_first():
    assert install_order(["grype-db", "trivy-db", "grype", "trivy", "unknown"]) == [
        "grype",
        "trivy",
        "grype-db",
        "trivy-db",
    ]
    assert required_for("trivy") == ["trivy", "trivy-db"]  # the Java DB is optional


async def test_full_sync_installs_everything_from_the_server(config, client, server):
    server.publish_standard()
    manager, summary = await _sync(config, client, server)
    assert summary == {"grype": "installed", "trivy": "installed", "grype-db": "installed", "trivy-db": "installed"}
    assert manager.ready_for("trivy") == (True, "")
    assert manager.ready_for("grype") == (True, "")
    report = {t["name"]: t for t in manager.report()}
    assert report["trivy"]["version"] == "0.73.0" and report["trivy"]["ready"]
    assert report["grype-db"]["sha256"] == sha(server.artifacts["grype-db"].data)
    # Everything came from the server's artifact endpoint.
    downloads = [str(r.url) for r in server.requests if "/artifacts/" in r.url.path]
    assert len(downloads) == 4 and all(u.startswith("http://rotsy.test:8000/api/runner-agent/v1/") for u in downloads)
    # The binary is activated through a symlink, the downloads are cleaned up.
    assert os.path.islink(config.tools_dir / "trivy" / "current")
    assert list(config.downloads_dir.iterdir()) == []


async def test_a_second_sync_downloads_nothing(config, client, server):
    server.publish_standard()
    await _sync(config, client, server)
    before = len(server.requests)
    _, summary = await _sync(config, client, server)
    assert set(summary.values()) == {"current"}
    assert [r for r in server.requests[before:] if "/artifacts/" in r.url.path] == []


async def test_checksum_mismatch_is_not_installed(config, client, server):
    server.publish_standard()
    server.corrupt_downloads = True
    manager, summary = await _sync(config, client, server)
    assert set(summary.values()) == {"failed"}
    assert manager.binary("trivy") is None
    report = {t["name"]: t for t in manager.report()}
    assert report["trivy"]["ready"] is False and "checksum mismatch" in report["trivy"]["error"]


async def test_failed_upgrade_keeps_the_working_version(config, client, server):
    server.publish_standard()
    manager, _ = await _sync(config, client, server)
    working = manager.binary("trivy")
    # A new "release" whose binary does not report the promised version.
    server.publish("trivy", "binary", "0.74.0", trivy_release("0.99.9"), "trivy_0.74.0_Linux-64bit.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy"] == "failed"
    assert manager.binary("trivy") == working  # still the old one, still active
    report = {t["name"]: t for t in manager.report()}["trivy"]
    assert report["version"] == "0.73.0" and report["ready"] is True
    assert "different version" in report["error"]


async def test_failed_install_backs_off(config, client, server):
    server.publish_standard()
    server.corrupt_downloads = True
    manager, _ = await _sync(config, client, server)
    before = len(server.requests)
    _, summary = await _sync(config, client, server)
    assert set(summary.values()) == {"backoff"}
    assert len(server.requests) == before + 1  # only the manifest was fetched
    _, summary = await _sync(config, client, server, force=True)
    assert "failed" in summary.values()


async def test_upgrade_and_rollback(config, client, server):
    server.publish_standard()
    manager, _ = await _sync(config, client, server)
    old = manager.binary("trivy")
    server.publish("trivy", "binary", "0.74.0", trivy_release("0.74.0"), "trivy_0.74.0_Linux-64bit.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy"] == "installed"
    assert manager.record("trivy").version == "0.74.0"
    assert manager.record("trivy").previous["version"] == "0.73.0"
    assert old.exists()  # the previous version is kept for rollback

    # The server's desired version goes back: re-activated from disk, no download.
    server.publish("trivy", "binary", "0.73.0", trivy_release("0.73.0"), "trivy_0.73.0_Linux-64bit.tar.gz")
    before = len(server.requests)
    manager, summary = await _sync(config, client, server)
    assert summary["trivy"] == "reactivated"
    assert manager.record("trivy").version == "0.73.0"
    assert [r for r in server.requests[before:] if "/artifacts/" in r.url.path] == []


async def test_archive_without_the_executable_is_refused(config, client, server):
    server.publish("trivy", "binary", "0.73.0", tarball({"README": b"no binary here"}), "trivy.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy"] == "failed"
    assert "does not contain trivy" in manager.record("trivy").error


async def test_symlinked_executable_is_refused(config, client, server):
    server.publish("trivy", "binary", "0.73.0", tarball({}, links={"trivy": "/bin/sh"}), "trivy.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy"] == "failed"
    assert "not a regular file" in manager.record("trivy").error


async def test_trivy_db_must_contain_the_database(config, client, server):
    server.publish_standard()
    server.publish("trivy-db", "database", "x", tarball({"metadata.json": b"{}"}), "db.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy-db"] == "failed"
    assert manager.ready_for("trivy")[0] is False


async def test_trivy_db_archive_cannot_escape_the_cache(config, client, server):
    server.publish_standard()
    evil = tarball({"trivy.db": b"x", "metadata.json": b"{}", "../../escaped": b"pwned"})
    server.publish("trivy-db", "database", "evil", evil, "db.tar.gz")
    _, summary = await _sync(config, client, server)
    assert summary["trivy-db"] == "failed"
    assert not (config.data_dir / "escaped").exists()
    assert not (config.cache_dir / "escaped").exists()


async def test_trivy_db_upgrade_swaps_atomically(config, client, server):
    server.publish_standard()
    manager, _ = await _sync(config, client, server)
    server.publish("trivy-db", "database", "20260926T000000Z", trivy_db("2026-09-26T00:00:00Z"), "db.tar.gz")
    manager, summary = await _sync(config, client, server)
    assert summary["trivy-db"] == "installed"
    meta = (manager.trivy_cache_dir / "db" / "metadata.json").read_text()
    assert "2026-09-26" in meta
    # No staging or old directories left behind.
    assert sorted(p.name for p in manager.trivy_cache_dir.iterdir()) == ["db"]


async def test_corrupt_grype_db_keeps_the_previous_database(config, client, server):
    server.publish_standard()
    manager, _ = await _sync(config, client, server)
    assert manager.ready_for("grype")[0]
    server.publish("grype-db", "database", "bad", b"corrupt-archive", "vulnerability-db.tar.zst")
    manager, summary = await _sync(config, client, server)
    assert summary["grype-db"] == "failed"
    assert manager.ready_for("grype")[0]  # the previous database still works


async def test_grype_db_needs_the_grype_binary(config, client, server):
    server.publish_standard()
    del server.artifacts["grype"]
    manager, summary = await _sync(config, client, server)
    assert summary["grype-db"] == "failed"
    assert "binary must be installed" in manager.record("grype-db").error


async def test_unavailable_artifacts_are_reported_not_fetched(config, client, server):
    manager, summary = await _sync(config, client, server)
    assert summary == {}
    assert manager.report() == []


async def test_interrupted_install_is_not_reported_as_installed(config, client, server):
    server.publish_standard()
    manager, _ = await _sync(config, client, server)
    record = manager.record("trivy")
    record.status = "installing"
    record.path = str(config.tools_dir / "nowhere" / "trivy")
    manager._save()
    reloaded = ToolManager(config)
    assert reloaded.record("trivy").status == "failed"
    assert reloaded.binary("trivy") is None


async def test_scans_wait_for_a_database_swap(config):
    """The readers–writer lock: a swap waits for running scans, and holds back new ones."""
    import asyncio

    manager = ToolManager(config)
    lock = manager.locks["grype"]
    order: list[str] = []

    async def scan(name, hold):
        async with lock.read():
            order.append(f"{name}-start")
            await asyncio.sleep(hold)
            order.append(f"{name}-end")

    async def swap():
        await asyncio.sleep(0.01)
        async with lock.write():
            order.append("swap")

    started = time.monotonic()
    await asyncio.gather(scan("a", 0.05), swap(), scan("b", 0))
    assert order.index("swap") > order.index("a-end")
    assert time.monotonic() - started < 2
