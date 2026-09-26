"""Scanner adapters: report parsing, argument/environment hygiene, timeouts.

The parser tests moved here from the Rotsy server with the adapters themselves.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from rotsy_runner.scanners import base, grype, trivy

TRIVY_REPORT = {
    "Results": [
        {
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2024-1",
                    "Severity": "high",
                    "PkgName": "openssl",
                    "InstalledVersion": "1.0",
                    "FixedVersion": "1.1",
                    "Title": "t",
                    "CVSS": {"nvd": {"V3Score": 7.5, "V2Score": 9.0}, "rh": {"V3Score": 8.1}},
                },
                {"VulnerabilityID": None, "CVE": "CVE-2024-2", "Description": "d" * 300},
            ]
        },
        {"Vulnerabilities": None},
    ],
}
GRYPE_REPORT = {
    "matches": [
        {
            "vulnerability": {
                "id": "GHSA-1",
                "severity": "Medium",
                "description": "desc",
                "fix": {"versions": ["2.0", "3.0"]},
            },
            "artifact": {"name": "lodash", "version": "1.0"},
            "relatedVulnerabilities": [{"cvss": [{"metrics": {"baseScore": 5.5}}, {"metrics": {"baseScore": 6.1}}]}],
        },
        {"vulnerability": {"id": "CVE-9"}, "artifact": {}},
    ]
}


# --- parsers (moved from the Rotsy server) ---------------------------------------------
def test_trivy_parse_extracts_findings():
    findings = trivy.parse(TRIVY_REPORT)
    assert findings[0] == {
        "cve": "CVE-2024-1",
        "severity": "HIGH",
        "package": "openssl",
        "installed_version": "1.0",
        "fixed_version": "1.1",
        "title": "t",
        "cvss": 9.0,
    }
    assert findings[1]["cve"] == "CVE-2024-2" and findings[1]["severity"] == "UNKNOWN"
    assert len(findings[1]["title"]) == 200
    assert trivy.parse({}) == []


def test_trivy_cvss_tolerates_junk():
    assert trivy.cvss({"CVSS": {"a": {"V3Score": "n/a"}, "b": "junk", "c": {"V2Score": "4.3"}}}) == 4.3


def test_grype_parse_extracts_findings():
    findings = grype.parse(GRYPE_REPORT)
    assert findings[0] == {
        "cve": "GHSA-1",
        "severity": "MEDIUM",
        "package": "lodash",
        "installed_version": "1.0",
        "fixed_version": "2.0",
        "title": "desc",
        "cvss": 6.1,
    }
    assert findings[1]["fixed_version"] == "" and findings[1]["cvss"] == 0.0
    assert grype.parse({}) == []


def test_grype_negligible_maps_to_low():
    assert grype.normalise_severity("Negligible") == "LOW"
    assert grype.normalise_severity(None) == "UNKNOWN"
    assert grype.normalise_severity("critical") == "CRITICAL"


def test_parse_json_report_skips_log_noise():
    assert base.parse_json_report('[0000] WARN insecure\n{"a": 1}') == {"a": 1}
    assert base.parse_json_report("  ") == {}


def test_first_error_line_and_tail():
    assert base.first_error_line("starting\nFATAL: no such host\ndone") == "FATAL: no such host"
    assert base.first_error_line("a\nb") == "b"
    assert base.tail("x" * 5000, 100).startswith("…")


@pytest.mark.parametrize(
    "ref",
    [
        "docker:nginx",
        "podman:x",
        "containerd:x",
        "docker-archive:/t.tar",
        "oci-dir:/x",
        "dir:/",
        "file:/etc/passwd",
        "sbom:/x",
    ],
)
def test_runtime_references_are_refused(ref):
    with pytest.raises(ValueError, match="refusing to scan"):
        base.assert_static_ref(ref)


# --- command lines and environments -------------------------------------------------
def test_trivy_arguments_keep_it_offline_and_registry_only(tmp_path):
    args = trivy.build_args("/t/trivy", tmp_path, "rotsy.test:8000/team/app:1.0", insecure=True, tool_timeout="60s")
    for flag in ("--image-src", "--skip-db-update", "--offline-scan", "--skip-version-check", "--insecure"):
        assert flag in args
    assert args[args.index("--image-src") + 1] == "remote"
    assert args[-1] == "rotsy.test:8000/team/app:1.0"
    assert "--skip-java-db-update" not in args  # no Java DB installed: the flag is invalid on a first run
    (tmp_path / "java-db").mkdir()
    (tmp_path / "java-db" / "metadata.json").write_text("{}")
    assert "--skip-java-db-update" in trivy.build_args("/t/trivy", tmp_path, "h/a:1", insecure=False, tool_timeout="1s")


def test_grype_pinned_to_the_local_database(tmp_path):
    args, env = grype.build(
        "/t/grype",
        tmp_path,
        "rotsy.test:8000/team/app:1.0",
        base.Credentials("rotsy-job-x", "rrj_secret"),
        insecure=False,
    )
    assert args[1] == "registry:rotsy.test:8000/team/app:1.0"
    assert env["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert env["GRYPE_DEFAULT_IMAGE_PULL_SOURCE"] == "registry"
    assert env["GRYPE_DB_CACHE_DIR"] == str(tmp_path)
    assert "rrj_secret" not in " ".join(args)  # credentials only in the environment


def test_scanner_environment_drops_proxies_and_foreign_variables(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.evil:3128")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
    env = base.scanner_env({"X": "1"})
    assert "HTTPS_PROXY" not in env and "AWS_SECRET_ACCESS_KEY" not in env
    assert env["X"] == "1" and "PATH" in env


# --- execution ---------------------------------------------------------------------
def _script(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "fake-scanner"
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


async def test_trivy_run_passes_credentials_by_environment_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    exe = _script(tmp_path, 'printf "%s\\n" "$@" > "$HOME/args"; env > "$HOME/env"; echo \'{"Results": []}\'\n')
    outcome = await trivy.run(
        str(exe),
        tmp_path / "cache",
        "rotsy.test:8000/team/app:1.0",
        base.Credentials("rotsy-job-abc", "rrj_super_secret_value"),
        insecure=False,
        timeout=30,
    )
    assert outcome.ok and outcome.vulnerabilities == []
    assert "rrj_super_secret_value" not in (tmp_path / "args").read_text()
    assert "TRIVY_PASSWORD=rrj_super_secret_value" in (tmp_path / "env").read_text()
    assert "rrj_super_secret_value" not in outcome.detail


async def test_scanner_failure_reports_the_explanatory_line(tmp_path):
    exe = _script(tmp_path, 'echo "loading" >&2; echo "FATAL: manifest unknown" >&2; exit 1\n')
    outcome = await grype.run(str(exe), tmp_path, "h/a:1", base.Credentials("u", "rrj_p"), insecure=False, timeout=30)
    assert not outcome.ok and outcome.error == "FATAL: manifest unknown"
    assert "exit 1" in outcome.detail


async def test_unparseable_output_is_a_failure(tmp_path):
    exe = _script(tmp_path, "echo '{not json'\n")
    outcome = await grype.run(str(exe), tmp_path, "h/a:1", base.Credentials("u", "p"), insecure=False, timeout=30)
    assert not outcome.ok and "could not parse" in outcome.error


async def test_a_hung_scanner_is_killed_at_the_timeout(tmp_path):
    exe = _script(tmp_path, "sleep 30\n")
    loop = asyncio.get_running_loop()
    started = loop.time()
    outcome = await grype.run(str(exe), tmp_path, "h/a:1", base.Credentials("u", "p"), insecure=False, timeout=1)
    assert not outcome.ok and "exceeded" in outcome.error
    assert loop.time() - started < 10


async def test_cancellation_kills_the_scanner(tmp_path):
    marker = tmp_path / "still-running"
    exe = _script(tmp_path, f"sleep 2; touch {marker}\n")
    task = asyncio.create_task(base.exec_scanner([str(exe)], base.scanner_env({}), 30))
    await asyncio.sleep(0.3)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(2.5)
    assert not marker.exists()


async def test_a_cancel_during_spawn_still_kills_the_whole_process_group(tmp_path, monkeypatch):
    """Cancelled while the process is being created: it and its children must
    still be killed, or they outlive the job (and can hold its pipes open)."""
    marker = tmp_path / "survived"
    exe = _script(tmp_path, f"(sleep 2; touch {marker}) &\nsleep 30\n")
    real_spawn = asyncio.create_subprocess_exec
    spawned = asyncio.Event()

    async def slow_spawn(*args, **kwargs):
        proc = await real_spawn(*args, **kwargs)
        spawned.set()
        await asyncio.sleep(0.5)  # the process is running; creation has not returned yet
        return proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", slow_spawn)
    task = asyncio.create_task(base.exec_scanner([str(exe)], base.scanner_env({}), 60))
    await asyncio.wait_for(spawned.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 15)
    await asyncio.sleep(2.5)
    assert not marker.exists()
