"""Configuration validation, identity storage and log redaction."""

from __future__ import annotations

import logging
import stat

import pytest

from rotsy_runner import logs, state
from rotsy_runner.config import Config, ConfigError, validate_server_url


# --- config -------------------------------------------------------------------------
def test_defaults_are_secure(tmp_path):
    config = Config.from_env({}, data_dir=str(tmp_path))
    assert config.tls_verify is True
    assert config.allow_insecure_http is False
    assert config.concurrency == 1
    assert config.verify is True


@pytest.mark.parametrize(
    "env,message",
    [
        ({"ROTSY_RUNNER_CONCURRENCY": "0"}, "between 1 and 32"),
        ({"ROTSY_RUNNER_CONCURRENCY": "lots"}, "integer"),
        ({"ROTSY_RUNNER_TLS_VERIFY": "maybe"}, "boolean"),
        ({"ROTSY_RUNNER_LOG_LEVEL": "LOUD"}, "LOG_LEVEL"),
        ({"ROTSY_RUNNER_CA_FILE": "/nonexistent/ca.pem"}, "does not exist"),
    ],
)
def test_invalid_config_fails_fast(tmp_path, env, message):
    with pytest.raises(ConfigError, match=message):
        Config.from_env(env, data_dir=str(tmp_path))


def test_ca_file_is_used_for_verification(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n")
    config = Config.from_env({"ROTSY_RUNNER_CA_FILE": str(ca)}, data_dir=str(tmp_path))
    assert config.verify == str(ca)
    assert Config.from_env({"ROTSY_RUNNER_TLS_VERIFY": "false"}, data_dir=str(tmp_path)).verify is False


def test_server_url_must_be_https_origin():
    assert validate_server_url("https://rotsy.example.com/", allow_insecure_http=False) == "https://rotsy.example.com"
    assert validate_server_url("https://rotsy.example.com:8443", allow_insecure_http=False).endswith(":8443")
    with pytest.raises(ConfigError, match="plain-http"):
        validate_server_url("http://rotsy.example.com", allow_insecure_http=False)
    assert validate_server_url("http://backend:8000", allow_insecure_http=True) == "http://backend:8000"
    for bad in (
        "ftp://x",
        "rotsy.example.com",
        "https://rotsy.example.com/api",
        "https://u:p@rotsy.example.com",
        "https://rotsy.example.com/?next=evil",
    ):
        with pytest.raises(ConfigError):
            validate_server_url(bad, allow_insecure_http=True)


# --- identity -----------------------------------------------------------------------
def _identity() -> state.Identity:
    return state.Identity("https://rotsy.example.com", "u" * 32, "runner-01", "2026-09-26T00:00:00+00:00", 1)


def test_credential_is_stored_private(tmp_path):
    state.save(tmp_path / "state", _identity(), "rrt_secret_credential_value")
    cred = tmp_path / "state" / state.CREDENTIAL_FILE
    assert stat.S_IMODE(cred.stat().st_mode) == 0o600
    assert stat.S_IMODE((tmp_path / "state").stat().st_mode) == 0o700
    identity, credential = state.load(tmp_path / "state")
    assert identity.name == "runner-01" and credential == "rrt_secret_credential_value"
    # The identity file carries no secret.
    assert "rrt_" not in (tmp_path / "state" / state.IDENTITY_FILE).read_text()


def test_loose_credential_permissions_are_refused(tmp_path):
    state.save(tmp_path / "state", _identity(), "rrt_secret_credential_value")
    (tmp_path / "state" / state.CREDENTIAL_FILE).chmod(0o644)
    with pytest.raises(PermissionError, match="chmod 600"):
        state.load(tmp_path / "state")


def test_unregistered_and_clear(tmp_path):
    assert state.load(tmp_path / "state") is None
    state.save(tmp_path / "state", _identity(), "rrt_x" * 5)
    assert state.clear(tmp_path / "state") is True
    assert state.load(tmp_path / "state") is None


# --- redaction ----------------------------------------------------------------------
def test_secrets_are_redacted_from_logs(caplog):
    logs.register_secret("a-very-specific-secret-value")
    record = logging.LogRecord(
        "t",
        logging.INFO,
        __file__,
        1,
        "token %s cred %s job %s auth %s custom %s",
        (
            "rre_" + "a" * 43,
            "rrt_" + "b" * 43,
            "rrj_" + "c" * 43,
            "Authorization: Bearer abc.def",
            "a-very-specific-secret-value",
        ),
        None,
    )
    logs.RedactingFilter().filter(record)
    message = record.getMessage()
    for leaked in ("a" * 43, "b" * 43, "c" * 43, "abc.def", "a-very-specific-secret-value"):
        assert leaked not in message
    assert "rre_***" in message and "rrt_***" in message
