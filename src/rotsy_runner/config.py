"""Runner configuration — from the environment, validated at startup.

Everything is an environment variable (the same rule as the Rotsy server): a
systemd unit, a container and a developer's shell configure it identically,
and there is no config file to leave secrets in. The runner's *identity* (which
server, which runner, its credential) is not configuration — it is written by
``rotsy-runner register`` into the data directory; see :mod:`.state`.

Fails fast on anything invalid rather than guessing: a runner that starts with
a half-understood configuration is harder to debug than one that refuses to.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

DEFAULT_DATA_DIR = "/var/lib/rotsy-runner"


class ConfigError(ValueError):
    """The configuration is unusable; the message says what to fix."""


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value.strip() == "":
        return default
    lowered = value.strip().lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"not a boolean: {value!r}")


def _int(name: str, value: str | None, default: int, lo: int, hi: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        parsed = int(value)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from None
    if not lo <= parsed <= hi:
        raise ConfigError(f"{name} must be between {lo} and {hi}, got {parsed}")
    return parsed


def validate_server_url(url: str, *, allow_insecure_http: bool) -> str:
    """Normalise and check a Rotsy server URL. Returns it without a trailing slash.

    Must be an origin — ``scheme://host[:port]`` — because the server's
    registry proxy lives at the root (``/v2/``) by protocol, and the runner
    builds image references as ``host[:port]/name:tag``.
    """
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigError(f"server URL must be https://host[:port], got {url!r}")
    if parts.scheme == "http" and not allow_insecure_http:
        raise ConfigError(
            "refusing a plain-http server URL: the runner credential and scan results would cross "
            "the network unencrypted. Use https, or set ROTSY_RUNNER_ALLOW_INSECURE_HTTP=true "
            "(or pass --allow-insecure-http) for a local test setup."
        )
    if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
        raise ConfigError(
            f"server URL must be an origin with no path, query or credentials (got {url!r}); the "
            "runner API and the registry proxy are served from the root of that origin"
        )
    return f"{parts.scheme}://{parts.netloc}"


@dataclass(frozen=True)
class Config:
    data_dir: Path
    #: Verify the server's TLS certificate (always, in production).
    tls_verify: bool
    #: A CA bundle for a server certificate from a private CA.
    ca_file: str | None
    allow_insecure_http: bool
    #: Jobs run at once. Trivy runs are serialised regardless (its cache is a
    #: single-writer BoltDB); higher values let Grype scans overlap.
    concurrency: int
    log_level: str
    #: How long SIGTERM/SHUTDOWN waits for running scans before cancelling them.
    shutdown_grace_seconds: int
    #: Wall clock for one scanner invocation, capped by the job's own timeout.
    scan_timeout_seconds: int

    @property
    def state_dir(self) -> Path:
        return self.data_dir / "state"

    @property
    def tools_dir(self) -> Path:
        return self.data_dir / "tools"

    @property
    def cache_dir(self) -> Path:
        return self.data_dir / "cache"

    @property
    def downloads_dir(self) -> Path:
        return self.data_dir / "downloads"

    @property
    def verify(self) -> bool | str:
        """The value httpx wants for ``verify``."""
        if not self.tls_verify:
            return False
        return self.ca_file or True

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **overrides) -> Config:
        env = dict(os.environ if env is None else env)
        data_dir = Path(overrides.pop("data_dir", None) or env.get("ROTSY_RUNNER_DATA_DIR") or DEFAULT_DATA_DIR)
        if not data_dir.is_absolute():
            data_dir = data_dir.resolve()
        ca_file = overrides.pop("ca_file", None) or env.get("ROTSY_RUNNER_CA_FILE") or None
        if ca_file and not Path(ca_file).is_file():
            raise ConfigError(f"ROTSY_RUNNER_CA_FILE {ca_file!r} does not exist")
        log_level = (env.get("ROTSY_RUNNER_LOG_LEVEL") or "INFO").upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ConfigError(f"ROTSY_RUNNER_LOG_LEVEL must be DEBUG/INFO/WARNING/ERROR, got {log_level!r}")
        values = dict(
            data_dir=data_dir,
            tls_verify=_bool(env.get("ROTSY_RUNNER_TLS_VERIFY"), True),
            ca_file=ca_file,
            allow_insecure_http=_bool(env.get("ROTSY_RUNNER_ALLOW_INSECURE_HTTP"), False),
            concurrency=_int("ROTSY_RUNNER_CONCURRENCY", env.get("ROTSY_RUNNER_CONCURRENCY"), 1, 1, 32),
            log_level=log_level,
            shutdown_grace_seconds=_int(
                "ROTSY_RUNNER_SHUTDOWN_GRACE_SECONDS", env.get("ROTSY_RUNNER_SHUTDOWN_GRACE_SECONDS"), 60, 0, 3600
            ),
            scan_timeout_seconds=_int(
                "ROTSY_RUNNER_SCAN_TIMEOUT_SECONDS", env.get("ROTSY_RUNNER_SCAN_TIMEOUT_SECONDS"), 900, 30, 7200
            ),
        )
        values.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**values)
