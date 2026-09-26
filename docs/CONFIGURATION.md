# Configuration

All configuration is environment variables — for systemd in
`/etc/rotsy-runner/env`, for Docker via `-e`/`--env-file`. Every setting is
optional and the defaults are the secure choice. Invalid values stop the
runner at startup with a message naming the variable (exit 2).

| Variable | Default | Meaning |
| --- | --- | --- |
| `ROTSY_RUNNER_DATA_DIR` | `/var/lib/rotsy-runner` | identity, credential, installed tools, scanner caches, partial downloads |
| `ROTSY_RUNNER_TLS_VERIFY` | `true` | verify the server certificate; `false` only for throwaway test setups |
| `ROTSY_RUNNER_CA_FILE` | — | CA bundle for a server certificate from a private CA |
| `ROTSY_RUNNER_ALLOW_INSECURE_HTTP` | `false` | allow an `http://` server URL (local development only); also `--allow-insecure-http` |
| `ROTSY_RUNNER_CONCURRENCY` | `1` | jobs at once, 1–32; Trivy runs are serialised regardless |
| `ROTSY_RUNNER_SHUTDOWN_GRACE_SECONDS` | `60` | on SIGTERM/`SHUTDOWN`, how long running scans may finish before being handed back |
| `ROTSY_RUNNER_SCAN_TIMEOUT_SECONDS` | `900` | wall clock per scanner invocation (capped by the job's timeout) |
| `ROTSY_RUNNER_LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`; secrets are redacted at every level |
| `ROTSY_SERVER_URL` + `ROTSY_ENROLLMENT_TOKEN` | — | register on first `run` if the data dir has no identity (containers) |

The heartbeat interval is not configured on the runner: the server sets it in
every heartbeat response (`RUNNER_HEARTBEAT_INTERVAL_SECONDS` on the server).

## The server URL

`--server` must be an **origin**: `https://host[:port]`, no path. The runner
API lives at `/api/runner-agent/v1/…` and the registry proxy at `/v2/…` on
that origin — Docker registries live at the root by protocol. If Rotsy sits
behind a reverse proxy, route both `/api/runner-agent/` and `/v2/` to the
backend.

## What is deliberately not configurable

* **Proxies.** The runner ignores `HTTP(S)_PROXY`: it talks to its server
  directly, and scanner subprocesses inherit only `PATH`, `HOME`, `TMPDIR`,
  locale and CA settings. An ambient proxy cannot reroute the credential or
  the image pull.
* **Scanner versions and database sources.** Chosen on the server.
* **Registry credentials.** Issued per job by the server.

## Data directory layout

```
/var/lib/rotsy-runner/          0700, owned by the runner user
  state/runner.json             server URL, runner uid/name (not secret)
  state/credential              runner credential, 0600
  state/tools.json              installed tools, checksums, previous versions
  tools/<tool>/<version>-<sha>/ unpacked binaries; tools/<tool>/current → active
  cache/trivy/{db,java-db}      Trivy databases (from the server)
  cache/grype/                  Grype database (from the server)
  downloads/                    in-progress downloads (*.partial, resumable)
```
