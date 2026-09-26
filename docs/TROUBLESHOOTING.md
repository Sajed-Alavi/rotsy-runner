# Troubleshooting

Start with `rotsy-runner status` (registration and installed tools, no
secrets) and the logs (`docker logs rotsy-runner` / `journalctl -u rotsy-runner`).
The Runners page in Rotsy shows the same inventory plus the last error.

| Symptom | Cause | Fix |
| --- | --- | --- |
| `Registration refused: This enrollment token has already been used` | tokens are single-use | Runners → the runner → *New enrollment token*, register again |
| `… has expired` | token older than `RUNNER_ENROLLMENT_TOKEN_TTL_SECONDS` | issue a new token |
| `Invalid enrollment token` | typo, or superseded by a newer token | copy the newest token |
| `refusing a plain-http server URL` | `--server http://…` | use https, or `--allow-insecure-http` for a local test setup |
| `server URL must be an origin` | `--server https://host/rotsy` | the runner API and `/v2/` must be served at the root of an origin; route both on your proxy |
| exits with status 3, `credential rejected` | the runner was deleted or reset in Rotsy | `rotsy-runner register --force` with a new token |
| `permission error: …credential is readable by other users` | the credential file mode was loosened | `chmod 600 <data>/state/credential` |
| Runners page: **offline** | no heartbeat for `RUNNER_OFFLINE_AFTER_SECONDS` | is the process running? can it reach the server (`curl -sI https://rotsy…/api/health/live`)? |
| **disabled**, no jobs | disabled on the Runners page | enable it |
| a tool shows `failed … checksum mismatch` | download corrupted or tampered | the runner retries with backoff; persistent → check proxies between runner and server |
| `… reports a different version than X` | the stored artifact is not the version it claims | re-fetch that version on the server (Tools page) |
| `grype-db … not usable` | database schema newer/older than the installed Grype | set a Grype version that reads the current schema (Tools page); the previous database stays active meanwhile |
| tools stay `not stored on the server yet` | the server has not downloaded that version for this platform | Tools page → *Fetch*, or the offline import on air-gapped servers |
| scans fail `unauthorized` / `invalid or expired job credential` | the job's lease lapsed (runner paused/suspended) or it was cancelled | it is re-queued automatically; check the runner's clock and load |
| scans fail `manifest unknown` | the tag no longer exists in Nexus | nothing to scan |
| scans queue forever then fail `no runner … claimed this scan` | no online runner has the required tools ready | check the runner's tools on the Runners page |
| `Tool sync failed (cannot reach …)` in a loop | server unreachable | the runner backs off (≤ 5 min) and recovers by itself |

## Debug logging

`ROTSY_RUNNER_LOG_LEVEL=DEBUG` adds per-request detail. Secrets are redacted
at every level; it is safe to share the output.

## Checking offline isolation

```bash
docker exec rotsy-runner python -c "import socket; socket.create_connection(('github.com', 443), 5)"
```

should fail on an isolated runner — while scans keep working.
