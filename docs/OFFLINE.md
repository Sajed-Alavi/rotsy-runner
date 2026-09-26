# Offline and restricted networks

The design assumption: **a runner may have no Internet access at all.** It
needs exactly one network path — to the Rotsy server's HTTPS origin.

```
                 Internet / vendor feeds / Telegram
                               │   (optionally via SCANNER_PROXY,
                               ▼    TELEGRAM_PROXY_URL on the server)
 Nexus ◄──────────────── Rotsy server
                               ▲
                               │ HTTPS: /api/runner-agent/v1/*, /v2/*
                               │
                         rotsy-runner  ──✗──  Internet, Nexus, Telegram
```

| Needed by a scan | Comes from |
| --- | --- |
| Trivy / Grype binaries | Rotsy server artifact endpoint |
| Vulnerability databases | Rotsy server artifact endpoint |
| Image manifests and layers | Rotsy server's job-scoped `/v2/` proxy (server → Nexus) |
| Where to send results | Rotsy server |
| Telegram | nowhere — the server notifies, the runner never knows |

## What the runner does to stay offline

* **HTTP client**: one origin; `trust_env=False` (ambient proxies ignored); no
  redirects; download paths must be the server's artifact endpoint.
* **Trivy**: `--skip-db-update`, `--skip-java-db-update` (when the Java DB is
  installed), `--offline-scan`, `--skip-version-check`, `--image-src remote`.
* **Grype**: `GRYPE_DB_AUTO_UPDATE=false`, `GRYPE_CHECK_FOR_APP_UPDATE=false`,
  `GRYPE_DB_VALIDATE_AGE=false`, `GRYPE_DEFAULT_IMAGE_PULL_SOURCE=registry`.
* **Scanner environment**: only `PATH`, `HOME`, `TMPDIR`, locale and CA
  variables are inherited — no `HTTP(S)_PROXY`.

## When the server is offline too

The server can import everything from its offline directory (`./offline-db`
on the Rotsy host): database archives at the top level, scanner release
archives **with their vendor checksums file** in `offline-db/tools/`. See
Rotsy's docs (*Offline / air-gapped deployment*). Runners are unaffected —
they receive whatever the server published, the same way.

## Proving it

Put the runner on a Docker network with no route out, shared only with the
Rotsy backend:

```yaml
networks:
  runner-only:
    internal: true        # no external connectivity
services:
  runner:
    networks: [runner-only]
```

Then check from inside the runner container that the world is unreachable
while scans still complete:

```bash
docker exec rotsy-runner python -c "import socket; socket.create_connection(('github.com', 443), 5)"
# → socket.gaierror / timeout: no route
```

Rotsy's repository ships exactly this setup as its end-to-end test
(`e2e/runner/`). In this repository, `tests/test_offline.py` pins the
guarantee: no vendor or Telegram endpoint may appear in the runner's code, the
scanners' no-update flags must be present, and a full register → sync → scan →
report cycle against a transport that fails on any other host must succeed.
