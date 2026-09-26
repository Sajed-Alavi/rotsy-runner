# rotsy-runner

The execution side of [Rotsy](https://github.com/sajed-alavi/rotsy). A runner
executes static container-image scans — Trivy and Grype today — on behalf of a
Rotsy server, and **talks to nothing but that server**:

* its scanner binaries and vulnerability databases come **from the Rotsy
  server**, verified by SHA-256 — never from GitHub, a mirror or a vendor feed;
* it reads images through the server's **job-scoped, read-only registry proxy**
  — it holds no Nexus/registry credential and needs no route to the registry;
* it reports progress and results **to the server**, which stores them and
  decides whether to notify anyone (Telegram lives on the server; the runner
  knows nothing about it).

So a runner can live on a host with **no Internet access at all**.

```
 Internet ──► Rotsy server ──(HTTPS, runner credential)──► rotsy-runner ──► trivy / grype
             (downloads + verifies                          (installs what the
              tools and databases,                           server hands it,
              owns Nexus + Telegram)                         scans, reports)
```

## Quick start (Docker)

```bash
# 1. In Rotsy: Runners → Create runner. It shows a one-time enrollment token.
# 2. Register (prompts for the token — it never lands in shell history):
docker build -t rotsy-runner .
docker run --rm -it -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner \
    register --server https://rotsy.example.com
# 3. Run:
docker run -d --name rotsy-runner --restart unless-stopped \
    -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner
```

Within a heartbeat or two the runner shows as **Online** on the Runners page,
Trivy and Grype show **installing…**, then their versions. Scans queued in
Rotsy are picked up from then on.

Host install with systemd, air-gapped installs and every setting:
[docs/INSTALL.md](docs/INSTALL.md) · [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Commands

```
rotsy-runner register --server URL [--token-file F | --token-stdin | --token T] [--force]
rotsy-runner run          # heartbeat, tool sync, claim and execute scans
rotsy-runner status       # registration + installed tools (no secrets); --json
rotsy-runner unregister   # forget the local registration
rotsy-runner version
```

Exit codes: `0` ok · `1` error · `2` configuration/usage · `3` credential or
token rejected (re-register; systemd will not restart-loop on it).

## Documentation

| | |
| --- | --- |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | components, flows, why it is shaped this way |
| [INSTALL](docs/INSTALL.md) | Docker, systemd host install, air-gapped, registration, token lifecycle |
| [CONFIGURATION](docs/CONFIGURATION.md) | every environment variable |
| [PROTOCOL](docs/PROTOCOL.md) | the runner ⇄ server API: auth, heartbeat, tools, jobs, results, errors |
| [TOOLS](docs/TOOLS.md) | supported scanners, how updates and rollbacks work, adding a tool |
| [OFFLINE](docs/OFFLINE.md) | restricted networks: what the runner needs, how to prove it |
| [SECURITY](docs/SECURITY.md) | threat model, credentials, what a runner can and cannot do |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | symptoms → causes → fixes |
| [DEVELOPMENT](docs/DEVELOPMENT.md) | layout, running tests, conventions |
| [RELEASING](docs/RELEASING.md) | versioning, building, publishing |

## Requirements

A Rotsy server with runner support (runner protocol v1), Linux amd64 or arm64,
and either Docker or Python ≥ 3.12. Nothing else — no Docker socket, no
container runtime, no scanner pre-installed.

## License

See [LICENSE](LICENSE).
