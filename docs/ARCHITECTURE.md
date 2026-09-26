# Architecture

rotsy-runner is the execution half of Rotsy's container-image scanning. The
Rotsy server decides *what* to scan and owns every external connection; the
runner does the scanning and nothing else. This document explains the pieces
and — more usefully — why they are shaped this way.

## The split

| Rotsy server | rotsy-runner |
| --- | --- |
| users, projects, RBAC, audit log | — |
| runner registration, credentials, inventory, health | registration, heartbeat, capability + inventory reporting |
| scan triggers (Nexus webhook, push watcher, Scan button) | — |
| job queue, assignment, leases, cancellation | claim, execute, report progress, return results |
| **downloads** Trivy/Grype releases and vulnerability databases, verifies them | **receives** them from the server, verifies again, installs atomically |
| desired tool versions, upgrades, rollback | reconciles its installed tools to the server's manifest |
| Nexus credentials; registry discovery; job-scoped `/v2/` proxy | reads images through that proxy with a per-job credential |
| results persistence, reports, PDFs, SSE progress | — |
| notification policy; Telegram | — (no Telegram code, token or network access) |

The server never executes a scanner. The runner never contacts anything but the server.

## Components

```
src/rotsy_runner/
  cli.py          register | run | status | unregister | version
  config.py       environment → validated Config (fails fast)
  state.py        identity (runner.json) + credential file (0600, atomic)
  logs.py         logging with secret redaction
  client.py       the only network client; one origin, no redirects, no proxies
  protocol.py     wire contracts; strict for jobs, lenient for everything else
  agent.py        heartbeat loop, tool-sync loop, N workers, commands, shutdown
  executor.py     validate → check tools → scan → progress → result
  tools/
    specs.py      what each tool is and how it installs  ← the extension point
    manager.py    reconcile with the server manifest; verified, atomic installs
    locks.py      readers–writer lock: scans vs. tool swaps
  scanners/
    base.py       static-ref guard, bounded subprocess exec (process-group kill)
    trivy.py      Trivy adapter + report parser
    grype.py      Grype adapter + report parser
```

## Lifecycles

**Registration.** An administrator clicks *Create runner* in Rotsy and gets a
one-time enrollment token (`rre_…`, expires, stored hashed). `rotsy-runner
register` sends it with the host's facts (hostname, OS/arch, version,
protocol version, capabilities). The server returns the runner's identity and
a long-lived credential (`rrt_…`), written to `state/credential` with mode
0600. The token is now spent.

**Heartbeat** (every `heartbeat_interval_seconds`, set by the server). The
runner reports state (`idle|busy|syncing|draining`), its tool inventory with
per-tool readiness, and the jobs it is running. The server answers with typed
commands — `SYNC_TOOLS`, `CANCEL_JOB`, `SHUTDOWN` — and whether the runner is
enabled. There is no command that carries a program or argument list.

**Tool sync** (at start, and on `SYNC_TOOLS`). The runner fetches its manifest
(`GET /tools/desired`: for its own platform, which artifact of each tool by
SHA-256), downloads anything that differs from the server's artifact endpoint
(resumable), verifies the SHA-256, installs it beside the current version,
proves it works (a binary must run and report the promised version; a Grype
database must pass `grype db status`), and switches over with one rename.
Failures leave the working version in place and back off exponentially.

**A scan.** A worker long-polls `POST /jobs/claim`. The assignment names the
image (`name:tag`), the scanners, a lease and a registry credential valid only
for this job. The executor validates all of it, checks the tools are ready,
and runs each scanner against `<server-host>/<name>:<tag>` — the server's
registry proxy — with the credential in the scanner's environment. Progress
reports renew the lease and are how a cancellation arrives. The structured
result (findings per scanner, versions, timings, redacted diagnostics) is
posted to `/complete`; the server writes the reports, closes its ledger and
decides about notifications.

**Shutdown** (SIGTERM, SIGINT or `SHUTDOWN`). Stop claiming; let running scans
finish within the grace period; hand the rest back as retryable so another
runner takes them; send a last heartbeat (`draining`).

## Why HTTPS long polling

The runner needs heartbeat, job delivery, acknowledgement, progress and
completion. The Rotsy server is a FastAPI app with a Redis-backed job queue
and SSE for browsers. Long-polled HTTPS fits that without new infrastructure:
it passes through every proxy and load balancer an operator already has,
needs no inbound connectivity to the runner, and makes each interaction a
plain authenticated request the server can refuse. WebSockets would add a
long-lived connection to manage and authenticate for no capability the
protocol needs; a broker would add a service to operate. Rotsy's own Redis job
queue stays server-side: the server creates the Redis job the UI watches and
a durable runner-job row; runners claim through the API, never Redis.

## Why a registry proxy instead of registry credentials

The only credential that can read images in Nexus is Rotsy's service account,
an administrator. Putting it on every runner would place the most powerful
secret in the system on the machines most exposed to untrusted content. The
per-job proxy credential is good for one image, reads only, and only while the
job runs; the server holds the real credential and forwards. As a side effect
runners need no network path to Nexus at all.

## Concurrency

`ROTSY_RUNNER_CONCURRENCY` workers claim independently. Trivy's cache is a
single-writer BoltDB, so Trivy invocations are serialised; Grype scans overlap.
Tool swaps take a per-scanner write lock, so a scan never sees a database
directory mid-replacement.
