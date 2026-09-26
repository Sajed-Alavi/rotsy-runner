# Changelog

## Unreleased

- **Telemetry.** Every heartbeat carries a metrics snapshot — CPU and memory
  (the container's own via cgroup v2, else the host's), disk, network, load,
  process memory, job counters, per-scanner success and timings, heartbeat
  round trip, reconnects, tool syncs — and the events since the last one
  (scans, tool installs and failures, lost/restored connections, commands).
  Sent only to a server that advertises `features: ["metrics", "events"]`;
  undelivered events are retried with the next heartbeat. No new dependency.
- A cancel that lands while a scanner is still being spawned now kills its
  whole process group (it could previously leave the scanner's children
  holding the job open).
- A job's scanners run side by side instead of one after the other: a scan
  now takes as long as the slower scanner. Each scanner gets the job's whole
  timeout (capped by `ROTSY_RUNNER_SCAN_TIMEOUT_SECONDS`), and a cancellation kills
  every running scanner.
- CI and release workflows removed for now; releases are cut by hand (see
  docs/RELEASING.md).

## 1.0.0

First release: the execution side of Rotsy, extracted from the Rotsy server.

- Registration with a one-time enrollment token exchanged for a revocable
  runner credential (stored 0600); `register` reads the token from a prompt,
  a file or stdin so it stays out of shell history.
- Heartbeat with state, capabilities and per-tool inventory; typed server
  commands only (`SYNC_TOOLS`, `CANCEL_JOB`, `SHUTDOWN`).
- Tool management: Trivy, Grype and their databases received from the Rotsy
  server only, SHA-256 verified, installed atomically, version-probed,
  upgradable, with one-step rollback and backoff on failure.
- Scan execution through the server's job-scoped registry proxy, static
  registry reads only, credentials via environment, process-group kill on
  timeout or cancellation.
- Reconnect with jittered backoff; fail-closed on a rejected credential
  (exit 3); graceful shutdown that hands running work back.
- Docker image (no scanners inside), hardened systemd unit, checksum-verified
  offline install bundle.
