# Runner protocol (v1)

The contract between rotsy-runner and a Rotsy server. Server side:
`backend/app/schemas/runners.py` and `backend/app/routers/runner_agent.py`
in the Rotsy repository; runner side: `src/rotsy_runner/protocol.py`.

All endpoints are under `/api/runner-agent/v1` on the server origin. JSON in,
JSON out. Request bodies are validated strictly by the server: unknown fields,
over-long strings, out-of-range numbers → `422`; bodies over the size cap
(256 KiB; 48 MiB for results) → `413`.

## Authentication

* `POST /register` takes a one-time enrollment token in the body.
* Everything else: `Authorization: Bearer rrt_…` (the runner credential). The
  server re-reads the runner on every request — no caching — so a deletion,
  a reset or a disable applies on the runner's next call.
* The registry proxy (`/v2/…`) takes HTTP Basic with the **job** credential
  (`rotsy-job-<job_uid>` / `rrj_…`), never the runner credential.

## Errors

`{"detail": {"code": "...", "message": "..."}}` (422 keeps FastAPI's list form).

| Status | Code examples | Runner does |
| --- | --- | --- |
| 401 | `invalid_credential`, `invalid_token` | stop; exit 3; re-register |
| 403 | `runner_disabled` | keep heartbeating; take no work; fetch no tools |
| 404 / 409 | `unknown_job`, `job_conflict` | drop the job; its result would be refused |
| 410 | `token_used`, `token_expired` | get a new enrollment token |
| 400 | `protocol_mismatch`, `unsupported_platform` | fix the install |
| 413 / 422 | — | bug in the runner; logged |
| 5xx, network | — | back off (1 s → 60 s, jittered) and retry |

Redirects are never followed (a redirect would carry the credential elsewhere).

## Register

`POST /register`

```json
{"token": "rre_…", "hostname": "scan-01", "os": "linux", "arch": "amd64",
 "version": "1.0.0", "protocol_version": 1,
 "capabilities": ["container_scan", "scanner:trivy", "scanner:grype"], "concurrency": 1}
```

`201`:

```json
{"runner_uid": "3f0c…", "name": "runner-01", "credential": "rrt_…",
 "heartbeat_interval_seconds": 15, "protocol_version": 1, "server_version": "1.x"}
```

Supported platforms: `linux/amd64`, `linux/arm64` (anything else: `400 unsupported_platform`).

## Heartbeat

`POST /heartbeat`

```json
{"state": "idle", "version": "1.0.0", "hostname": "scan-01", "os": "linux", "arch": "amd64",
 "protocol_version": 1, "capabilities": ["container_scan"], "concurrency": 1,
 "tools": [{"name": "trivy", "kind": "binary", "version": "0.73.0", "sha256": "…",
            "status": "installed", "ready": true, "error": ""}],
 "running_jobs": ["<job_uid>"], "last_error": ""}
```

`state`: `idle | busy | syncing | draining`. Tool `status`:
`installed | installing | failed | missing`; `ready` means installed *and*
usable (a database the scanner can load). Unknown tool names are ignored.

`200`:

```json
{"runner_status": "active", "heartbeat_interval_seconds": 15, "desired_tools_revision": "9c1e…",
 "commands": [{"type": "SYNC_TOOLS", "reason": "installed tools differ from the desired set"},
              {"type": "CANCEL_JOB", "job_uid": "…", "reason": "cancelled by an operator"}]}
```

Commands are a closed set: `SYNC_TOOLS`, `CANCEL_JOB`, `SHUTDOWN`. The runner
ignores (and logs) anything else. No command carries a program to run.

## Tools

`GET /tools/desired` → the manifest for *this runner's* platform:

```json
{"platform": "linux/amd64", "revision": "9c1e…", "artifacts": [
  {"name": "trivy", "kind": "binary", "version": "0.73.0", "os": "linux", "arch": "amd64",
   "available": true, "artifact_id": 7, "filename": "trivy_0.73.0_Linux-64bit.tar.gz",
   "sha256": "…", "size_bytes": 51234567, "download_path": "/api/runner-agent/v1/artifacts/7"},
  {"name": "grype-db", "kind": "database", "version": "20260925T061349Z", "os": "any", "arch": "any",
   "available": true, "artifact_id": 12, "sha256": "…", "download_path": "/api/runner-agent/v1/artifacts/12"},
  {"name": "grype", "kind": "binary", "version": "0.117.0", "available": false,
   "reason": "grype 0.117.0 for linux/amd64 is not stored on the server yet"}]}
```

`GET /artifacts/{artifact_id}` → the file (`Content-Length`,
`Content-Type`, `X-Checksum-Sha256`, `X-Artifact-Version`). `Range` is
supported (206) for resumable downloads. A runner may download only artifacts
in its own current manifest; anything else is `404 not_allowed`. The id is the
only input — there is no path parameter to traverse with.

The runner refuses any `download_path` that is not a relative path under
`/api/runner-agent/v1/artifacts/`, and installs nothing whose SHA-256 differs
from the manifest.

## Jobs

`POST /jobs/claim` `{"wait_seconds": 20, "capacity": 1}` → `204` after the wait
if nothing matched, or `200`:

```json
{"job_uid": "…32 hex…", "type": "SCAN_IMAGE", "attempt": 1, "lease_seconds": 180,
 "timeout_seconds": 1500, "scanners": ["trivy", "grype"],
 "target": {"repo": "docker-hosted", "image": "team/app:1.0", "name": "team/app", "tag": "1.0",
            "registry": {"username": "rotsy-job-…", "password": "rrj_…"}}}
```

A runner is offered only jobs whose required tools it reports ready. Job types
are a closed set (`SCAN_IMAGE`). The runner validates everything before
running anything: type, scanners (`trivy|grype`), `name`/`tag` against the
Docker reference grammar, no runtime scheme (`docker:`, `dir:` …).

`POST /jobs/{uid}/progress` `{"percent": 40, "message": "trivy: scanning", "stage": "scanning"}`
→ `{"cancel_requested": false, "lease_seconds": 180}`. Every report renews the
lease; the runner also renews it every `lease_seconds/3` during long scans. A
lease that lapses re-queues the job for another runner (up to 3 attempts).

`POST /jobs/{uid}/complete`:

```json
{"results": [{"scanner": "trivy", "ok": true, "tool_version": "0.73.0", "db_version": "2026-09-25T…",
              "duration_ms": 18234, "error": "", "detail": "$ trivy image … (redacted)\nexit 0\n…",
              "findings": [{"cve": "CVE-2024-0001", "severity": "CRITICAL", "package": "openssl",
                            "installed_version": "3.0.0", "fixed_version": "3.0.1",
                            "title": "…", "cvss": 9.8}]}]}
```

A scanner failure is a result (`ok: false` + `error`), not a job failure.
Results for scanners the job did not ask for, or duplicates → `409`.

`POST /jobs/{uid}/fail` `{"error": "…", "detail": "", "retryable": false}` — the
job could not be done at all. `retryable: true` (tools not ready, shutting
down) hands it back to the queue.

## Registry proxy

`GET|HEAD /v2/`, `/v2/<name>/manifests/<tag-or-digest>`,
`/v2/<name>/blobs/<digest>`, Basic auth with the job credential. Only the
job's image; the tag first, then only digests that image's manifests
reference; only while the job is running. No write method exists (405).
