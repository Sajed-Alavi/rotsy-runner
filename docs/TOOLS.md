# Tools: supported scanners, updates, rollback, adding one

## Supported today

| Tool | Kind | Installed how | Ready when |
| --- | --- | --- | --- |
| `trivy` | binary | the `trivy` executable extracted from the vendor release tar.gz | it runs and `trivy --version` reports the version the server promised |
| `grype` | binary | the `grype` executable from the vendor release tar.gz | `grype version` reports the promised version |
| `trivy-db` | database | the server's `db.tar.gz` unpacked into `cache/trivy/db` | `trivy.db` and `metadata.json` present |
| `trivy-java-db` | database (optional) | `javadb.tar.gz` into `cache/trivy/java-db` | files present; Trivy then also covers JARs offline |
| `grype-db` | database | `grype db import` into a staging dir, then swapped in | `grype db status` says valid |

Supported platforms: `linux/amd64`, `linux/arm64`. A binary is only ever
offered for, and installed on, the platform it was built for.

## Where they come from

Only from the Rotsy server. The **server** downloads each release from the
vendor (or an internal mirror), verifies it against the vendor's published
checksums file, and stores it; it refreshes the vulnerability databases on its
own schedule. The runner downloads from `GET /api/runner-agent/v1/artifacts/{id}`
and nowhere else — the client code refuses any other destination and there is
no vendor URL in this repository (a test enforces that).

## Updates

1. An administrator picks a version on Rotsy's Runners → Tools page. The
   server fetches and verifies that release (it refuses to make a version
   desired before it has the artifact).
2. Every runner is flagged; its next heartbeat gets `SYNC_TOOLS`.
3. The runner downloads the new artifact (resuming a partial download),
   checks the SHA-256, unpacks it beside the current version, **runs it** to
   confirm the version, then atomically switches `tools/<tool>/current`.
4. The next heartbeat reports the new version.

Databases work the same way, driven by the server publishing a new snapshot;
the swap takes a write lock so no scan sees a half-replaced database.

A failure at any step — bad checksum, corrupt archive, a binary that does not
run or reports the wrong version, a database Grype cannot load — leaves the
working version active, reports the error on the Runners page, and retries
with exponential backoff (30 s doubling, capped at 30 min).

## Rollback

The previous binary version stays unpacked. Choosing it again on the server
(Tools → *Roll back*) makes the runner re-activate it with a symlink swap and
no download (it checks the stored checksum marker first).

## Adding a tool (Syft, Dockle, Semgrep …)

1. **Server** (Rotsy): add a `ToolDef` in `backend/app/core/tools.py`; if it is
   a GitHub-released binary, one `GitHubReleaseSource` entry in
   `backend/app/modules/toolchain/sources.py` teaches the server to download
   and verify it.
2. **Runner**: add a `ToolSpec` in `src/rotsy_runner/tools/specs.py` — for a
   single executable in a tar.gz the existing `binary` installer does
   everything (extract, probe version, atomic switch, rollback).
3. For a scanner: an adapter in `src/rotsy_runner/scanners/` with `run` and
   `parse`, and a branch in `Executor._scan_one`; add the name to the job
   contract's scanner set on both sides.

Nothing in the manager, the client or the protocol changes.
