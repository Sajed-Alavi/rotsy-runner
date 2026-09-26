# Security model

## What a runner holds

| Secret | Where | Scope | Revocation |
| --- | --- | --- | --- |
| enrollment token `rre_…` | typed once at registration; never stored by the runner | one use, expires (default 1 h) | used, expired, or superseded by a new one |
| runner credential `rrt_…` | `state/credential`, 0600 in a 0700 dir | this runner's API access | delete or reset the runner in Rotsy — effective on its next request |
| job registry credential `rrj_…` | memory, and the scanner's environment for one scan | one image, read-only, while the job runs | automatic at completion, cancellation, re-queue or lease expiry |

The runner never holds Nexus credentials, the Telegram bot token, or any
other server secret; the tests assert none of them appear in any response a
runner receives.

## What a runner can do

* Report its own heartbeat and inventory.
* Download artifacts in **its own** current manifest (its platform, desired versions).
* Claim jobs it has the tools for; report progress/results **for its own jobs**
  only (someone else's job → 409).
* Read, through the proxy, the one image a running job names.

It cannot list other runners, read scan history, see users, reach other
repositories, write to the registry, or receive a command line. Job and
command types are closed enumerations validated on both ends; a malformed or
unknown job is refused before anything executes.

## What the runner protects against a compromised input

* **Artifacts**: SHA-256 must match the manifest; binaries must run and report
  the promised version; archives are unpacked with Python's `data` tar filter
  (no absolute paths, `..`, links out or devices); the executable must be a
  regular file. A failed install never replaces the working version.
* **Jobs**: image name/tag must match the Docker reference grammar; runtime
  sources (`docker:`, `podman:`, `dir:`, `file:` …) are refused twice (protocol
  and executor); scanners get an argv, never a shell.
* **Network**: TLS verification on by default; plain HTTP refused unless
  explicitly allowed; no redirects; no ambient proxies.
* **Logs**: every record is passed through a redaction filter that removes
  `rre_`/`rrt_`/`rrj_` tokens, `Authorization` headers and registered secrets;
  scanner command lines shown to operators are redacted too.

## Static scanning only

The runner never runs a scanned image. It has no container runtime and no
Docker socket; Trivy is pinned to `--image-src remote` and Grype to explicit
`registry:` references. This is the same guarantee the Rotsy server made when
it ran the scanners itself, enforced at the same points.

## Hardening recommendations

* Run the Docker image with `--read-only --cap-drop ALL --security-opt no-new-privileges`
  (see the compose example), or the systemd unit as shipped (it sandboxes the
  service to its data directory and `AF_INET/AF_INET6/AF_UNIX`).
* Restrict egress to the Rotsy server (firewall, `IPAddressAllow=`, or an
  `internal` Docker network).
* Put the Rotsy server behind TLS; use `ROTSY_RUNNER_CA_FILE` for a private CA.
