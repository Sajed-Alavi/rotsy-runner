# Installation and registration

Two supported ways to run a runner. **Docker is the primary one**: the image
is small, carries no scanner, and moves into air-gapped networks with
`docker save`/`docker load`. The systemd host install is for hosts without
Docker; it installs from a checksum-verified bundle with no network access.

Either way the host needs a route to the Rotsy server and nothing else.

## 1. Create the runner in Rotsy

Runners → **Create runner** → give it a name (e.g. `runner-01`). Rotsy shows a
**one-time enrollment token** and the registration command. The token:

* works **once** — replaying it answers `410 token_used`;
* **expires** after `RUNNER_ENROLLMENT_TOKEN_TTL_SECONDS` (default 1 hour) —
  `410 token_expired`; issue a new one from the runner's page;
* is stored on the server only as a SHA-256 hash, and is shown only once.

## 2a. Docker

```bash
git clone https://github.com/sajed-alavi/rotsy-runner && cd rotsy-runner
docker build -t rotsy-runner .

# Register: prompts for the token (no echo), so it stays out of shell history.
docker run --rm -it -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner \
    register --server https://rotsy.example.com

docker run -d --name rotsy-runner --restart unless-stopped \
    --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges \
    -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner
docker logs -f rotsy-runner
```

Non-interactive registration (automation), without a TTY:

```bash
printf '%s' "$TOKEN" | docker run --rm -i -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner \
    register --server https://rotsy.example.com --token-stdin
```

Or register on first start (the token is spent on first use; remove it afterwards):

```bash
docker run -d --name rotsy-runner -v rotsy-runner-data:/var/lib/rotsy-runner \
    -e ROTSY_SERVER_URL=https://rotsy.example.com -e ROTSY_ENROLLMENT_TOKEN=rre_… rotsy-runner
```

A compose file is in [`docker-compose.example.yml`](../docker-compose.example.yml).

### Air-gapped Docker install

On a connected machine: `docker build -t rotsy-runner . && docker save rotsy-runner | gzip > rotsy-runner.tar.gz`,
carry the file over, then `docker load < rotsy-runner.tar.gz` on the runner
host. Nothing else is needed: scanners and databases arrive from the Rotsy server.

## 2b. systemd host install

On a connected machine, build (or download from a release) the bundle for the
host's Python version and architecture, plus `SHA256SUMS`:

```bash
scripts/build-release.sh                                     # py3.13, x86_64
BUNDLE_PYTHON=3.12 PLATFORM=manylinux2014_aarch64 scripts/build-release.sh
```

On the runner host (no Internet needed):

```bash
sudo ./packaging/install.sh rotsy-runner-1.0.0-bundle-py3.13-manylinux2014_x86_64.tar.gz SHA256SUMS
sudo -u rotsy-runner /opt/rotsy-runner/bin/rotsy-runner register --server https://rotsy.example.com
sudo systemctl enable --now rotsy-runner
journalctl -u rotsy-runner -f
```

`install.sh` refuses to proceed unless the bundle's SHA-256 matches
`SHA256SUMS`, installs with `pip --no-index` (never contacts PyPI), creates the
`rotsy-runner` user and `/var/lib/rotsy-runner` (0700), and installs the
hardened unit in [`packaging/systemd`](../packaging/systemd/rotsy-runner.service).
There is deliberately no `curl | sh` installer.

## 3. What happens next

1. The runner stores its identity and credential in `<data>/state/`
   (`credential` is mode 0600 in a 0700 directory) and starts heartbeating.
2. The Runners page shows it **Online** with its OS/arch, version, hostname and
   capabilities.
3. The server answers the first heartbeat with `SYNC_TOOLS`; the runner fetches
   Trivy, Grype and their databases from the server (**installing…**),
   verifies and installs them, and reports the versions.
4. From then on it claims queued scans.

## Credential lifecycle

| Action (Runners page) | Effect on the runner |
| --- | --- |
| Disable | keeps heartbeating (shows *disabled*), takes no jobs, gets no tools (403) |
| Enable | back to normal on the next heartbeat |
| Reset registration | current credential rejected at once (401); register again with the new token |
| Delete | credential rejected at once (401); its running scan is re-queued |

On 401 the runner exits with status 3 and does not retry. Re-register with
`rotsy-runner register --force` and a new token.

## Uninstall

Docker: `docker rm -f rotsy-runner && docker volume rm rotsy-runner-data`.
systemd: `systemctl disable --now rotsy-runner`, remove `/opt/rotsy-runner`,
`/var/lib/rotsy-runner`, `/etc/systemd/system/rotsy-runner.service`, the user.
Then delete the runner on the Runners page.
