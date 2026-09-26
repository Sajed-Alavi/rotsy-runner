# Releasing

Versioning is semantic: `src/rotsy_runner/__init__.py` holds `__version__`
(the package reads it; so does the release workflow). `PROTOCOL_VERSION` is
separate and changes only when the runner ⇄ server contract does — a server
refuses registration from a runner speaking another protocol version.

## Cut a release

1. Bump `__version__`, add a `CHANGELOG.md` entry, commit.
2. `git tag v1.0.1 && git push origin main v1.0.1`.
3. `.github/workflows/release.yml` then: runs the tests; builds the wheel,
   sdist and offline bundles for amd64 and arm64 with `scripts/build-release.sh`;
   writes `SHA256SUMS`; creates the GitHub release with those files; pushes
   `ghcr.io/sajed-alavi/rotsy-runner:<tag>` and `:latest` (amd64 + arm64).

## Build locally

```bash
pip install build==1.3.0
scripts/build-release.sh                                        # py3.13, x86_64
BUNDLE_PYTHON=3.12 PLATFORM=manylinux2014_aarch64 scripts/build-release.sh
ls release/    # wheel, sdist, bundle, SHA256SUMS

docker build --target base -t rotsy-runner:1.0.1 .
```

## What a release contains — and does not

It contains the agent. It never contains Trivy, Grype or a vulnerability
database: those are delivered at runtime by the Rotsy server, which decides
their versions. That is why a runner release and a scanner upgrade are
independent — and why an air-gapped runner never needs a new image to pick up
a new scanner version.
