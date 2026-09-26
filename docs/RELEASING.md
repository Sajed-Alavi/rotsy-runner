# Releasing

Versioning is semantic: `src/rotsy_runner/__init__.py` holds `__version__`
(the package and `scripts/build-release.sh` read it). `PROTOCOL_VERSION` is
separate and changes only when the runner ⇄ server contract does — a server
refuses registration from a runner speaking another protocol version.

## Cut a release

There is no CI pipeline yet; a release is cut by hand.

1. Bump `__version__`, add a `CHANGELOG.md` entry, commit.
2. Run the checks in Docker (see [DEVELOPMENT.md](DEVELOPMENT.md#running-the-tests)).
3. Build the artifacts as below, and `git tag v1.0.1 && git push origin main v1.0.1`.
4. Attach `release/*` (wheel, sdist, offline bundles, `SHA256SUMS`) to the
   GitHub release for the tag, and load or push the image wherever your
   runners pull it from.

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
