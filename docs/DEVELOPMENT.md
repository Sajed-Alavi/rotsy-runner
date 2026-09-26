# Development

## Layout

See [ARCHITECTURE.md](ARCHITECTURE.md#components). Tests are in `tests/`;
`tests/conftest.py` provides `FakeServer`, an in-memory implementation of the
runner agent API driven through httpx's `MockTransport`, and fake Trivy/Grype
releases (shell scripts packaged exactly like the vendor tarballs) that answer
version probes, implement `grype db import/status`, emit canned reports and
record the argv/environment they received.

## Running the tests

In Docker (the supported way):

```bash
docker build --target test -t rotsy-runner-test .
docker run --rm rotsy-runner-test                       # pytest -q
docker run --rm --entrypoint sh rotsy-runner-test -c 'ruff check src tests && ruff format --check src tests'
```

Iterating without rebuilding:

```bash
docker run --init --rm -v "$PWD/src:/opt/rotsy-runner/src:ro" -v "$PWD/tests:/opt/rotsy-runner/tests:ro" \
    rotsy-runner-test pytest -q tests/test_tools.py
```

Or a local virtualenv (Python ≥ 3.12):

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt && pip install --no-deps -e .
pytest -q && ruff check src tests && ruff format --check src tests
```

## Against a real Rotsy

Rotsy's repository has the full end-to-end environment (`e2e/runner/`): it
builds this repository's image from `ROTSY_RUNNER_DIR` (default
`../rotsy-runner`), registers it, lets the server fetch real Trivy/Grype
releases, and scans a real image through the registry proxy — with the runner
on an internal network with no Internet.

For a quick manual loop against a local Rotsy on `http://localhost:8000`:

```bash
export ROTSY_RUNNER_DATA_DIR=$PWD/data ROTSY_RUNNER_ALLOW_INSECURE_HTTP=true
rotsy-runner register --server http://localhost:8000
rotsy-runner run
```

## Conventions

Same as the Rotsy backend: a narrow, defect-focused ruff rule set; formatting
by `ruff format`; single-line commit messages; configuration from the
environment only, failing fast; credentials never on a command line or in a
log; no abstraction ahead of need — one owner per responsibility.
