# rotsy-runner image.
#
# Contains the agent only — **no scanner binaries and no vulnerability
# databases**. Those are delivered at runtime by the Rotsy server the runner
# registers with (verified by SHA-256, installed into the data volume), which
# is what lets this image run on a host with no Internet access at all, and
# keeps scanner versions under the server's control instead of the image's.
#
# No Docker socket, no container runtime: scans are static reads of registry
# data through the Rotsy server's job-scoped registry proxy. Nothing is ever
# run as a container.
#
#   docker build -t rotsy-runner .
#   docker run --rm -it -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner \
#       register --server https://rotsy.example.com
#   docker run -d --name rotsy-runner --restart unless-stopped \
#       -v rotsy-runner-data:/var/lib/rotsy-runner rotsy-runner

# Same pinned base as the Rotsy backend: one base-image CVE review covers both.
FROM python:3.13.14-alpine3.23 AS base

# `apk upgrade` picks up base-OS security fixes published after the base image
# was cut. ca-certificates: TLS verification of the Rotsy server. Nothing else —
# no curl, no git, no shell tooling the agent does not use.
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && addgroup -S -g 10001 runner \
    && adduser -S -u 10001 -G runner -h /var/lib/rotsy-runner -s /sbin/nologin runner

WORKDIR /opt/rotsy-runner
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade "pip>=25.0" "setuptools>=78.1.1" wheel \
    && pip install --no-cache-dir --retries 6 --timeout 120 -r requirements.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir --no-deps . \
    && install -d -o runner -g runner -m 0700 /var/lib/rotsy-runner

ENV ROTSY_RUNNER_DATA_DIR=/var/lib/rotsy-runner \
    PYTHONUNBUFFERED=1
USER runner
VOLUME ["/var/lib/rotsy-runner"]
ENTRYPOINT ["rotsy-runner"]
CMD ["run"]

# ---------------------------------------------------------------------------
# Test image: pytest + ruff on top of the runtime image. Not what ships.
#   docker build --target test -t rotsy-runner-test . && docker run --rm rotsy-runner-test
# ---------------------------------------------------------------------------
FROM base AS test
USER root
COPY requirements-dev.txt .
RUN pip install --no-cache-dir --retries 6 --timeout 120 -r requirements-dev.txt
COPY ruff.toml pytest.ini ./
COPY tests ./tests
RUN chown -R runner:runner /opt/rotsy-runner
USER runner
ENV HOME=/tmp
ENTRYPOINT []
CMD ["pytest", "-q"]
