#!/bin/sh
# Install rotsy-runner on a Linux host from a release bundle — no Internet needed.
#
#   sudo ./install.sh rotsy-runner-1.0.0-bundle-py3.13-manylinux2014_x86_64.tar.gz SHA256SUMS
#
# The bundle (scripts/build-release.sh) contains the rotsy-runner wheel, the
# wheels of its dependencies and the systemd unit. This script:
#   1. verifies the bundle against SHA256SUMS and refuses to continue otherwise
#      (this is not a curl | sh installer: you download both files, you can
#      inspect both, and nothing runs unverified);
#   2. creates the `rotsy-runner` system user and /var/lib/rotsy-runner (0700);
#   3. installs into a virtualenv at /opt/rotsy-runner with --no-index, so pip
#      never reaches out to PyPI;
#   4. installs the systemd unit (not started — register first).
#
# Requires: python3 >= 3.12 with venv, sha256sum, tar, systemd.
set -eu

BUNDLE=${1:-}
SUMS=${2:-}
PREFIX=${ROTSY_RUNNER_PREFIX:-/opt/rotsy-runner}
DATA=${ROTSY_RUNNER_DATA_DIR:-/var/lib/rotsy-runner}

die() { echo "install.sh: $*" >&2; exit 1; }

[ -n "$BUNDLE" ] && [ -n "$SUMS" ] || die "usage: $0 <bundle.tar.gz> <SHA256SUMS>"
[ "$(id -u)" -eq 0 ] || die "run as root (it creates a system user and a systemd unit)"
[ -f "$BUNDLE" ] || die "no such file: $BUNDLE"
[ -f "$SUMS" ] || die "no such file: $SUMS"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || die "python3 >= 3.12 is required"

name=$(basename "$BUNDLE")
echo "==> verifying $name against $(basename "$SUMS")"
expected=$(awk -v f="$name" '$2 == f {print $1}' "$SUMS")
[ -n "$expected" ] || die "$name is not listed in $SUMS"
actual=$(sha256sum "$BUNDLE" | awk '{print $1}')
[ "$expected" = "$actual" ] || die "checksum mismatch: expected $expected, got $actual — refusing to install"
echo "    ok ($actual)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -xzf "$BUNDLE" -C "$work"
wheelhouse=$(find "$work" -type d -name wheelhouse | head -n 1)
[ -n "$wheelhouse" ] || die "the bundle has no wheelhouse/ directory"

echo "==> creating the rotsy-runner user and $DATA"
if ! id rotsy-runner >/dev/null 2>&1; then
    useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin --user-group rotsy-runner
fi
install -d -o rotsy-runner -g rotsy-runner -m 0700 "$DATA"
install -d -m 0755 /etc/rotsy-runner

echo "==> installing into $PREFIX (offline: --no-index)"
python3 -m venv "$PREFIX"
"$PREFIX/bin/pip" install --no-index --find-links "$wheelhouse" --quiet rotsy-runner
"$PREFIX/bin/rotsy-runner" version

echo "==> installing the systemd unit"
unit_src=$(find "$work" -name rotsy-runner.service | head -n 1)
[ -n "$unit_src" ] || die "the bundle has no rotsy-runner.service"
install -m 0644 "$unit_src" /etc/systemd/system/rotsy-runner.service
systemctl daemon-reload

cat <<MSG

rotsy-runner is installed. Next:

  1. In Rotsy: Runners -> Create runner. Keep the one-time token at hand.
  2. Register (prompts for the token, so it stays out of shell history):
       sudo -u rotsy-runner $PREFIX/bin/rotsy-runner register --server https://rotsy.example.com
  3. Start it:
       sudo systemctl enable --now rotsy-runner
       journalctl -u rotsy-runner -f

Optional settings go in /etc/rotsy-runner/env (see docs/CONFIGURATION.md).
MSG
