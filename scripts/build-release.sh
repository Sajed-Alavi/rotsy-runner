#!/bin/sh
# Build a rotsy-runner release: wheel + sdist + an offline install bundle + SHA256SUMS.
#
#   scripts/build-release.sh
#   BUNDLE_PYTHON=3.12 PLATFORM=manylinux2014_aarch64 scripts/build-release.sh
#
# Output in release/:
#   rotsy_runner-<v>-py3-none-any.whl
#   rotsy_runner-<v>.tar.gz
#   rotsy-runner-<v>-bundle-py<PY>-<PLATFORM>.tar.gz  wheel + dependency wheels + systemd unit + install.sh
#   SHA256SUMS
#
# The bundle is what packaging/install.sh consumes on a host with no Internet
# access. Dependency wheels are platform-specific (pydantic-core is compiled),
# so build one bundle per target Python version / architecture.
set -eu

cd "$(dirname "$0")/.."
VERSION=$(sed -n 's/^__version__ = "\(.*\)"$/\1/p' src/rotsy_runner/__init__.py)
[ -n "$VERSION" ] || { echo "cannot read the version" >&2; exit 1; }
PY=${BUNDLE_PYTHON:-3.13}
PLATFORM=${PLATFORM:-manylinux2014_x86_64}
OUT=release

rm -rf "$OUT" build dist
mkdir -p "$OUT"

echo "==> building rotsy-runner $VERSION"
python3 -m build --outdir "$OUT" .

echo "==> assembling the offline bundle (python $PY, $PLATFORM)"
BUNDLE_DIR="$OUT/rotsy-runner-$VERSION"
mkdir -p "$BUNDLE_DIR/wheelhouse"
cp "$OUT/rotsy_runner-$VERSION-py3-none-any.whl" "$BUNDLE_DIR/wheelhouse/"
python3 -m pip download --quiet --only-binary=:all: --python-version "$PY" --platform "$PLATFORM" \
    --dest "$BUNDLE_DIR/wheelhouse" -r requirements.txt
cp packaging/systemd/rotsy-runner.service packaging/install.sh README.md LICENSE "$BUNDLE_DIR/"
BUNDLE="rotsy-runner-$VERSION-bundle-py$PY-$PLATFORM.tar.gz"
tar -C "$OUT" -czf "$OUT/$BUNDLE" "rotsy-runner-$VERSION"
rm -rf "$BUNDLE_DIR"

echo "==> checksums"
(cd "$OUT" && sha256sum -- *.whl *.tar.gz > SHA256SUMS && cat SHA256SUMS)
