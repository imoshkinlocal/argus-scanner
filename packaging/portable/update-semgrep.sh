#!/bin/sh
# Update the Semgrep used by this portable argus bundle.
#
#   ./update-semgrep.sh                 # latest release from PyPI
#   ./update-semgrep.sh 1.90.0          # exact version
#   ./update-semgrep.sh --wheelhouse DIR [VERSION]
#   ./update-semgrep.sh --list
#   ./update-semgrep.sh --remove        # back to the bundled Semgrep
#
# The update goes into ./semgrep-overlay and never touches the bundled
# runtime, so argus keeps working if a new Semgrep turns out to be broken.
set -e

unset PYTHONPATH PYTHONHOME

SELF=$0
while [ -L "$SELF" ]; do
    LINK=$(readlink "$SELF")
    case $LINK in
        /*) SELF=$LINK ;;
        *) SELF=$(dirname "$SELF")/$LINK ;;
    esac
done
ROOT=$(CDPATH= cd -- "$(dirname -- "$SELF")" && pwd)
PY="$ROOT/python/bin/python3.11"
DEST="$ROOT/semgrep-overlay"
RUNTIME="$ROOT/runtime"
VERSION=""
WHEELHOUSE=""
ACTION="install"

# pip needs a trust anchor on minimal systems without ca-certificates.
CERT="$RUNTIME/certifi/cacert.pem"
if [ -r "$CERT" ] && [ -z "${SSL_CERT_FILE:-}" ]; then
    SSL_CERT_FILE="$CERT"
    export SSL_CERT_FILE
fi

usage() {
    sed -n '2,10p' "$0" | sed 's/^# \{0,1\}//'
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --remove) ACTION="remove" ;;
        --list) ACTION="list" ;;
        --wheelhouse)
            shift
            [ $# -gt 0 ] || { echo "error: --wheelhouse needs a directory" >&2; exit 2; }
            WHEELHOUSE="$1"
            ;;
        -h|--help) usage ;;
        -*)
            echo "error: unknown option: $1" >&2
            exit 2
            ;;
        *)
            [ -z "$VERSION" ] || { echo "error: more than one version given" >&2; exit 2; }
            VERSION="$1"
            ;;
    esac
    shift
done

semgrep_version() {
    PATH="$ROOT/python/bin:$1/bin:$PATH" PYTHONPATH="$1" \
        "$1/bin/semgrep" --version 2>/dev/null | tail -n 1
}

case "$ACTION" in
    list)
        echo "bundled: $(semgrep_version "$RUNTIME" || echo unknown)"
        if [ -x "$DEST/bin/semgrep" ]; then
            echo "overlay: $(semgrep_version "$DEST" || echo unknown)"
        else
            echo "overlay: not installed"
        fi
        exit 0
        ;;
    remove)
        rm -rf "$DEST"
        echo "removed the Semgrep overlay; the bundled version is active again"
        exit 0
        ;;
esac

TMP="$ROOT/.semgrep-overlay.new"
rm -rf "$TMP"
SPEC="semgrep${VERSION:+==$VERSION}"

echo "==> installing $SPEC into $TMP"
if [ -n "$WHEELHOUSE" ]; then
    "$PY" -m pip install --no-index --find-links "$WHEELHOUSE" \
        --target "$TMP" "$SPEC"
else
    "$PY" -m pip install --upgrade --target "$TMP" "$SPEC"
fi

# pip writes the absolute path of the build interpreter; make the overlay
# independent of where the archive is unpacked.
for script in "$TMP"/bin/*; do
    [ -f "$script" ] || continue
    sed -i '1s|^#!.*python[0-9.]*$|#!/usr/bin/env python3|' "$script"
done

if ! semgrep_version "$TMP" >/dev/null 2>&1; then
    echo "error: the new Semgrep does not run; keeping the current one" >&2
    rm -rf "$TMP"
    exit 1
fi

rm -rf "$DEST"
mv "$TMP" "$DEST"
echo "Semgrep updated: $(semgrep_version "$DEST")"
echo "argus will use it automatically; run '$0 --remove' to roll back."
