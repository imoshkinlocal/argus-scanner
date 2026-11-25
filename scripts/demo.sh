#!/bin/sh
# End-to-end demonstration: scan examples/vulnerable, expect two findings.
#
#   ./scripts/demo.sh
#   ARGUS=/path/to/argus ./scripts/demo.sh   # e.g. the portable archive
set -e

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -n "${ARGUS:-}" ]; then
    :
elif [ -x "$ROOT/.venv/bin/argus" ]; then
    ARGUS="$ROOT/.venv/bin/argus"
elif command -v argus >/dev/null 2>&1; then
    ARGUS=$(command -v argus)
else
    echo "error: argus is not installed; run ./scripts/install.sh or set ARGUS" >&2
    exit 2
fi

cd "$ROOT"

echo "== version =="
"$ARGUS" version
echo
echo "== scan examples/vulnerable =="
set +e
"$ARGUS" scan examples/vulnerable --no-sca -q -f text
status=$?
set -e
echo

if [ "$status" -ne 1 ]; then
    echo "FAIL: expected exit code 1 (findings), got $status" >&2
    exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
"$ARGUS" scan examples/vulnerable --no-sca -q -f json -o "$tmp/report.json" >/dev/null 2>&1 || true

for rule in java-sqli-jdbc python-command-injection; do
    if ! grep -q "\"$rule\"" "$tmp/report.json"; then
        echo "FAIL: $rule is missing from the report" >&2
        exit 1
    fi
done

echo "OK: both known vulnerabilities were reported (exit code 1)."
