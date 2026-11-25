#!/usr/bin/env bash
# Create an isolated environment with every argus backend installed.
#
#   ./scripts/install.sh              # install into ./.venv
#   VENV=/opt/argus ./scripts/install.sh
#   ./scripts/install.sh --no-semgrep # Java engine + SCA only
#
# After installation the scanner is available as `.venv/bin/argus`.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${VENV:-$ROOT/.venv}"
PYTHON="${PYTHON:-python3}"
WITH_SEMGREP=1

for arg in "$@"; do
  case "$arg" in
    --no-semgrep) WITH_SEMGREP=0 ;;
    -h|--help)
      sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

if [ ! -d "$VENV" ]; then
  echo "==> creating virtualenv at $VENV"
  "$PYTHON" -m venv "$VENV"
fi

echo "==> installing argus (editable)"
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null
if [ "$WITH_SEMGREP" -eq 1 ]; then
  "$VENV/bin/python" -m pip install -e "$ROOT[semgrep]"
else
  "$VENV/bin/python" -m pip install -e "$ROOT"
fi

echo
echo "Installed:"
"$VENV/bin/argus" version || true
cat <<'EOF'

Next steps:
  .venv/bin/argus sast  <path>            # static analysis
  .venv/bin/argus sca   <path>            # dependency analysis (needs network)
  .venv/bin/argus db update               # optional: offline OSV archives
  .venv/bin/argus bench owasp --bench-dir /tmp/owasp-benchmark
EOF
