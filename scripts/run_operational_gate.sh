#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -n "${PYTHON_BIN:-}" ]]; then
  PYTHON="$PYTHON_BIN"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON="$ROOT/.venv/bin/python"
elif command -v python3.12 >/dev/null 2>&1; then
  PYTHON="$(command -v python3.12)"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  echo "Python 3.12 is required" >&2
  exit 2
fi

export PYTHONHASHSEED="${PYTHONHASHSEED:-0}"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONPATH="${ROOT}/src:${ROOT}"
export TZ="${TZ:-UTC}"

# Product-direction guards: the UI may enter durable state only through the
# named composition facade, and that facade must use the existing core.
"$PYTHON" scripts/check_operational_boundary.py --json
"$PYTHON" scripts/check_architecture_boundaries.py --json
"$PYTHON" scripts/check_runtime_boundaries.py --json

# User-visible lifecycle plus the existing core slices it directly depends on.
"$PYTHON" -m pytest -W error -q \
  tests/operational \
  tests/test_cli.py \
  tests/compat/mcp_v1/test_compat_factory.py \
  tests/second_brain/test_mac_production_composition.py \
  tests/encrypted_lifecycle/test_gate3_pipeline.py \
  tests/encrypted_lifecycle/test_gate4_pipeline.py \
  tests/encrypted_lifecycle/test_gate5_forget.py \
  tests/encrypted_lifecycle/test_gate7_mcp.py

# One secret scan and one installed-wheel lifecycle. Historical G3/G4/Gate-1..8
# release evidence is verified separately at its immutable release ref.
"$PYTHON" scripts/scan_secrets.py --json
"$PYTHON" scripts/package_smoke.py --json
