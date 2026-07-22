#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG_DIR="${P4_00_LOG_DIR:-.ci/p4-00}"
EVIDENCE_OUT="${P4_00_EVIDENCE_OUT:-artifacts/conformance/phase4/local/evidence.json}"
mkdir -p "$LOG_DIR" "$(dirname "$EVIDENCE_OUT")"

python scripts/verify_phase3_contract_pin.py --json >"$LOG_DIR/phase3-pin.json" 2>&1
cat "$LOG_DIR/phase3-pin.json"
python scripts/check_runtime_boundaries.py --json >"$LOG_DIR/runtime-boundaries.json" 2>&1
cat "$LOG_DIR/runtime-boundaries.json"
python scripts/check_architecture_boundaries.py --json >"$LOG_DIR/architecture-boundaries.json" 2>&1
cat "$LOG_DIR/architecture-boundaries.json"
python scripts/scan_secrets.py --json >"$LOG_DIR/secrets.json" 2>&1
cat "$LOG_DIR/secrets.json"
python -m pytest -W error -q tests/phase4 >"$LOG_DIR/targeted-tests.log" 2>&1
cat "$LOG_DIR/targeted-tests.log"
python -m pytest -W error -q >"$LOG_DIR/regression.log" 2>&1
cat "$LOG_DIR/regression.log"
python scripts/package_smoke.py --json >"$LOG_DIR/package.json" 2>&1
cat "$LOG_DIR/package.json"
python scripts/write_p4_00_evidence.py \
  --log-dir "$LOG_DIR" \
  --json-out "$EVIDENCE_OUT"
