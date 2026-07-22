#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG_DIR="${P3_00_LOG_DIR:-.ci/p3-00}"
EVIDENCE_OUT="${P3_00_EVIDENCE_OUT:-artifacts/conformance/phase3/local/evidence.json}"
mkdir -p "$LOG_DIR" "$(dirname "$EVIDENCE_OUT")"

python scripts/verify_phase2_checkpoint.py >"$LOG_DIR/checkpoint.log" 2>&1
cat "$LOG_DIR/checkpoint.log"
python scripts/check_architecture_boundaries.py >"$LOG_DIR/boundaries.log" 2>&1
cat "$LOG_DIR/boundaries.log"
python scripts/scan_secrets.py >"$LOG_DIR/secrets.log" 2>&1
cat "$LOG_DIR/secrets.log"
python -m pytest -W error -q >"$LOG_DIR/pytest.log" 2>&1
cat "$LOG_DIR/pytest.log"
python scripts/package_smoke.py --json >"$LOG_DIR/package.json" 2>&1
cat "$LOG_DIR/package.json"
python scripts/write_p3_00_evidence.py \
  --log-dir "$LOG_DIR" \
  --json-out "$EVIDENCE_OUT"
