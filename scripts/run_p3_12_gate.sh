#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
LOG_DIR="${G3_LOG_DIR:-artifacts/conformance/phase3/G3/runs/local/logs}"
EVIDENCE_OUT="${G3_EVIDENCE_OUT:-artifacts/conformance/phase3/G3/runs/local/evidence.json}"
mkdir -p "$LOG_DIR" "$(dirname "$EVIDENCE_OUT")"

python scripts/verify_g3_checkpoint.py
python scripts/p3_12_conformance.py \
  --run-gates \
  --log-dir "$LOG_DIR" \
  --evidence-out "$EVIDENCE_OUT"
