#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
python scripts/verify_g4_checkpoint.py --require-git
python scripts/check_runtime_boundaries.py
python scripts/check_architecture_boundaries.py
python scripts/scan_secrets.py
python -m pytest -W error -q
python scripts/package_smoke.py --json
python -m compileall -q src tests scripts
