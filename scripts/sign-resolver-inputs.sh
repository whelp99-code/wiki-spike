#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
uv run --directory "$root" python "$root/scripts/build_canonical_resolver_inputs.py" --owner-key /Users/jmpark/keys/wiki-spike-local/owner.pem --approver-key /Users/jmpark/keys/wiki-spike-local/approver.pem --root "$root"
