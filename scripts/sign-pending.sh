#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
owner_out="/Users/jmpark/second-brain-decision-envelopes/owner"
approver_out="/Users/jmpark/second-brain-decision-envelopes/approver"
resolver_owner_out="/Users/jmpark/second-brain-resolver-envelopes/owner"
resolver_approver_out="/Users/jmpark/second-brain-resolver-envelopes/approver"
wall_signature_out="$root/artifacts/product-release/second-brain-v1/authority-wall-signatures"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  printf '%s\n' "Usage: $0 <owner-private-key.pem> <approver-private-key.pem>"
  exit 0
fi
if [[ "$#" -ne 2 ]]; then
  printf 'Usage: %s <owner-private-key.pem> <approver-private-key.pem>\n' "$0" >&2
  exit 2
fi

uv run --directory "$root" python "$root/scripts/build_canonical_resolver_inputs.py" \
  prepare --root "$root"
"$root/scripts/run_pending_decision_role_signing.sh" owner "$1" "$owner_out"
"$root/scripts/run_pending_decision_role_signing.sh" approver "$2" "$approver_out"
"$root/scripts/run_pending_resolver_role_signing.sh" \
  owner "$1" "$resolver_owner_out"
"$root/scripts/run_pending_resolver_role_signing.sh" \
  approver "$2" "$resolver_approver_out"
uv run --directory "$root" python "$root/scripts/build_canonical_resolver_inputs.py" \
  assemble \
  --root "$root" \
  --owner-envelope-dir "$resolver_owner_out" \
  --approver-envelope-dir "$resolver_approver_out"
mkdir -p "$wall_signature_out"
chmod u+w "$wall_signature_out"/*.json 2>/dev/null || true
cp "$owner_out/DB-01.owner-envelope.json" "$wall_signature_out/"
cp "$approver_out/DB-01.approver-envelope.json" "$wall_signature_out/"
cp "$owner_out/DB-03-me-wiki.owner-envelope.json" "$wall_signature_out/"
cp "$approver_out/DB-03-me-wiki.approver-envelope.json" "$wall_signature_out/"
chmod 0444 "$wall_signature_out"/*.json
uv run --directory "$root" python "$root/scripts/build_second_brain_authority_wall.py" \
  --root "$root"
