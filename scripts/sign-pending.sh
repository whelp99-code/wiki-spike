#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
owner_out="/Users/jmpark/second-brain-decision-envelopes/owner"
approver_out="/Users/jmpark/second-brain-decision-envelopes/approver"

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  printf '%s\n' "Usage: $0 <owner-private-key.pem> <approver-private-key.pem>"
  exit 0
fi
if [[ "$#" -ne 2 ]]; then
  printf 'Usage: %s <owner-private-key.pem> <approver-private-key.pem>\n' "$0" >&2
  exit 2
fi

"$root/scripts/run_pending_decision_role_signing.sh" owner "$1" "$owner_out"
"$root/scripts/run_pending_decision_role_signing.sh" approver "$2" "$approver_out"
