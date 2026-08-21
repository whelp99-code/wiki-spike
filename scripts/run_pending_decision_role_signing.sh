#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    "Usage: $0 <owner|approver> <private-key.pem> <output-directory>" \
    "Signs only the currently evidence-backed pending decision bodies." \
    "Run once per role. Never share the private-key path or file."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "$#" -ne 3 ]]; then
  usage >&2
  exit 2
fi

role="$1"
signer_input="$2"
output_directory="$3"
case "$role" in
  owner)
    binding_id="wiki-spike-local-owner-2026"
    binding_b64="AqkUcin7vP0DSKNKq77+AoG4dLivjs7gBQC+I2U0znQ="
    ;;
  approver)
    binding_id="wiki-spike-local-approver-2026"
    binding_b64="qqjshbOlaEeE5umj4jBVJPYqOqFypULm4nX9FSxIMNQ="
    ;;
  *)
    printf 'pending decision signing refused: unknown role\n' >&2
    exit 2
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
bodies=(
  "DB-01"
  "DB-02-claude-memory-bank"
  "DB-02-codex"
  "DB-02-git"
  "DB-02-markdown"
  "DB-03-legacy-mem0-rag"
  "DB-03-me-wiki"
  "DB-03-unified-db"
  "DB-07"
)

umask 077
mkdir -p "$output_directory"
for stem in "${bodies[@]}"; do
  body="$root/artifacts/product-release/second-brain-v1/decision-signing/$stem.body.json"
  output="$output_directory/$stem.$role-envelope.json"
  uv run --directory "$root" python "$root/scripts/sign_second_brain_decision_role.py" \
    --role "$role" \
    --key-id "$binding_id" \
    --expected-public-key-b64 "$binding_b64" \
    --body "$body" \
    --private-key "$signer_input" \
    --output "$output"
done

printf 'Wrote %s %s envelopes to %s\n' "${#bodies[@]}" "$role" "$output_directory"
