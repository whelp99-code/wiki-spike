#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 3 ]]; then
  printf 'Usage: %s <owner|approver> <private-key.pem> <output-directory>\n' "$0" >&2
  exit 2
fi

role="$1"
signer_input="$2"
output_directory="$3"
case "$role" in
  owner)
    key_id="wiki-spike-local-owner-2026"
    public_key_b64="AqkUcin7vP0DSKNKq77+AoG4dLivjs7gBQC+I2U0znQ="
    ;;
  approver)
    key_id="wiki-spike-local-approver-2026"
    public_key_b64="qqjshbOlaEeE5umj4jBVJPYqOqFypULm4nX9FSxIMNQ="
    ;;
  *)
    printf 'resolver role signing refused: unknown role\n' >&2
    exit 2
    ;;
esac

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
umask 077
mkdir -p "$output_directory"
uv run --directory "$root" python "$root/scripts/sign_second_brain_resolver_role.py" \
  --role "$role" \
  --key-id "$key_id" \
  --expected-public-key-b64 "$public_key_b64" \
  --private-key "$signer_input" \
  --resolver-signing-dir "$root/artifacts/product-release/second-brain-v1/resolver-signing" \
  --output-directory "$output_directory"
