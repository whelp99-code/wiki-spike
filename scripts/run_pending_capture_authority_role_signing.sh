#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    "Usage: $0 <owner|approver> <private-key.pem> <output-directory>" \
    "Signs the pending POSTGRES_METADATA_CAPTURE_ONLY authorization body." \
    "Run approver first, then owner. Never share the private-key path or file." \
    "Agent never receives keys. Writes only public envelope JSON."
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
    binding_id="wiki-owner-2026"
    binding_b64="K0zr+45z5JHxAKdqodvDeZSB36B7L8OooR+g9W+vo20="
    ;;
  approver)
    binding_id="wiki-approver-2026"
    binding_b64="o3MsXdJIhRnHggMzCd1RGSVDJMqtb5abxWgKlElxc+g="
    ;;
  *)
    printf 'metadata capture signing refused: unknown role\n' >&2
    exit 2
    ;;
esac

path_has_symlink() {
  local current="$1"
  while [[ -n "$current" && "$current" != "/" && "$current" != "." ]]; do
    if [[ -L "$current" ]]; then
      return 0
    fi
    current="$(dirname "$current")"
  done
  return 1
}

refuse_symlink_output() {
  printf 'metadata capture signing refused: output would be a symlink\n' >&2
  exit 2
}

output="$output_directory/POSTGRES_METADATA_CAPTURE_ONLY.$role-envelope.json"
if path_has_symlink "$output" || path_has_symlink "$output_directory"; then
  refuse_symlink_output
fi
if [[ -e "$output_directory" ]]; then
  if [[ ! -d "$output_directory" ]]; then
    printf 'metadata capture signing refused: output directory is invalid\n' >&2
    exit 2
  fi
else
  if path_has_symlink "$(dirname "$output_directory")"; then
    refuse_symlink_output
  fi
  umask 077
  mkdir -p "$output_directory"
  if path_has_symlink "$output_directory"; then
    refuse_symlink_output
  fi
fi
if path_has_symlink "$output"; then
  refuse_symlink_output
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
body="$root/artifacts/product-release/second-brain-v1/capture-authority-signing/POSTGRES_METADATA_CAPTURE_ONLY.body.json"
if [[ ! -f "$body" ]]; then
  printf 'unsigned body is missing\n' >&2
  exit 2
fi
umask 077
uv run python "$root/scripts/sign_second_brain_capture_authority_role.py" \
  --role "$role" \
  --key-id "$binding_id" \
  --expected-public-key-b64 "$binding_b64" \
  --body "$body" \
  --private-key "$signer_input" \
  --output "$output"

printf 'Wrote one %s envelope to %s\n' "$role" "$output_directory"
