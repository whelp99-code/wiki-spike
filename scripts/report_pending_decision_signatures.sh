#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    "Usage: $0 [public-envelope-directory]" \
    "Reports pending decision bodies and missing public envelopes." \
    "Never reads private keys. Public envelopes only."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "$#" -gt 1 ]]; then
  usage >&2
  exit 2
fi

stems=(
  "DB-02-claude-memory-bank"
  "DB-02-codex"
  "DB-02-git"
  "DB-02-markdown"
  "DB-03-legacy-mem0-rag"
  "DB-07"
)

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

envelope_dir=""
if [[ "$#" -eq 1 ]]; then
  envelope_dir="$1"
  if path_has_symlink "$envelope_dir"; then
    printf 'pending decision report refused: envelope directory would be a symlink\n' >&2
    exit 2
  fi
  if [[ ! -d "$envelope_dir" ]]; then
    printf 'pending decision report refused: envelope directory is missing\n' >&2
    exit 2
  fi
fi

printf 'signable:\n'
for stem in "${stems[@]}"; do
  if [[ -z "$envelope_dir" ]]; then
    printf '%s: unsigned\n' "$stem"
    continue
  fi
  owner="$envelope_dir/$stem.owner-envelope.json"
  approver="$envelope_dir/$stem.approver-envelope.json"
  if path_has_symlink "$owner" || path_has_symlink "$approver"; then
    printf 'pending decision report refused: envelope would be a symlink\n' >&2
    exit 2
  fi
  if [[ -f "$owner" ]]; then
    printf '%s: owner envelope present\n' "$stem"
  else
    printf '%s: owner envelope missing\n' "$stem"
  fi
  if [[ -f "$approver" ]]; then
    printf '%s: approver envelope present\n' "$stem"
  else
    printf '%s: approver envelope missing\n' "$stem"
  fi
done

printf 'blocked UNRESOLVED:\n'
printf 'DB-01 global\n'
printf 'DB-05 global\n'
printf 'DB-03 me-wiki\n'
printf 'DB-03 unified-db\n'
