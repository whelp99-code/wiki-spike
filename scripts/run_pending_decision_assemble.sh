#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    "Usage: $0 <approver-envelope-directory> <owner-envelope-directory> <assembled-directory>" \
    "Assembles the six pending public decision envelopes, approver then owner." \
    "Writes create-only assembled records. Never reads private keys."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "$#" -ne 3 ]]; then
  usage >&2
  exit 2
fi

approver_dir="$1"
owner_dir="$2"
out_dir="$3"

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

if path_has_symlink "$approver_dir" || path_has_symlink "$owner_dir" || path_has_symlink "$out_dir"; then
  printf 'pending decision assemble refused: path would be a symlink\n' >&2
  exit 2
fi
if [[ ! -d "$approver_dir" ]]; then
  printf 'approver envelope directory is missing\n' >&2
  exit 2
fi
if [[ ! -d "$owner_dir" ]]; then
  printf 'owner envelope directory is missing\n' >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
for stem in "${stems[@]}"; do
  body="$root/artifacts/product-release/second-brain-v1/decision-signing/$stem.body.json"
  approver="$approver_dir/$stem.approver-envelope.json"
  owner="$owner_dir/$stem.owner-envelope.json"
  if path_has_symlink "$body" || path_has_symlink "$approver" || path_has_symlink "$owner"; then
    printf 'pending decision assemble refused: input would be a symlink\n' >&2
    exit 2
  fi
  if [[ ! -f "$body" ]]; then
    printf 'unsigned body is missing\n' >&2
    exit 2
  fi
  if [[ ! -f "$approver" ]]; then
    printf 'approver envelope is missing\n' >&2
    exit 2
  fi
  if [[ ! -f "$owner" ]]; then
    printf 'owner envelope is missing\n' >&2
    exit 2
  fi
done

if [[ -e "$out_dir" ]]; then
  if [[ ! -d "$out_dir" ]]; then
    printf 'pending decision assemble refused: output directory is invalid\n' >&2
    exit 2
  fi
  if [[ -n "$(ls -A "$out_dir")" ]]; then
    printf 'pending decision assemble refused: output already exists\n' >&2
    exit 2
  fi
else
  umask 077
  mkdir -p "$out_dir"
fi

for stem in "${stems[@]}"; do
  body="$root/artifacts/product-release/second-brain-v1/decision-signing/$stem.body.json"
  dest="$out_dir/$stem.json"
  if [[ -e "$dest" ]]; then
    printf 'pending decision assemble refused: output already exists\n' >&2
    exit 2
  fi
  uv run python "$root/scripts/second_brain_decision.py" assemble \
    --body "$body" \
    --signature "$approver_dir/$stem.approver-envelope.json" \
    --signature "$owner_dir/$stem.owner-envelope.json" \
    --out "$dest"
done

printf 'Wrote six assembled records to %s\n' "$out_dir"
