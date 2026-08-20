#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    "Usage: $0 <unsigned-body.json> <approver-envelope.json> <owner-envelope.json> <assembled.json>" \
    "Assembles public POSTGRES_METADATA_CAPTURE_ONLY envelopes." \
    "Pass exactly two envelopes, approver then owner." \
    "Writes a create-only assembled envelope."
}

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  usage
  exit 0
fi
if [[ "$#" -ne 4 ]]; then
  usage >&2
  exit 2
fi

body="$1"
approver_envelope="$2"
owner_envelope="$3"
dest="$4"

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

if path_has_symlink "$body" || path_has_symlink "$approver_envelope" || path_has_symlink "$owner_envelope"; then
  printf 'metadata capture assemble refused: input would be a symlink\n' >&2
  exit 2
fi

if [[ ! -f "$body" ]]; then
  printf 'unsigned body is missing\n' >&2
  exit 2
fi
if [[ ! -f "$approver_envelope" ]]; then
  printf 'approver envelope is missing\n' >&2
  exit 2
fi
if [[ ! -f "$owner_envelope" ]]; then
  printf 'owner envelope is missing\n' >&2
  exit 2
fi

refuse_symlink_output() {
  printf 'metadata capture assemble refused: output would be a symlink\n' >&2
  exit 2
}

if path_has_symlink "$dest" || path_has_symlink "$(dirname "$dest")"; then
  refuse_symlink_output
fi
if [[ -e "$dest" ]]; then
  printf 'metadata capture assemble refused: output already exists\n' >&2
  exit 2
fi

envelope_role() {
  uv run python -c 'import json, sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except (OSError, ValueError, UnicodeError):
    raise SystemExit(2)
if not isinstance(data, dict):
    raise SystemExit(2)
role = data.get("role")
if role not in ("approver", "owner"):
    raise SystemExit(2)
print(role)' "$1"
}

if ! first_role="$(envelope_role "$approver_envelope" 2>/dev/null)"; then
  printf 'metadata capture assemble refused: envelopes must be ordered approver then owner\n' >&2
  exit 2
fi
if ! second_role="$(envelope_role "$owner_envelope" 2>/dev/null)"; then
  printf 'metadata capture assemble refused: envelopes must be ordered approver then owner\n' >&2
  exit 2
fi
if [[ "$first_role" != "approver" || "$second_role" != "owner" ]]; then
  printf 'metadata capture assemble refused: envelopes must be ordered approver then owner\n' >&2
  exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cli="$root/scripts/second_brain_unified_db_snapshot_export.py"
uv run python "$cli" capture-authority-verify \
  --body "$body" \
  --signature "$approver_envelope" \
  --signature "$owner_envelope"
uv run python "$cli" capture-authority-assemble \
  --body "$body" \
  --signature "$approver_envelope" \
  --signature "$owner_envelope" \
  --out "$dest"

printf 'Wrote assembled envelope to %s\n' "$dest"
