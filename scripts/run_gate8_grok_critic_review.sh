#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if (( $# != 0 )); then
  "${script_dir}/run_gate8_review_process.sh" "$@"
  exit $?
fi

exec "${script_dir}/run_gate8_review_process.sh" \
  CRITIC \
  grok-critic-key-1 \
  grok-critic
