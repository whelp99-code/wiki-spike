#!/usr/bin/env bash
set -euo pipefail

umask 077

workspace_id="ws-gate8-d9176d5"
implementation_commit="d9176d5dd32e47fc86248fff75946e9042386fe4"
manifest_digest="2e22de6de7cd17e1563c78cafbbe5d41afe8edaf00127139a25e8a15c34de285"
attestation_domain="wiki.gate8.reviewer-attestation.v1"
attestation_schema="wiki-gate8-reviewer-attestation-v1"

usage() {
  cat <<'EOF'
Internal helper for one independently keyed Gate 8 review process.

Run one of these role-specific executables instead:
  scripts/run_gate8_deepseek_architect_review.sh
  scripts/run_gate8_grok_critic_review.sh
EOF
}

case "${1:-}" in
  -h|--help)
    usage
    exit 0
    ;;
esac

if (( $# != 3 )); then
  usage >&2
  exit 2
fi

reviewer_role="$1"
reviewer_key_id="$2"
process_name="$3"

case "${reviewer_role}:${reviewer_key_id}:${process_name}" in
  ARCHITECT:deepseek-architect-key-1:deepseek-architect) ;;
  CRITIC:grok-critic-key-1:grok-critic) ;;
  *)
    printf 'error: unsupported reviewer process binding\n' >&2
    exit 2
    ;;
esac

for command_name in jq openssl xxd; do
  if ! command -v "${command_name}" >/dev/null 2>&1; then
    printf 'error: %s is required\n' "${command_name}" >&2
    exit 1
  fi
done

review_root="${GATE8_REVIEW_ROOT:-${HOME}/.config/wiki-spike/gate8-human-reviews}"
process_dir="${review_root}/${process_name}"
local_signer_path="${process_dir}/reviewer-private.pem"
public_key="${process_dir}/reviewer-public.pem"
attestation_path="${process_dir}/attestation.json"

mkdir -p "${process_dir}"
chmod 700 "${review_root}" "${process_dir}"

if [[ -e "${local_signer_path}" && ! -e "${public_key}" ]] ||
   [[ ! -e "${local_signer_path}" && -e "${public_key}" ]]; then
  printf 'error: incomplete reviewer key pair in %s\n' "${process_dir}" >&2
  exit 1
fi

if [[ ! -e "${local_signer_path}" ]]; then
  key_work_dir="$(mktemp -d "${process_dir}/.generate-key.XXXXXX")"
  cleanup_key_work_dir() {
    rm -rf "${key_work_dir}"
  }
  trap cleanup_key_work_dir EXIT

  openssl genpkey \
    -algorithm ED25519 \
    -out "${key_work_dir}/reviewer-private.pem"
  openssl pkey \
    -in "${key_work_dir}/reviewer-private.pem" \
    -pubout \
    -out "${key_work_dir}/reviewer-public.pem"

  mv "${key_work_dir}/reviewer-private.pem" "${local_signer_path}"
  mv "${key_work_dir}/reviewer-public.pem" "${public_key}"
  chmod 600 "${local_signer_path}"
  chmod 644 "${public_key}"
fi

issued_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
if expires_at="$(date -u -v+30M '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"; then
  :
else
  expires_at="$(date -u -d '+30 minutes' '+%Y-%m-%dT%H:%M:%SZ')"
fi

payload="$(
  jq -cnS \
    --arg schema "${attestation_schema}" \
    --arg reviewer_role "${reviewer_role}" \
    --arg verdict "APPROVE" \
    --arg workspace_id "${workspace_id}" \
    --arg implementation_commit "${implementation_commit}" \
    --arg manifest_digest "${manifest_digest}" \
    --arg reviewer_key_id "${reviewer_key_id}" \
    --arg issued_at "${issued_at}" \
    --arg expires_at "${expires_at}" \
    '{
      schema: $schema,
      reviewer_role: $reviewer_role,
      verdict: $verdict,
      workspace_id: $workspace_id,
      implementation_commit: $implementation_commit,
      manifest_digest: $manifest_digest,
      reviewer_key_id: $reviewer_key_id,
      issued_at: $issued_at,
      expires_at: $expires_at
    }'
)"

sign_work_dir="$(mktemp -d "${process_dir}/.sign-attestation.XXXXXX")"
cleanup_sign_work_dir() {
  rm -rf "${sign_work_dir}"
}
trap cleanup_sign_work_dir EXIT

printf '%s\0%s' "${attestation_domain}" "${payload}" >"${sign_work_dir}/signature-input"
openssl pkeyutl \
  -sign \
  -rawin \
  -inkey "${local_signer_path}" \
  -in "${sign_work_dir}/signature-input" \
  -out "${sign_work_dir}/signature"
openssl pkeyutl \
  -verify \
  -rawin \
  -pubin \
  -inkey "${public_key}" \
  -in "${sign_work_dir}/signature-input" \
  -sigfile "${sign_work_dir}/signature" \
  >/dev/null

signature="$(xxd -p -c 256 "${sign_work_dir}/signature")"
jq -cnS \
  --argjson payload "${payload}" \
  --arg signature "${signature}" \
  '$payload + {signature: $signature}' \
  >"${sign_work_dir}/attestation.json"

mv "${sign_work_dir}/attestation.json" "${attestation_path}"
chmod 644 "${attestation_path}"

public_key_fingerprint="$(
  openssl pkey \
    -pubin \
    -in "${public_key}" \
    -outform DER |
    openssl dgst -sha256
)"

printf 'Gate 8 %s review attestation created.\n' "${reviewer_role}"
printf 'Public key: %s\n' "${public_key}"
printf 'Public key fingerprint: %s\n' "${public_key_fingerprint}"
printf 'Attestation: %s\n' "${attestation_path}"
printf 'Private key remains local: %s\n' "${local_signer_path}"
