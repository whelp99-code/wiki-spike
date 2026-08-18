"""Builders for LIVE_EXPORT_ONLY authorization tests."""
from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.applications.unified_db_export_authorization_verify import (
    ExpectedExportAuthorizationDigestsV1,
    ExportAuthorizationVerifyRequestV1,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_export_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
)
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    InMemoryExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_SIGNATURE_VERSION,
    export_only_authorization_signing_bytes,
)

SCRIPT = Path("scripts/second_brain_unified_db_snapshot_export.py")
AUTHORIZATION_PY = (
    Path("src/wiki_spike/memory_core/unified_db_export_authorization.py"),
    Path("src/wiki_spike/memory_core/unified_db_export_authorization_sign.py"),
    Path("src/wiki_spike/memory_core/unified_db_export_authorization_nonce.py"),
    Path("src/wiki_spike/applications/unified_db_export_authorization_types.py"),
    Path("src/wiki_spike/applications/unified_db_export_authorization_checks.py"),
    Path("src/wiki_spike/applications/unified_db_export_authorization_verify.py"),
    Path("src/wiki_spike/applications/unified_db_export_authorization_cli.py"),
    Path("src/wiki_spike/applications/unified_db_export_authorization_publish.py"),
    Path("src/wiki_spike/infrastructure/export_authorization_nonce_store.py"),
    Path("src/wiki_spike/infrastructure/export_authorization_nonce_fs.py"),
    Path("src/wiki_spike/infrastructure/export_authorization_nonce_schema.py"),
    Path("src/wiki_spike/infrastructure/export_authorization_nonce_backup.py"),
    Path("src/wiki_spike/infrastructure/export_authorization_nonce_decode.py"),
    Path("src/wiki_spike/composition/unified_db_live_export.py"),
)
EXPORT_PY = (
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_bind.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_profile.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_ports.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_proof.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_evidence.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_json.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_cursors.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_fixture.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_manifest.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_bounds.py"),
    Path("src/wiki_spike/memory_core/unified_db_snapshot_export_result.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_service.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_reader.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_handoff.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_io.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_tree.py"),
    Path("src/wiki_spike/applications/unified_db_snapshot_export_verify.py"),
    Path("src/wiki_spike/infrastructure/local_snapshot_package_writer.py"),
    SCRIPT,
) + AUTHORIZATION_PY
SCHEMA = Path("schemas/second-brain/unified-db-export-only-authorization-v1.schema.json")
CONFORMANCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-export-only-authorization-conformance-v1.schema.json"
)
EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/unified-db-export-only-authorization-conformance-v1.json"
)
ISSUED = "2026-08-18T12:00:00Z"
EXPIRES = "2026-08-18T12:15:00Z"
NOW = datetime(2026, 8, 18, 12, 5, tzinfo=UTC)
PROFILE_DIGEST = "11" * 32
PLAN_DIGEST = "22" * 32
MAPPING_DIGEST = "33" * 32
ADAPTER_DIGEST = "44" * 32
INVENTORY_DIGEST = "55" * 32
DESTINATION_DIGEST = "66" * 32


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64encode(raw).decode("ascii")


def authorization_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "authorization_version": AUTHORIZATION_VERSION,
        "authorization_kind": AUTHORIZATION_KIND,
        "authorization_id": "export-auth-001",
        "nonce": "ab" * 32,
        "source_name": "unified-db",
        "operation": "EXPORT_ONLY",
        "profile_digest": PROFILE_DIGEST,
        "plan_digest": PLAN_DIGEST,
        "mapping_digest": MAPPING_DIGEST,
        "adapter_digest": ADAPTER_DIGEST,
        "inventory_digest": INVENTORY_DIGEST,
        "destination_digest": DESTINATION_DIGEST,
        "quiesce_approved": True,
        "max_exports": "1",
        "source_body_read_allowed_for_export": True,
        "mutation_allowed": False,
        "import_allowed": False,
        "register_allowed": False,
        "cohort_allowed": False,
        "serve_allowed": False,
        "promote_allowed": False,
        "cutover_allowed": False,
        "issued_at": ISSUED,
        "not_before": ISSUED,
        "expires_at": EXPIRES,
    }
    body.update(overrides)
    if "authorization_digest" not in overrides:
        unsigned = {key: value for key, value in body.items() if key != "authorization_digest"}
        body["authorization_digest"] = canonical_ledger_digest(
            "unified-db-export-only-authorization-v1",
            unsigned,
        )
    return body


def sign_body(
    body: dict[str, JsonValue],
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> tuple[Ed25519SignatureEnvelopeV1, Ed25519SignatureEnvelopeV1]:
    payload = export_only_authorization_signing_bytes(body)
    approver_env = Ed25519SignatureEnvelopeV1.from_mapping(
        {
            "signature_version": EXPORT_ONLY_SIGNATURE_VERSION,
            "role": "approver",
            "key_id": "security-approver",
            "public_key_b64": public_b64(approver),
            "signature_b64": b64encode(approver.sign(payload)).decode("ascii"),
        },
        version=EXPORT_ONLY_SIGNATURE_VERSION,
    )
    owner_env = Ed25519SignatureEnvelopeV1.from_mapping(
        {
            "signature_version": EXPORT_ONLY_SIGNATURE_VERSION,
            "role": "owner",
            "key_id": "owner",
            "public_key_b64": public_b64(owner),
            "signature_b64": b64encode(owner.sign(payload)).decode("ascii"),
        },
        version=EXPORT_ONLY_SIGNATURE_VERSION,
    )
    return approver_env, owner_env


def trusted_pair(
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> TrustedAuthorityBindingsV1:
    return TrustedAuthorityBindingsV1(
        "security-approver",
        public_b64(approver),
        "owner",
        public_b64(owner),
    )


def expected_digests() -> ExpectedExportAuthorizationDigestsV1:
    return ExpectedExportAuthorizationDigestsV1(
        PROFILE_DIGEST,
        PLAN_DIGEST,
        MAPPING_DIGEST,
        ADAPTER_DIGEST,
        INVENTORY_DIGEST,
        DESTINATION_DIGEST,
    )


def signed_request(
    *,
    body: dict[str, JsonValue] | None = None,
    now: datetime = NOW,
    expected: ExpectedExportAuthorizationDigestsV1 | None = None,
    owner: Ed25519PrivateKey | None = None,
    approver: Ed25519PrivateKey | None = None,
    trusted: TrustedAuthorityBindingsV1 | None = None,
) -> tuple[
    ExportAuthorizationVerifyRequestV1,
    InMemoryExportAuthorizationNonceStore,
]:
    owner_key = Ed25519PrivateKey.generate() if owner is None else owner
    approver_key = Ed25519PrivateKey.generate() if approver is None else approver
    chosen = authorization_body() if body is None else body
    envelopes = sign_body(chosen, owner_key, approver_key)
    bindings = trusted_pair(owner_key, approver_key) if trusted is None else trusted
    request = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(chosen),
        envelopes,
        bindings,
        expected if expected is not None else expected_digests(),
        now,
    )
    return request, InMemoryExportAuthorizationNonceStore()
