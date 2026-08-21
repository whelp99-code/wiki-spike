"""Builders for POSTGRES_METADATA_CAPTURE_ONLY authorization tests."""
from __future__ import annotations

from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.second_brain.unified_db_postgres_capture_result_support import (
    destination_body,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
    MetadataCaptureVerifyRequestV1,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
    CLOSED_QUERY_MANIFEST_DIGEST,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    InMemoryMetadataCaptureNonceStore,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    metadata_capture_authorization_signing_bytes,
)

SCRIPT = Path("scripts/second_brain_unified_db_snapshot_export.py")
SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-only-authorization-v1.schema.json"
)
CONFORMANCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-only-authorization-conformance-v1.schema.json"
)
EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/unified-db-postgres-metadata-capture-only-authorization-conformance-v1.json"
)
ISSUED = "2026-08-18T12:00:00Z"
EXPIRES = "2026-08-18T12:15:00Z"
NOW = datetime(2026, 8, 18, 12, 5, tzinfo=UTC)
QUERY_MANIFEST_DIGEST = CLOSED_QUERY_MANIFEST_DIGEST
CAPTURE_PLAN_DIGEST = "bb" * 32
OUTPUT_DIGEST = "cc" * 32
DESTINATION_DIGEST = str(destination_body()["destination_digest"])


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64encode(raw).decode("ascii")


def authorization_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "authorization_version": AUTHORIZATION_VERSION,
        "authorization_kind": AUTHORIZATION_KIND,
        "authorization_id": "capture-auth-001",
        "nonce": "cd" * 32,
        "source_name": "unified-db",
        "operation": "METADATA_CAPTURE_ONLY",
        "query_manifest_digest": QUERY_MANIFEST_DIGEST,
        "capture_plan_digest": CAPTURE_PLAN_DIGEST,
        "output_digest": OUTPUT_DIGEST,
        "destination": destination_body(),
        "max_captures": "1",
        "application_row_allowed": False,
        "source_body_read_allowed": False,
        "mutation_allowed": False,
        "export_allowed": False,
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
        unsigned = {
            key: value for key, value in body.items() if key != "authorization_digest"
        }
        body["authorization_digest"] = canonical_ledger_digest(
            "unified-db-postgres-metadata-capture-only-authorization-v1",
            unsigned,
        )
    return body


def sign_body(
    body: dict[str, JsonValue],
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> tuple[Ed25519SignatureEnvelopeV1, Ed25519SignatureEnvelopeV1]:
    payload = metadata_capture_authorization_signing_bytes(body)
    approver_env = Ed25519SignatureEnvelopeV1.from_mapping(
        {
            "signature_version": METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
            "role": "approver",
            "key_id": "security-approver",
            "public_key_b64": public_b64(approver),
            "signature_b64": b64encode(approver.sign(payload)).decode("ascii"),
        },
        version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    )
    owner_env = Ed25519SignatureEnvelopeV1.from_mapping(
        {
            "signature_version": METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
            "role": "owner",
            "key_id": "owner",
            "public_key_b64": public_b64(owner),
            "signature_b64": b64encode(owner.sign(payload)).decode("ascii"),
        },
        version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
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


def expected_digests() -> ExpectedMetadataCaptureDigestsV1:
    return ExpectedMetadataCaptureDigestsV1(
        QUERY_MANIFEST_DIGEST,
        CAPTURE_PLAN_DIGEST,
        OUTPUT_DIGEST,
        DESTINATION_DIGEST,
    )


def signed_request(
    *,
    body: dict[str, JsonValue] | None = None,
    now: datetime = NOW,
    expected: ExpectedMetadataCaptureDigestsV1 | None = None,
    owner: Ed25519PrivateKey | None = None,
    approver: Ed25519PrivateKey | None = None,
    trusted: TrustedAuthorityBindingsV1 | None = None,
    envelopes: tuple[Ed25519SignatureEnvelopeV1, ...] | None = None,
) -> tuple[MetadataCaptureVerifyRequestV1, InMemoryMetadataCaptureNonceStore]:
    owner_key = Ed25519PrivateKey.generate() if owner is None else owner
    approver_key = Ed25519PrivateKey.generate() if approver is None else approver
    chosen = authorization_body() if body is None else body
    signed = sign_body(chosen, owner_key, approver_key) if envelopes is None else envelopes
    bindings = trusted_pair(owner_key, approver_key) if trusted is None else trusted
    request = MetadataCaptureVerifyRequestV1(
        canonical_bytes(chosen),
        signed,
        bindings,
        expected if expected is not None else expected_digests(),
        now,
    )
    return request, InMemoryMetadataCaptureNonceStore()
