"""Verifier negatives for POSTGRES_METADATA_CAPTURE_ONLY authority."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.unified_db_export_authorization_support import (
    authorization_body as export_authorization_body,
)
from tests.second_brain.unified_db_export_authorization_support import (
    sign_body as sign_export_body,
)
from tests.second_brain.unified_db_export_authorization_support import (
    trusted_pair as export_trusted_pair,
)
from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    CAPTURE_PLAN_DIGEST,
    NOW,
    OUTPUT_DIGEST,
    QUERY_MANIFEST_DIGEST,
    authorization_body,
    expected_digests,
    sign_body,
    signed_request,
    trusted_pair,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
    MetadataCaptureVerifyRequestV1,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
    verify_metadata_capture_authorization,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    export_only_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    InMemoryMetadataCaptureNonceStore,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    parse_metadata_capture_envelopes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_verifier_mints_process_local_authority_when_bindings_and_window_hold() -> None:
    request, nonces = signed_request()
    token = verify_metadata_capture_authorization(request, nonces)
    assert isinstance(token, VerifiedUnifiedDbMetadataCaptureAuthorityV1)
    claimed = token.claim()
    assert claimed.authorization_id == "capture-auth-001"
    assert claimed.query_manifest_digest == QUERY_MANIFEST_DIGEST
    assert claimed.capture_plan_digest == CAPTURE_PLAN_DIGEST
    assert claimed.output_digest == OUTPUT_DIGEST
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = token.claim()


def test_verifier_rejects_export_domain_replay() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    export_body = export_authorization_body()
    export_envs = sign_export_body(export_body, owner, approver)
    replayed = MetadataCaptureVerifyRequestV1(
        canonical_bytes(export_body),
        export_envs,
        export_trusted_pair(owner, approver),
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_metadata_capture_authorization(
            replayed, InMemoryMetadataCaptureNonceStore()
        )
    capture_body = authorization_body()
    export_signed = export_only_authorization_signing_bytes(capture_body)
    capture_payload = (
        b"wiki-spike.second-brain.unified-db.postgres-metadata-capture-only-authorization.v1\x00"
        + canonical_bytes(capture_body)
    )
    assert export_signed != capture_payload


def test_verifier_rejects_owner_only_or_security_only_envelopes() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    body = authorization_body()
    approver_env, owner_env = sign_body(body, owner, approver)
    for envelopes in ((owner_env,), (approver_env,)):
        request = MetadataCaptureVerifyRequestV1(
            canonical_bytes(body),
            envelopes,
            trusted_pair(owner, approver),
            expected_digests(),
            NOW,
        )
        with pytest.raises(InvalidContractValue, match="exactly two|two public"):
            _ = verify_metadata_capture_authorization(
                request, InMemoryMetadataCaptureNonceStore()
            )


def test_envelopes_reject_duplicate_role_or_shared_key() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    body = authorization_body()
    approver_env, owner_env = sign_body(body, owner, approver)
    with pytest.raises(InvalidContractValue, match="approver then owner"):
        _ = parse_metadata_capture_envelopes(
            (owner_env.to_mapping(), owner_env.to_mapping())
        )
    shared = sign_body(body, owner, owner)
    with pytest.raises(InvalidContractValue, match="distinct"):
        _ = parse_metadata_capture_envelopes(
            (shared[0].to_mapping(), shared[1].to_mapping())
        )
    _ = approver_env


def test_verifier_rejects_wrong_trusted_key() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    request, nonces = signed_request(
        owner=owner,
        approver=approver,
        trusted=trusted_pair(Ed25519PrivateKey.generate(), approver),
    )
    with pytest.raises(InvalidContractValue, match="untrusted"):
        _ = verify_metadata_capture_authorization(request, nonces)


def test_verifier_rejects_body_or_signature_swap() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    original = authorization_body()
    swapped = authorization_body(authorization_id="capture-auth-002")
    envelopes = sign_body(original, owner, approver)
    request = MetadataCaptureVerifyRequestV1(
        canonical_bytes(swapped),
        envelopes,
        trusted_pair(owner, approver),
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_metadata_capture_authorization(
            request, InMemoryMetadataCaptureNonceStore()
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("query_manifest_digest", "11" * 32),
        ("capture_plan_digest", "22" * 32),
        ("output_digest", "33" * 32),
    ],
)
def test_verifier_rejects_digest_output_or_manifest_swap(
    field: str, value: str
) -> None:
    expected = ExpectedMetadataCaptureDigestsV1(
        QUERY_MANIFEST_DIGEST,
        CAPTURE_PLAN_DIGEST,
        OUTPUT_DIGEST,
    )
    mutated = ExpectedMetadataCaptureDigestsV1(
        value if field == "query_manifest_digest" else expected.query_manifest_digest,
        value if field == "capture_plan_digest" else expected.capture_plan_digest,
        value if field == "output_digest" else expected.output_digest,
    )
    request, nonces = signed_request(expected=mutated)
    with pytest.raises(InvalidContractValue, match="digest"):
        _ = verify_metadata_capture_authorization(request, nonces)


def test_verifier_rejects_expired_and_not_yet_valid_windows() -> None:
    expired, nonces = signed_request(
        now=datetime(2026, 8, 18, 12, 15, 1, tzinfo=UTC)
    )
    with pytest.raises(InvalidContractValue, match="expired"):
        _ = verify_metadata_capture_authorization(expired, nonces)
    early, early_nonces = signed_request(
        now=datetime(2026, 8, 18, 11, 59, 59, tzinfo=UTC)
    )
    with pytest.raises(InvalidContractValue, match="not yet"):
        _ = verify_metadata_capture_authorization(early, early_nonces)
