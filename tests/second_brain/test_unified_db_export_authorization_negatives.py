"""Negative verifier, mint, nonce, and isolation tests."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo
from typing import override

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.unified_db_export_authorization_support import (
    ADAPTER_DIGEST,
    INVENTORY_DIGEST,
    MAPPING_DIGEST,
    NOW,
    PLAN_DIGEST,
    PROFILE_DIGEST,
    authorization_body,
    expected_digests,
    sign_body,
    signed_request,
    trusted_pair,
)
from tests.second_brain.unified_db_export_support import bound_reader
from wiki_spike.applications.unified_db_export_authorization_verify import (
    ExpectedExportAuthorizationDigestsV1,
    ExportAuthorizationVerifyRequestV1,
    VerifiedUnifiedDbExportAuthorityV1,
    verify_export_only_authorization,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import CoreContractError, InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import DecisionRecordV1
from wiki_spike.memory_core.second_brain_cutover import CutoverDecisionV1
from wiki_spike.memory_core.second_brain_security_contracts import (
    require_security_context_authority,
)
from wiki_spike.memory_core.second_brain_source_fixture import SourceFixtureVerifier
from wiki_spike.memory_core.snapshot_import_request import SnapshotImportRequestV1
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    InMemoryExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import (
    FixtureExportAuthorityV1,
    UnifiedDbExportError,
)


def test_verifier_rejects_untrusted_or_tampered_signature() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    body = authorization_body()
    request, nonces = signed_request(
        body=body,
        owner=owner,
        approver=approver,
        trusted=trusted_pair(Ed25519PrivateKey.generate(), approver),
    )
    with pytest.raises(InvalidContractValue, match="untrusted"):
        _ = verify_export_only_authorization(request, nonces)
    signed = authorization_body()
    envelopes = sign_body(signed, owner, approver)
    signed["authorization_id"] = "export-auth-002"
    tampered = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(signed),
        envelopes,
        trusted_pair(owner, approver),
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_export_only_authorization(
            tampered, InMemoryExportAuthorizationNonceStore()
        )


def test_verifier_rejects_expired_and_not_yet_valid_windows() -> None:
    expired, nonces = signed_request(
        now=datetime(2026, 8, 18, 12, 15, 1, tzinfo=UTC)
    )
    with pytest.raises(InvalidContractValue, match="expired"):
        _ = verify_export_only_authorization(expired, nonces)
    early, early_nonces = signed_request(
        now=datetime(2026, 8, 18, 11, 59, 59, tzinfo=UTC)
    )
    with pytest.raises(InvalidContractValue, match="not yet"):
        _ = verify_export_only_authorization(early, early_nonces)


def test_verifier_rejects_wrong_expected_destination_digest() -> None:
    wrong = ExpectedExportAuthorizationDigestsV1(
        PROFILE_DIGEST,
        PLAN_DIGEST,
        MAPPING_DIGEST,
        ADAPTER_DIGEST,
        INVENTORY_DIGEST,
        "99" * 32,
    )
    request, nonces = signed_request(expected=wrong)
    with pytest.raises(InvalidContractValue, match="destination"):
        _ = verify_export_only_authorization(request, nonces)


def test_nonce_is_exclusive_and_consumed_on_failed_attempt() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    body = authorization_body()
    failed, nonces = signed_request(
        body=body,
        owner=owner,
        approver=approver,
        now=datetime(2026, 8, 18, 12, 16, tzinfo=UTC),
    )
    with pytest.raises(InvalidContractValue, match="expired"):
        _ = verify_export_only_authorization(failed, nonces)
    retry = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(body),
        failed.envelopes,
        failed.trusted,
        expected_digests(),
        NOW,
    )
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_export_only_authorization(retry, nonces)


def test_json_cannot_construct_verified_authority() -> None:
    body = authorization_body()
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = VerifiedUnifiedDbExportAuthorityV1.from_mapping(body)
    parsed = UnifiedDbExportOnlyAuthorizationV1.from_mapping(body)
    assert not isinstance(parsed, VerifiedUnifiedDbExportAuthorityV1)


def test_token_module_exposes_no_public_mint_or_issue_api() -> None:
    import wiki_spike.applications.unified_db_export_authorization_verify as verify_mod

    public = [name for name in dir(verify_mod) if not name.startswith("_")]
    assert "mint_verified_unified_db_export_authority" not in public
    assert "issue_export_grant" not in public
    assert "bind_verified_export_grant" not in public
    assert "record" not in dir(verify_mod.VerifiedUnifiedDbExportAuthorityV1)
    assert all("mint" not in name.lower() and not name.endswith("_grant") for name in public)
    exported = getattr(verify_mod, "__all__", ())
    assert "issue_export_grant" not in exported
    assert "ClaimedUnifiedDbExportAuthorityV1" not in exported
    assert callable(getattr(verify_mod, "_issue_export_grant", None))
    assert not hasattr(verify_mod.VerifiedUnifiedDbExportAuthorityV1, "record")


def test_caller_body_or_object_cannot_mint() -> None:
    body = authorization_body()
    parsed = UnifiedDbExportOnlyAuthorizationV1.from_mapping(body)
    import wiki_spike.applications.unified_db_export_authorization_verify as verify_mod

    assert getattr(verify_mod, "mint_verified_unified_db_export_authority", None) is None
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = VerifiedUnifiedDbExportAuthorityV1(b"\x00" * 32).claim()
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = VerifiedUnifiedDbExportAuthorityV1.from_mapping(parsed.to_mapping())


class _MissingOffset(tzinfo):
    @override
    def utcoffset(self, _dt: datetime | None) -> timedelta | None:
        return None

    @override
    def dst(self, _dt: datetime | None) -> timedelta | None:
        return None

    @override
    def tzname(self, _dt: datetime | None) -> str:
        return "missing-offset"


def test_verifier_rejects_naive_or_offsetless_trusted_now() -> None:
    naive, naive_nonces = signed_request(
        now=datetime.strptime("2026-08-18T12:05:00", "%Y-%m-%dT%H:%M:%S"),  # noqa: DTZ007
    )
    with pytest.raises(InvalidContractValue, match="timezone|utcoffset"):
        _ = verify_export_only_authorization(naive, naive_nonces)
    offsetless, offsetless_nonces = signed_request(
        now=datetime(2026, 8, 18, 12, 5, tzinfo=_MissingOffset())
    )
    with pytest.raises(InvalidContractValue, match="timezone|utcoffset"):
        _ = verify_export_only_authorization(offsetless, offsetless_nonces)


def test_token_cannot_satisfy_resolver_importer_cutover_or_serving() -> None:
    request, nonces = signed_request()
    token = verify_export_only_authorization(request, nonces)
    body = authorization_body()
    assert not isinstance(token, DecisionRecordV1)
    assert not isinstance(token, SnapshotImportRequestV1)
    assert not isinstance(token, CutoverDecisionV1)
    assert not isinstance(token, FixtureExportAuthorityV1)
    with pytest.raises(CoreContractError):
        _ = DecisionRecordV1.from_mapping(body)
    with pytest.raises(CoreContractError):
        _ = SnapshotImportRequestV1.from_mapping(body)
    with pytest.raises(CoreContractError):
        _ = SourceFixtureVerifier().verify(body)
    with pytest.raises(InvalidContractValue):
        _ = require_security_context_authority(token)
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    )
    with pytest.raises(UnifiedDbExportError, match="mapping"):
        service.export_live(token, dsn_fd=None)


def test_nonce_is_global_across_authorization_ids() -> None:
    first, nonces = signed_request(body=authorization_body(authorization_id="export-auth-aaa"))
    _ = verify_export_only_authorization(first, nonces)
    reused, _ignored = signed_request(
        body=authorization_body(authorization_id="export-auth-bbb")
    )
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_export_only_authorization(reused, nonces)
