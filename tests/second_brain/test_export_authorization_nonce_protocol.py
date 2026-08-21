"""Protocol tests for one-shot reserve_and_consume nonce semantics."""
from __future__ import annotations

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    NONCE,
    OTHER_NONCE,
    attempt,
    in_memory,
)
from tests.second_brain.unified_db_export_authorization_support import (
    authorization_body,
    signed_request,
)
from wiki_spike.applications.unified_db_export_authorization_verify import (
    ExpectedExportAuthorizationDigestsV1,
    ExportAuthorizationVerifyRequestV1,
    verify_export_only_authorization,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    ExportAuthorizationNonceStore,
    InMemoryExportAuthorizationNonceStore,
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_protocol_exposes_only_reserve_and_consume() -> None:
    names = {
        name for name in dir(ExportAuthorizationNonceStore) if not name.startswith("_")
    }
    assert names == {"reserve_and_consume"}
    fake = InMemoryExportAuthorizationNonceStore()
    assert not hasattr(fake, "reserve")
    assert not hasattr(fake, "consume")
    assert callable(fake.reserve_and_consume)


def test_in_memory_inserts_final_consumed_state_once() -> None:
    store = in_memory()
    store.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt(authorization_id="export-auth-bbb"))


def test_nonce_digest_is_domain_separated_and_ascii() -> None:
    digest = export_authorization_nonce_digest(NONCE)
    assert digest != NONCE
    assert digest == export_authorization_nonce_digest(NONCE)
    assert digest != export_authorization_nonce_digest(OTHER_NONCE)
    with pytest.raises(UnifiedDbExportError, match="ASCII"):
        _ = export_authorization_nonce_digest("caf\u00e9")


def test_verifier_burns_well_formed_body_before_expected_checks() -> None:
    request, store = signed_request()
    failed = ExportAuthorizationVerifyRequestV1(
        request.body_bytes,
        request.envelopes,
        request.trusted,
        ExpectedExportAuthorizationDigestsV1(
            request.expected.profile_digest,
            request.expected.plan_digest,
            request.expected.mapping_digest,
            request.expected.adapter_digest,
            request.expected.inventory_digest,
            "99" * 32,
        ),
        request.now,
    )
    with pytest.raises(InvalidContractValue, match="destination"):
        _ = verify_export_only_authorization(failed, store)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_export_only_authorization(request, store)


def test_malformed_body_without_valid_nonce_does_not_consume() -> None:
    store = in_memory()
    request, _ignored = signed_request()
    missing = authorization_body()
    del missing["nonce"]
    bad = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(missing),
        request.envelopes,
        request.trusted,
        request.expected,
        request.now,
    )
    with pytest.raises(InvalidContractValue):
        _ = verify_export_only_authorization(bad, store)
    token = verify_export_only_authorization(request, store)
    assert token.claim().nonce == NONCE
