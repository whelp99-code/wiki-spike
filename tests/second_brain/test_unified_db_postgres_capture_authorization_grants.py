"""One-shot process-local grant probes for metadata capture authority."""
from __future__ import annotations

import copy
import pickle
from threading import Thread

import pytest

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    authorization_body,
    signed_request,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    ClaimedUnifiedDbMetadataCaptureAuthorityV1,
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
    verify_metadata_capture_authorization,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_copy_deepcopy_and_pickle_cannot_double_claim() -> None:
    request, nonces = signed_request()
    token = verify_metadata_capture_authorization(request, nonces)
    clones = [copy.copy(token), copy.deepcopy(token)]
    with pytest.raises((InvalidContractValue, UnifiedDbExportError, TypeError)):
        _ = pickle.dumps(token)
    winner = token.claim()
    assert winner.authorization_id == "capture-auth-001"
    for clone in clones:
        with pytest.raises(UnifiedDbExportError, match="claimed"):
            _ = clone.claim()
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = token.claim()


def test_forged_handle_and_json_cannot_claim() -> None:
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = VerifiedUnifiedDbMetadataCaptureAuthorityV1(b"\x00" * 32).claim()
    parsed = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(authorization_body())
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = VerifiedUnifiedDbMetadataCaptureAuthorityV1.from_mapping(parsed.to_mapping())
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = ClaimedUnifiedDbMetadataCaptureAuthorityV1.from_mapping(parsed.to_mapping())


def test_concurrent_copy_claims_exactly_one_winner() -> None:
    request, nonces = signed_request()
    token = verify_metadata_capture_authorization(request, nonces)
    copies = [copy.copy(token) for _ in range(8)]
    results: list[str] = []
    errors: list[str] = []

    def attempt(clone: VerifiedUnifiedDbMetadataCaptureAuthorityV1) -> None:
        try:
            claimed = clone.claim()
            results.append(claimed.authorization_id)
        except UnifiedDbExportError:
            errors.append("claimed")

    workers = [Thread(target=attempt, args=(clone,)) for clone in copies]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert results == ["capture-auth-001"]
    assert len(errors) == 7


def test_claimed_authority_retains_signed_commitments_and_cannot_pickle() -> None:
    body = authorization_body()
    request, nonces = signed_request(body=body)
    claimed = verify_metadata_capture_authorization(request, nonces).claim()
    assert claimed.authorization_id == body["authorization_id"]
    assert claimed.nonce == body["nonce"]
    assert claimed.operation == body["operation"]
    assert claimed.source_name == body["source_name"]
    assert claimed.query_manifest_digest == body["query_manifest_digest"]
    assert claimed.capture_plan_digest == body["capture_plan_digest"]
    assert claimed.output_digest == body["output_digest"]
    assert claimed.issued_at == body["issued_at"]
    assert claimed.not_before == body["not_before"]
    assert claimed.expires_at == body["expires_at"]
    assert claimed.authorization_digest == body["authorization_digest"]
    import wiki_spike.applications.unified_db_postgres_capture_authorization_verify as verify_mod

    assert "ClaimedUnifiedDbMetadataCaptureAuthorityV1" not in getattr(
        verify_mod, "__all__", ()
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError, TypeError)):
        _ = pickle.dumps(claimed)
