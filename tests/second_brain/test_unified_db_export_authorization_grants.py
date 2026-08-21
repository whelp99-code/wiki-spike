"""Registry-pop one-shot grant probes."""
from __future__ import annotations

import copy
import pickle
from threading import Thread

import pytest

from tests.second_brain.unified_db_export_authorization_support import (
    authorization_body,
    signed_request,
)
from tests.second_brain.unified_db_export_support import bound_reader
from wiki_spike.applications.unified_db_export_authorization_verify import (
    ClaimedUnifiedDbExportAuthorityV1,
    VerifiedUnifiedDbExportAuthorityV1,
    verify_export_only_authorization,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import DecisionRecordV1
from wiki_spike.memory_core.second_brain_cutover import CutoverDecisionV1
from wiki_spike.memory_core.snapshot_import_request import SnapshotImportRequestV1
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import (
    FixtureExportAuthorityV1,
    UnifiedDbExportError,
)


def test_copy_deepcopy_and_pickle_cannot_double_claim() -> None:
    request, nonces = signed_request()
    token = verify_export_only_authorization(request, nonces)
    clones = [copy.copy(token), copy.deepcopy(token)]
    with pytest.raises((InvalidContractValue, UnifiedDbExportError, TypeError)):
        _ = pickle.dumps(token)
    winner = token.claim()
    assert winner.authorization_id == "export-auth-001"
    for clone in clones:
        with pytest.raises(UnifiedDbExportError, match="claimed"):
            _ = clone.claim()
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = token.claim()


def test_forged_handle_and_object_new_cannot_claim() -> None:
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = VerifiedUnifiedDbExportAuthorityV1(b"\x00" * 32).claim()
    bare = object.__new__(VerifiedUnifiedDbExportAuthorityV1)
    with pytest.raises((InvalidContractValue, UnifiedDbExportError, AttributeError)):
        _ = bare.claim()
    parsed = UnifiedDbExportOnlyAuthorizationV1.from_mapping(authorization_body())
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = VerifiedUnifiedDbExportAuthorityV1.from_mapping(parsed.to_mapping())


def test_concurrent_copy_claims_exactly_one_winner() -> None:
    request, nonces = signed_request()
    token = verify_export_only_authorization(request, nonces)
    copies = [copy.copy(token) for _ in range(8)]
    results: list[str] = []
    errors: list[str] = []

    def attempt(clone: VerifiedUnifiedDbExportAuthorityV1) -> None:
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
    assert results == ["export-auth-001"]
    assert len(errors) == 7


def test_claimed_authority_retains_every_signed_commitment() -> None:
    body = authorization_body()
    request, nonces = signed_request(body=body)
    claimed = verify_export_only_authorization(request, nonces).claim()
    assert claimed.authorization_id == body["authorization_id"]
    assert claimed.nonce == body["nonce"]
    assert claimed.operation == body["operation"]
    assert claimed.source_name == body["source_name"]
    assert claimed.profile_digest == body["profile_digest"]
    assert claimed.plan_digest == body["plan_digest"]
    assert claimed.mapping_digest == body["mapping_digest"]
    assert claimed.adapter_digest == body["adapter_digest"]
    assert claimed.inventory_digest == body["inventory_digest"]
    assert claimed.destination_digest == body["destination_digest"]
    assert claimed.issued_at == body["issued_at"]
    assert claimed.not_before == body["not_before"]
    assert claimed.expires_at == body["expires_at"]
    assert claimed.authorization_digest == body["authorization_digest"]
    assert claimed.authorization.authorization_digest == body["authorization_digest"]
    assert not isinstance(claimed, DecisionRecordV1)
    assert not isinstance(claimed, SnapshotImportRequestV1)
    assert not isinstance(claimed, CutoverDecisionV1)
    assert not isinstance(claimed, FixtureExportAuthorityV1)
    with pytest.raises(InvalidContractValue, match="JSON"):
        _ = ClaimedUnifiedDbExportAuthorityV1.from_mapping(body)
    import wiki_spike.applications.unified_db_export_authorization_verify as verify_mod

    assert "ClaimedUnifiedDbExportAuthorityV1" not in getattr(verify_mod, "__all__", ())
    with pytest.raises((InvalidContractValue, UnifiedDbExportError, TypeError)):
        _ = pickle.dumps(claimed)


def test_live_export_consumes_registry_then_refuses() -> None:
    request, nonces = signed_request()
    token = verify_export_only_authorization(request, nonces)
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    )
    with pytest.raises(UnifiedDbExportError, match="mapping"):
        service.export_live(token, dsn_fd=None)
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = token.claim()
