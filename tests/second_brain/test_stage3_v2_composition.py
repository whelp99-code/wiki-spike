from pathlib import Path

from test_stage1_capabilities import authority as security_authority

from wiki_spike.composition.second_brain_product import compose_second_brain_product_v2
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from test_stage3_ledger_persistence import (
    _COMMAND_PROVENANCE,
    DeterministicEd25519Verifier,
    KEY_ID,
    SIGNER_REF,
    blob,
    command,
    ref,
    request,
    signed_snapshot_signer,
    trust_for_request,
)
from wiki_spike.infrastructure.second_brain_ledger import LedgerAuthority, LifecycleLedgerAuthority
from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.composition.api_v2 import CapabilityUseV2, SecondBrainApiV2
from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.memory_core.second_brain_ledger_contracts import RecallContinuationV2
from test_stage3_ledger_persistence import NOW, TrackingLedgerService, create_and_approve, digest
import test_stage3_ledger_persistence as ledger_fixtures


def test_product_composition_executes_authority_append_and_recall(tmp_path: Path) -> None:
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "composition")
    recall_request = request(workspace, transaction_cut="1")
    product = compose_second_brain_product_v2(
        authority=security_authority(), database=database, cas=cas,
        verifier=DeterministicEd25519Verifier(), clock=lambda: "2026-01-01T00:00:00Z",
        provenance=trust_for_request(recall_request)._RecallTrustAuthorityV2__provenance,
        snapshot_signer=signed_snapshot_signer, signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    ledger_authority = product.ledger._ledger
    ledger_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    item = command("CREATE_CANDIDATE", ref("candidate", "composition"), command_name="composition", workspace=workspace, content_digest=blob(cas, "composition"), transaction_cut="1")
    ledger_authority._trust_authority.register_verified_provenance(
        _COMMAND_PROVENANCE[item.authority_provenance_ref]
    )
    product.ledger.append(item)
    assert product.recall.recall(recall_request).abstained
    database.close()


def test_v2_recall_paginates_across_a_workspace_with_more_candidates_than_the_page_size(tmp_path: Path) -> None:
    ledger_fixtures._ACTIVE_REVISIONS.clear()
    ledger_fixtures._COMMAND_PROVENANCE.clear()
    ledger_fixtures._CURRENT_CUT = "1"
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "paginated")
    first_request = request(workspace, transaction_cut="1", recorded_at=NOW)
    write_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(first_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    write_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    writer = TrackingLedgerService(write_authority, write_authority)
    first_candidate, second_candidate = ref("candidate", "page-one"), ref("candidate", "page-two")
    create_and_approve(writer, cas, first_candidate, "page-one", workspace=workspace)
    create_and_approve(writer, cas, second_candidate, "page-two", workspace=workspace)

    # Each read stage gets its own trust-bound authority/product over the same
    # durable database, mirroring how a real, separately-authorized recall
    # request arrives (see test_stage3_ledger_persistence's continuation tests).
    page1_request = request(workspace, recorded_at=NOW)  # picks up the current transaction cut after both writes
    page1_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(page1_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    page1_product = SecondBrainProductV2(
        authority=security_authority(),
        ledger=SecondBrainLedgerService(page1_authority, page1_authority),
        recall=SecondBrainRecallService(page1_authority),
    )
    page1_api = SecondBrainApiV2(page1_product)
    use_recall_1 = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "recall", "n-recall-1", ("citation", "recall"))
    use_citation_1 = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "citation", "n-cite-1", ("citation", "recall"))
    use_citation_2 = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "citation", "n-cite-2", ("citation", "recall"))

    first_page = page1_api.recall(use_recall_1, page1_request)
    assert first_page.code == "OK"
    assert first_page.receipt["result_count"] == "1"
    assert first_page.receipt["has_more"] == "true"
    assert first_page.receipt["continuation"]

    # The candidate off page 1 must never be reported as OK/zero citations: it
    # is indistinguishable from genuinely uncited without seeing every page.
    off_page_citation = page1_api.citation(use_citation_1, page1_request, second_candidate)
    assert (off_page_citation.code, off_page_citation.receipt["citation_count"]) == ("NOT_SERVED", "0")
    on_page_citation = page1_api.citation(use_citation_2, page1_request, first_candidate)
    assert (on_page_citation.code, on_page_citation.receipt["citation_count"]) == ("OK", "1")

    decoded = dict(pair.split("=", 1) for pair in first_page.receipt["continuation"].split(";"))
    continuation = RecallContinuationV2.from_mapping(decoded)
    second_request = request(workspace, transaction_cut=continuation.transaction_cut, continuation=continuation, recorded_at=NOW)
    page2_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(second_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    page2_product = SecondBrainProductV2(
        authority=security_authority(),
        ledger=SecondBrainLedgerService(page2_authority, page2_authority),
        recall=SecondBrainRecallService(page2_authority),
    )
    page2_api = SecondBrainApiV2(page2_product)
    use_recall_2 = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "recall", "n-recall-2", ("citation", "recall"))
    second_page = page2_api.recall(use_recall_2, second_request)
    assert second_page.code == "OK"
    assert second_page.receipt["result_count"] == "1"
    assert second_page.receipt["has_more"] == "false"
    assert second_page.receipt["continuation"] == ""
    database.close()
