from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain import test_stage3_ledger_persistence as ledger_fixtures
from tests.second_brain.test_macos_persistence_profile import (
    SQLCIPHER_ARTIFACT,
    persistence_profile,
    persistence_receipt,
)
from tests.second_brain.test_stage1_capabilities import (
    authority as security_authority,
)
from tests.second_brain.test_stage3_ledger_persistence import (
    KEY_ID,
    NOW,
    SIGNER_REF,
    DeterministicEd25519Verifier,
    TrackingLedgerService,
    blob,
    command,
    create_and_approve,
    digest,
    ref,
    signed_snapshot_signer,
)
from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.composition.api_v2 import CapabilityUseV2, SecondBrainApiV2
from wiki_spike.composition.second_brain_product import (
    SecondBrainProductV2,
    compose_second_brain_product_v2,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile import verify_mac_persistence_profile
from wiki_spike.infrastructure.second_brain_ledger import (
    LedgerAuthority,
    LifecycleLedgerAuthority,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2,
    RecallContinuationV2,
    RecallSnapshotRequestV2,
    RecallTrustAuthorityV2,
)

request = cast(Callable[..., RecallSnapshotRequestV2], ledger_fixtures.request)
trust_for_request = cast(
    Callable[..., RecallTrustAuthorityV2],
    ledger_fixtures.trust_for_request,
)


def test_product_composition_executes_authority_append_and_recall(tmp_path: Path) -> None:
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "composition")
    recall_request = request(workspace, transaction_cut="1")
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    verified_persistence = verify_mac_persistence_profile(
        profile=profile,
        receipt=persistence_receipt(profile, owner, approver),
        owner_public_key=owner.public_key(),
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
        database=database,
        cas=cas,
    )
    product = compose_second_brain_product_v2(
        authority=security_authority(), database=database, cas=cas,
        persistence_profile=verified_persistence,
        verifier=DeterministicEd25519Verifier(), clock=lambda: "2026-01-01T00:00:00Z",
        provenance=cast(
            Mapping[str, AuthorityProvenanceV2],
            object.__getattribute__(
                trust_for_request(recall_request),
                "_RecallTrustAuthorityV2__provenance",
            ),
        ),
        snapshot_signer=signed_snapshot_signer, signer_ref=SIGNER_REF, key_id=KEY_ID,
    )
    ledger_authority = cast(
        LifecycleLedgerAuthority,
        object.__getattribute__(product.ledger, "_ledger"),
    )
    ledger_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    item = command("CREATE_CANDIDATE", ref("candidate", "composition"), command_name="composition", workspace=workspace, content_digest=blob(cas, "composition"), transaction_cut="1")
    trust_authority = cast(
        RecallTrustAuthorityV2,
        object.__getattribute__(ledger_authority, "_trust_authority"),
    )
    command_provenance = cast(
        dict[str, AuthorityProvenanceV2],
        vars(ledger_fixtures)["_COMMAND_PROVENANCE"],
    )
    trust_authority.register_verified_provenance(
        command_provenance[item.authority_provenance_ref]
    )
    _ = product.ledger.append(item)
    assert product.recall.recall(recall_request).abstained
    database.close()


def test_v2_recall_paginates_across_a_workspace_with_more_candidates_than_the_page_size(tmp_path: Path) -> None:
    active_revisions = cast(
        dict[str, str],
        vars(ledger_fixtures)["_ACTIVE_REVISIONS"],
    )
    command_provenance = cast(
        dict[str, AuthorityProvenanceV2],
        vars(ledger_fixtures)["_COMMAND_PROVENANCE"],
    )
    active_revisions.clear()
    command_provenance.clear()
    module_state = cast(dict[str, object], ledger_fixtures.__dict__)
    module_state["_CURRENT_CUT"] = "1"
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
