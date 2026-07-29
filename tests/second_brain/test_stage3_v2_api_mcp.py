from pathlib import Path

from test_stage3_ledger_persistence import (
    NOW,
    KEY_ID,
    SIGNER_REF,
    TrackingLedgerService,
    create_and_approve,
    digest,
    ref,
    request,
    signed_snapshot_signer,
    trust_for_request,
)
import test_stage3_ledger_persistence as ledger_fixtures
from test_stage1_capabilities import authority as security_authority
from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.composition.api_v2 import CapabilityUseV2, SecondBrainApiV2
from wiki_spike.composition.mcp_v2 import SecondBrainMcpV2
from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import LedgerAuthority, LifecycleLedgerAuthority


ROOT = Path(__file__).parents[2]


def test_transports_expose_only_identical_bounded_v2_operations():
    api = (ROOT / "src/wiki_spike/composition/api_v2.py").read_text()
    mcp = (ROOT / "src/wiki_spike/composition/mcp_v2.py").read_text()
    for operation in ("command", "recall", "citation", "status"):
        assert f"def {operation}(" in api
        assert f"def {operation}(" in mcp
    for forbidden in ("list", "dump", "Workspace", "McpServer", "raw_key", "derived_key", "artifact", "blob", "Gate8"):
        assert forbidden not in api
        assert forbidden not in mcp


def test_api_has_required_capability_scope_and_replay_checks():
    api = (ROOT / "src/wiki_spike/composition/api_v2.py").read_text()
    assert "class CapabilityUseV2" in api
    assert "capability action is out of scope" in api
    assert "capability use was replayed" in api
    assert "nonce exceeds bound" in api
    assert "self._product.authority.require()" in api


_FORBIDDEN = ("list", "dump", "Workspace", "McpServer", "raw_key", "derived_key", "artifact", "blob", "Gate8", "workspace_dump")


def test_recall_and_citation_receipts_never_leak_forbidden_surface_through_either_transport(tmp_path):
    ledger_fixtures._ACTIVE_REVISIONS.clear()
    ledger_fixtures._COMMAND_PROVENANCE.clear()
    ledger_fixtures._CURRENT_CUT = "1"
    database = LifecycleDatabase(tmp_path / "ledger.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    workspace = ref("workspace", "surface")
    first_request = request(workspace, transaction_cut="1", recorded_at=NOW)
    write_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(first_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    write_authority.set_authority(workspace, LedgerAuthority(ref("capability", "stage3"), "1"), "2026-01-01T00:00:00Z")
    writer = TrackingLedgerService(write_authority, write_authority)
    first_candidate, second_candidate = ref("candidate", "surface-one"), ref("candidate", "surface-two")
    create_and_approve(writer, cas, first_candidate, "surface-one", workspace=workspace)
    create_and_approve(writer, cas, second_candidate, "surface-two", workspace=workspace)

    page1_request = request(workspace, recorded_at=NOW)
    read_authority = LifecycleLedgerAuthority(
        database, cas, trust_for_request(page1_request), signed_snapshot_signer,
        signer_ref=SIGNER_REF, key_id=KEY_ID, page_size=1,
    )
    product = SecondBrainProductV2(
        authority=security_authority(),
        ledger=SecondBrainLedgerService(read_authority, read_authority),
        recall=SecondBrainRecallService(read_authority),
    )
    api = SecondBrainApiV2(product)
    mcp = SecondBrainMcpV2(product)
    use_recall_api = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "recall", "n-api-recall", ("citation", "recall"))
    use_recall_mcp = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "recall", "n-mcp-recall", ("citation", "recall"))
    use_citation_api = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "citation", "n-api-cite", ("citation", "recall"))
    use_citation_mcp = CapabilityUseV2(ref("capability", "stage3"), "1", workspace, digest("scope"), "citation", "n-mcp-cite", ("citation", "recall"))

    api_recall = api.recall(use_recall_api, page1_request)
    mcp_recall = mcp.recall(use_recall_mcp, page1_request)
    assert (api_recall.code, mcp_recall.code) == ("OK", "OK")
    assert api_recall.receipt["has_more"] == mcp_recall.receipt["has_more"] == "true"
    assert api_recall.receipt["continuation"] == mcp_recall.receipt["continuation"]

    served_candidate, off_page_candidate = sorted((first_candidate, second_candidate))
    api_citation = api.citation(use_citation_api, page1_request, off_page_candidate)
    mcp_citation = mcp.citation(use_citation_mcp, page1_request, off_page_candidate)
    assert (api_citation.code, mcp_citation.code) == ("NOT_SERVED", "NOT_SERVED")

    for result in (api_recall, mcp_recall, api_citation, mcp_citation):
        for value in result.receipt.values():
            for forbidden in _FORBIDDEN:
                assert forbidden not in value
    database.close()
