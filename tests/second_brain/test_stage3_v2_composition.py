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
from wiki_spike.infrastructure.second_brain_ledger import LedgerAuthority


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
