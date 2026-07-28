from __future__ import annotations

from pathlib import Path

import pytest
import importlib
from test_stage3_ledger_persistence import (
    KEY_ID,
    SIGNER_REF,
    blob,
    command,
    create_and_approve,
    ref,
    request,
    signed_snapshot_signer,
    store,
    trust_for_request,
)
from wiki_spike.composition.api_v2 import CapabilityUseV2
from wiki_spike.composition.second_brain_product import ProductCompositionError, compose_second_brain_product_v2
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService


def test_support_withdrawal_recursively_removes_supported_recall(tmp_path: Path) -> None:
    database, cas, service, workspace = store(tmp_path)
    root, dependent = ref("candidate", "support-root"), ref("candidate", "support-dependent")
    create_and_approve(service, cas, root, "support-root", workspace=workspace)
    create_and_approve(service, cas, dependent, "support-dependent", workspace=workspace)
    service.append(command("CORRECT", dependent, command_name="journey-support", related=root, workspace=workspace, content_digest=blob(cas, "support")))
    service.append(command("REVOKE", root, command_name="journey-withdraw", workspace=workspace))
    recall_request = request(workspace)
    recall = SecondBrainRecallService(
        LifecycleLedgerAuthority(
            database,
            cas,
            trust_authority=trust_for_request(recall_request),
            snapshot_signer=signed_snapshot_signer,
            signer_ref=SIGNER_REF,
            key_id=KEY_ID,
        )
    )
    assert recall.recall(recall_request).abstained
    assert {row[0] for row in database.con.execute("SELECT candidate_state FROM ledger_candidate")} == {"REVOKED"}
    database.close()


def test_product_root_and_v2_capability_fail_closed_before_route_use(tmp_path: Path) -> None:
    database = LifecycleDatabase(tmp_path / "closed.sqlite"); database.initialize()
    with pytest.raises(ProductCompositionError):
        compose_second_brain_product_v2(authority=object(), database=database)
    with pytest.raises(ValueError, match="out of scope"):
        CapabilityUseV2(ref("capability", "x"), "1", ref("workspace", "x"), "a" * 64, "recall", "n", ("status",))
    database.close()
    mcp = importlib.import_module("wiki_spike.composition.mcp_v2")
    assert callable(mcp.SecondBrainMcpV2)
