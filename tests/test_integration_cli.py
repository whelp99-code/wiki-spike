"""End-to-end integration of Phase 1a + 1b + SUB-07 through the Workspace."""
from pathlib import Path

import pytest

from wiki_spike.controlplane import LeaseError
from wiki_spike.workspace import Workspace

FIX = Path(__file__).parent / "fixtures"


def test_ingest_and_publish_then_search(tmp_path):
    ws = Workspace(tmp_path / "ws")
    r = ws.ingest_and_publish(FIX / "normal.md")
    assert r.new_claims == 3
    assert ws.cp.current_pointer() == r.publish.generation_id
    resp = ws.query("Product A")
    assert not resp.stale and any(h.subject == "Product A" for h in resp.hits)
    ws.close()


def test_injection_fixture_publishes_one_claim(tmp_path):
    ws = Workspace(tmp_path / "ws")
    r = ws.ingest_and_publish(FIX / "instruction_data.md")
    assert r.new_claims == 1
    ws.close()


def test_mirror_end_to_end(tmp_path):
    ws = Workspace(tmp_path / "ws")
    r = ws.ingest_and_publish(FIX / "normal.md")
    assert ws.mirror_now() == 1
    assert ws.mirror.remote_has(r.publish.candidate_commit_oid)
    ws.close()


def test_lease_blocks_second_publisher(tmp_path):
    ws = Workspace(tmp_path / "ws", holder="pub-A")
    import time
    ws.cp.acquire_lease("pub-B", int(time.time()), ttl=60)
    with pytest.raises(LeaseError):
        ws.ingest_and_publish(FIX / "normal.md")
    ws.close()
