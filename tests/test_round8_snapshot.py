import json
from wiki_spike.workspace import Workspace

def test_parent_rebuild_does_not_trust_mutated_sqlite_assertion(tmp_path):
    ws = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("Product A | supports | feature X | positive | v=1\n")
    ws.ingest_and_publish(a)
    hit = ws.query("Product A").hits[0]
    ws.cp.con.execute("UPDATE claim_identity SET subject='MUTATED', object='poison' WHERE claim_id=?", (hit.claim_id,))
    b = tmp_path / "b.md"; b.write_text("Product B | supports | feature Y | positive | v=1\n")
    second = ws.ingest_and_publish(b)
    commit = ws.cp.generation_commit(second.publish.generation_id)
    snapshot = json.loads(ws.repo.cat_file(f"{commit}:knowledge/snapshot.json"))
    subjects = {r["identity"]["subject_id"] for r in snapshot["accepted_claims"]}
    assert "Product A" in subjects and "MUTATED" not in subjects
    ws.close()

def test_manifest_semantically_binds_snapshot_and_pages(tmp_path):
    ws = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("A | supports | X | positive | v=1\n")
    r = ws.ingest_and_publish(a)
    assert ws.builder.verify_manifest(r.publish.candidate_commit_oid, r.publish.generation_id)
    ws.close()
