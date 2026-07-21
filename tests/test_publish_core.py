import json

import pytest

from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.controlplane import ActivationError, CASConflict, ControlPlane
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.hashing import canonical_hash
from wiki_spike.publish import PublishService
from wiki_spike.signing import Keyring

SRC_A = "A | supports | X | positive | v=2026\nB | acquired | C | positive | region=KR\n"
SRC_D = "D | mitigates | Y | positive | region=global\n"


def _stack(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    kr = Keyring(); kr.generate("k1")
    builder = GenerationBuilder(repo, kr, "k1")
    cp = ControlPlane(tmp_path / "control.sqlite")
    return repo, builder, cp, PublishService(builder, cp)


def _claims(text):
    return DeterministicMockExtractor().extract(text, "src", "rep").claims


def _register_ready(cp, cand, release_oid, wiki_digest=None, cite_digest=None):
    cp.register_generation(
        cand.generation_id, None, cand.commit_oid, canonical_hash(cand.manifest),
        manifest_json=json.dumps(cand.manifest, sort_keys=True), release_commit_oid=release_oid,
    )
    cp.mark_read_model(cand.generation_id, "wiki_files", wiki_digest or cand.wiki_files_root)
    cp.mark_read_model(cand.generation_id, "citation_index", cite_digest or cand.citation_index_digest)
    cp.set_read_models_ready(cand.generation_id)


def test_publish_e2e_bootstrap(tmp_path):
    _, _, cp, pub = _stack(tmp_path)
    res = pub.publish(_claims(SRC_A), "snapA")
    assert cp.current_pointer() == res.generation_id
    assert cp.generation_state(res.generation_id) == "published"


def test_second_publish_supersedes_parent_pointer(tmp_path):
    _, _, cp, pub = _stack(tmp_path)
    r1 = pub.publish(_claims(SRC_A), "snapA")
    r2 = pub.publish(_claims(SRC_D), "snapD")
    assert cp.current_pointer() == r2.generation_id
    assert cp.generation_state(r1.generation_id) == "superseded"  # pointer moved


def test_git_gc_retention_keeps_candidate_and_release(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    r1 = pub.publish(_claims(SRC_A), "snapA")
    r2 = pub.publish(_claims(SRC_D), "snapD")
    repo.gc_prune_now()
    # Both candidate AND release commits survive (retention anchors).
    assert repo.object_exists(r1.candidate_commit_oid)
    assert repo.object_exists(r1.release_commit_oid)
    assert builder.verify_manifest(r1.candidate_commit_oid, r1.generation_id)


def test_activation_refuses_binding_mismatch(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    cand = builder.build_candidate(_claims(SRC_A), None, "snapA", "rootA")
    rel = pub._build_release_commit(cand, None)
    _register_ready(cp, cand, rel, wiki_digest="WRONG")
    with pytest.raises(ActivationError):
        cp.activate(cand.generation_id, None, rel)
    assert cp.current_pointer() is None


def test_activation_cannot_be_bypassed_with_empty_manifest(tmp_path):
    # #4: activation derives required artifacts from the registered manifest; an
    # empty/missing manifest cannot publish.
    repo, builder, cp, pub = _stack(tmp_path)
    cand = builder.build_candidate(_claims(SRC_A), None, "snapA", "rootA")
    rel = pub._build_release_commit(cand, None)
    cp.register_generation(cand.generation_id, None, cand.commit_oid, "mh",
                           manifest_json="{}", release_commit_oid=rel)  # no inline_artifacts
    cp.mark_read_model(cand.generation_id, "wiki_files", cand.wiki_files_root)
    cp.mark_read_model(cand.generation_id, "citation_index", cand.citation_index_digest)
    cp.set_read_models_ready(cand.generation_id)
    with pytest.raises(ActivationError):
        cp.activate(cand.generation_id, None, rel)
    assert cp.current_pointer() is None


def test_crash_before_db_leaves_orphan_unpublished(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    cand = builder.build_candidate(_claims(SRC_A), None, "snapA", "rootA")
    assert cp.current_pointer() is None
    assert repo.object_exists(cand.commit_oid)
    assert repo.read_ref(cand.retention_ref) == cand.commit_oid


def test_crash_after_db_resumes_via_outbox(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    res = pub.publish(_claims(SRC_A), "snapA")
    pending = cp.pending_outbox()
    assert len(pending) == 1 and pending[0][2] == res.generation_id


def test_stale_cas_conflict_and_requeue(tmp_path):
    # A stale publisher loses the CAS; the requeue loop rebuilds -> no lost ingest.
    repo, builder, cp, pub = _stack(tmp_path)
    r1 = pub.publish(_claims(SRC_A), "snapA")
    cand = builder.build_candidate(_claims(SRC_D), None, "snapD", "rootD")
    rel = pub._build_release_commit(cand, None)
    _register_ready(cp, cand, rel)
    with pytest.raises(CASConflict):
        cp.activate(cand.generation_id, None, rel)  # stale parent=None while current=G1
    r2 = pub.publish(_claims(SRC_D), "snapD")
    assert cp.current_pointer() == r2.generation_id
