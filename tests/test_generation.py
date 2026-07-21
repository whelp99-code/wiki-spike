import json

import pytest

from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.hashing import canonical_hash
from wiki_spike.signing import Keyring

NORMAL = (
    "A | supports | X | positive | v=2026\n"
    "A | supports | X | negative | v=2025\n"
    "B | acquired | C | positive | region=KR\n"
)


def _accepted():
    return DeterministicMockExtractor().extract(NORMAL, "src1", "rep1").claims


def _builder(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    kr = Keyring()
    kr.generate("k1")
    return GenerationBuilder(repo, kr, "k1")


def test_candidate_build_and_verify(tmp_path):
    b = _builder(tmp_path)
    cand = b.build_candidate(_accepted(), None, "snap1", "root1")
    assert b.repo.object_exists(cand.commit_oid)
    assert b.repo.read_ref(cand.retention_ref) == cand.commit_oid
    assert b.verify_manifest(cand.commit_oid, cand.generation_id)


def test_generation_id_is_acyclic_hash_of_descriptor(tmp_path):
    b = _builder(tmp_path)
    cand = b.build_candidate(_accepted(), None, "snap1", "root1")
    # generation_id must equal H(descriptor); descriptor must not embed commit oid or id.
    assert canonical_hash(cand.descriptor) == cand.generation_id
    assert cand.commit_oid not in json.dumps(cand.descriptor)
    assert "generation_id" not in cand.descriptor


def test_manifest_in_commit_has_no_self_commit_oid(tmp_path):
    b = _builder(tmp_path)
    cand = b.build_candidate(_accepted(), None, "snap1", "root1")
    raw = b.repo.cat_file(f"{cand.commit_oid}:manifest/{cand.generation_id}.json").decode()
    assert cand.commit_oid not in raw  # no self-reference inside the tree


def test_citation_index_present_in_commit(tmp_path):
    # N2: citation index was built BEFORE the commit and is inside it.
    b = _builder(tmp_path)
    cand = b.build_candidate(_accepted(), None, "snap1", "root1")
    idx = json.loads(b.repo.cat_file(f"{cand.commit_oid}:citation_index/index.json"))
    assert "claims" in idx and len(idx["claims"]) == 3


def test_reproducible_generation_id(tmp_path):
    # Same inputs -> same descriptor -> same generation_id (deterministic pipeline).
    b1 = _builder(tmp_path / "a")
    b2 = _builder(tmp_path / "b")
    c1 = b1.build_candidate(_accepted(), None, "snap1", "root1")
    c2 = b2.build_candidate(_accepted(), None, "snap1", "root1")
    assert c1.generation_id == c2.generation_id


def test_tampered_manifest_fails_verify(tmp_path):
    b = _builder(tmp_path)
    cand = b.build_candidate(_accepted(), None, "snap1", "root1")
    # verifying a different generation_id against the same signature must fail
    assert not b.keyring.verify("k1", b"not-the-generation-id", bytes.fromhex(cand.manifest["signature"]))
