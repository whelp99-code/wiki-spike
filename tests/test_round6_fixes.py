"""Contracts fixing the 9 critical Round-6 findings (code-level adversarial review)."""
import threading
from pathlib import Path

import pytest

from wiki_spike.canonical import CanonicalizationError, canonical_bytes
from wiki_spike.cas import ContentAddressedStore
from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.controlplane import ActivationError, ControlPlane
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.publish import PublishService
from wiki_spike.signing import Keyring
from wiki_spike.workspace import Workspace

FIX = Path(__file__).parent / "fixtures"


def _stack(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    kr = Keyring(); kr.generate("k1")
    builder = GenerationBuilder(repo, kr, "k1")
    cp = ControlPlane(tmp_path / "control.sqlite")
    return repo, builder, cp, PublishService(builder, cp)


def _ex(text):
    return DeterministicMockExtractor().extract(text, "src", "rep")


# #1 knowledge accumulates (a new, unrelated source does not wipe prior knowledge)
def test_knowledge_accumulates(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.ingest_and_publish(FIX / "normal.md")          # Product A, B, ...
    before = len(ws.query("Product A").hits)
    ws.ingest_and_publish(FIX / "instruction_data.md")  # unrelated Product D
    after = len(ws.query("Product A").hits)
    assert before > 0 and after == before  # Product A survives
    assert len(ws.query("Product D").hits) == 1  # D added on top
    ws.close()


# #2 a zero-claim source is a no-op (does not empty the wiki)
def test_zero_claim_source_is_noop(tmp_path):
    ws = Workspace(tmp_path / "ws")
    r1 = ws.ingest_and_publish(FIX / "normal.md")
    ptr1 = ws.cp.current_pointer()
    prose = tmp_path / "prose.md"
    prose.write_text("# just prose\n\nNo structured claims here at all.\n")
    r2 = ws.ingest_and_publish(prose)
    assert r2.publish.noop is True
    assert ws.cp.current_pointer() == ptr1  # pointer unchanged
    assert len(ws.query("Product A").hits) > 0  # knowledge intact
    ws.close()


# #3 signed manifest binds the ACTUAL wiki content
def test_signature_binds_actual_content(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    cand = builder.build_candidate(_ex("A | supports | X | positive | v=1\n").claims,
                                   None, "snap", "root")
    assert builder.verify_manifest(cand.commit_oid, cand.generation_id)
    # Tamper: build a commit that reuses the manifest but changes a wiki file.
    orig_paths = repo.ls_tree(cand.commit_oid)
    files = {p: repo.cat_file(f"{cand.commit_oid}:{p}") for p in orig_paths}
    wiki_key = next(p for p in files if p.startswith("wiki/"))
    files[wiki_key] = b"# tampered\n- tampered claim\n"
    tampered_tree = repo.write_tree_from_files(files)
    tampered_commit = repo.commit_tree(tampered_tree, "tampered")
    assert builder.verify_manifest(tampered_commit, cand.generation_id) is False


# #6 lease is exclusive across distinct holders (uuid per workspace)
def test_two_workspaces_have_distinct_holders(tmp_path):
    ws1 = Workspace(tmp_path / "w")   # shares the same root/control-plane
    ws2 = Workspace(tmp_path / "w")
    assert ws1.holder != ws2.holder
    import time
    assert ws1.cp.acquire_lease(ws1.holder, int(time.time()), 30) is not None
    assert ws2.cp.acquire_lease(ws2.holder, int(time.time()), 30) is None
    ws1.close(); ws2.close()


# #8 non-ASCII (Korean) subjects get distinct pages
def test_korean_subjects_do_not_collide(tmp_path):
    from wiki_spike.assembler import render_pages
    claims = _ex("한국제품 | supports | 기능 | positive | v=1\n"
                 "다른제품 | supports | 기능 | positive | v=1\n").claims
    pages = render_pages(claims)
    assert len(pages) == 2  # two distinct files, not one 'untitled.md'


# #9 CAS tolerates concurrent writers of the same digest
def test_cas_concurrent_writers(tmp_path):
    cas = ContentAddressedStore(tmp_path / "cas")
    data = b"x" * 4096
    errors = []
    def w():
        try:
            cas.put(data)
        except Exception as e:  # noqa
            errors.append(e)
    threads = [threading.Thread(target=w) for _ in range(8)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert errors == []
    assert cas.get(cas.put(data)) == data


# high-priority: NFC-collapsing keys are rejected, not silently merged
def test_nfc_key_collision_rejected(tmp_path):
    import unicodedata
    nfc = unicodedata.normalize("NFC", "각")
    nfd = unicodedata.normalize("NFD", "각")
    with pytest.raises(CanonicalizationError):
        canonical_bytes({nfc: "1", nfd: "2"})


# high-priority: re-ingesting the same source is a no-op, not an exception
def test_reingest_same_source_is_noop(tmp_path):
    ws = Workspace(tmp_path / "ws")
    ws.ingest_and_publish(FIX / "normal.md")
    r2 = ws.ingest_and_publish(FIX / "normal.md")
    assert r2.publish.noop is True
    ws.close()


# high-priority: nonexistent parent generation raises instead of silent root commit
def test_missing_parent_raises(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    with pytest.raises(ValueError):
        builder.build_candidate(_ex("A | b | C | positive | v=1\n").claims,
                                "nonexistent-parent", "snap", "root")


# high-priority: evidence carries real provenance (source_object_hash populated)
def test_evidence_has_source_object_hash(tmp_path):
    claims = _ex("A | supports | X | positive | v=1\n").claims
    assert claims[0].evidence.source_object_hash == "src"
    assert claims[0].evidence.locators[0]["offset_unit"] == "unicode_codepoint"
