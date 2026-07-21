"""Round 7 contract tests: multi-source preservation, unauthorized REVOKE, snapshot
binding, release verification, output sanitization."""
import json
from pathlib import Path

import pytest

from wiki_spike.assembler import sanitize
from wiki_spike.controlplane import ControlPlane
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.publish import PublishService
from wiki_spike.signing import Keyring
from wiki_spike.workspace import Workspace


def _stack(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    kr = Keyring(); kr.generate("k1")
    builder = GenerationBuilder(repo, kr, "k1")
    cp = ControlPlane(tmp_path / "control.sqlite")
    return repo, builder, cp, PublishService(builder, cp)


# --- #3.1 multi-source assertion preservation ---------------------------- #
def test_second_independent_source_is_not_noop_and_preserved(tmp_path):
    ws = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("# source A\nA | supports | X | positive | v=1\n")
    b = tmp_path / "b.md"; b.write_text("# source B different bytes\nA | supports | X | positive | v=1\n")
    r1 = ws.ingest_and_publish(a)
    r2 = ws.ingest_and_publish(b)
    assert not r2.publish.noop  # second independent source publishes
    # Citation index in the new generation keeps BOTH source assertions for the claim.
    commit = ws.cp.generation_commit(r2.publish.generation_id)
    idx = json.loads(ws.repo.cat_file(f"{commit}:citation_index/index.json"))
    (claim_id, assertions), = idx["claims"].items()
    assert len({a["source_id"] for a in assertions}) == 2  # two independent sources
    # Page still shows the proposition once.
    wiki_paths = [p for p in ws.repo.ls_tree(commit) if p.startswith("wiki/")]
    page = ws.repo.cat_file(f"{commit}:{wiki_paths[0]}").decode()
    assert page.count("supports X") == 1
    ws.close()


# --- #3.10 unauthorized REVOKE from a raw source is quarantined ---------- #
def test_source_revoke_is_quarantined(tmp_path):
    ws = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("A | supports | X | positive | v=1\n")
    r1 = ws.ingest_and_publish(a)
    ptr = ws.cp.current_pointer()
    claim_id = ws.query("A").hits[0].claim_id if ws.query("A").hits else None
    rev = tmp_path / "rev.md"; rev.write_text(f"REVOKE | {claim_id}\n")
    r2 = ws.ingest_and_publish(rev)
    assert r2.quarantined is True
    assert ws.cp.current_pointer() == ptr           # pointer unchanged
    assert len(ws.query("A").hits) == 1             # claim survives
    ws.close()


# --- trusted admin revoke DOES retract ----------------------------------- #
def test_admin_revoke_retracts(tmp_path):
    ws = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("A | supports | X | positive | v=1\n")
    ws.ingest_and_publish(a)
    claim_id = ws.query("A").hits[0].claim_id
    res = ws.admin_revoke([claim_id], reason="test")
    assert not res.noop
    # after revoke, the claim is retracted in the current generation -> filtered
    assert ws.query("A").hits == []
    ws.close()


# --- #3.5 snapshot/file-allowlist binding -------------------------------- #
def test_extra_file_breaks_verification(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    from wiki_spike.claims import DeterministicMockExtractor
    claims = DeterministicMockExtractor().extract("A | b | C | positive | v=1\n", "s", "r").claims
    cand = builder.build_candidate(claims, None, "snap", "root")
    assert builder.verify_manifest(cand.commit_oid, cand.generation_id)
    # Add an unexpected file -> allowlist violation -> verification fails.
    paths = repo.ls_tree(cand.commit_oid)
    files = {p: repo.cat_file(f"{cand.commit_oid}:{p}") for p in paths}
    files["extra/rogue.txt"] = b"rogue"  # not in the allowlist
    tampered = repo.commit_tree(repo.write_tree_from_files(files), "tampered")
    assert builder.verify_manifest(tampered, cand.generation_id) is False


# --- #3.6 release manifest verification ---------------------------------- #
def test_release_manifest_verifies(tmp_path):
    repo, builder, cp, pub = _stack(tmp_path)
    from wiki_spike.claims import DeterministicMockExtractor
    claims = DeterministicMockExtractor().extract("A | b | C | positive | v=1\n", "s", "r").claims
    r = pub.publish(claims, "snap")
    assert builder.verify_release(r.release_commit_oid, r.generation_id)


# --- #3.17 output sanitization ------------------------------------------- #
def test_sanitize_escapes_markdown_and_html():
    out = sanitize("<script>alert(1)</script> **bold** [x](javascript:evil)")
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "**bold**" not in out  # asterisks escaped


def test_rendered_page_escapes_injection(tmp_path):
    from wiki_spike.assembler import render_pages
    from wiki_spike.claims import DeterministicMockExtractor
    # subject contains markdown/html that must be escaped in the page
    claims = DeterministicMockExtractor().extract(
        "<b>Inj</b> | supports | [x](javascript:e) | positive | v=1\n", "s", "r").claims
    pages = render_pages(claims)
    body = next(iter(pages.values())).decode()
    assert "<b>" not in body and "&lt;b&gt;" in body
