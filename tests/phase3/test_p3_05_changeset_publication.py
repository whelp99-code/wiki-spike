from __future__ import annotations

from dataclasses import replace

from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.controlplane import ControlPlane
from wiki_spike.generation import GenerationBuilder
from wiki_spike.gitrepo import GitRepo
from wiki_spike.memory_core.changeset_publication import (
    ChangeSetBuilder,
    InMemoryChangeObjectStore,
    StoragePublicationAdapter,
)
from wiki_spike.publish import PublishService
from wiki_spike.signing import Keyring


def make_stack(tmp_path):
    repo = GitRepo.init_bare(tmp_path / "repo.git")
    keys = Keyring()
    keys.generate("k1")
    cp = ControlPlane(tmp_path / "control.sqlite")
    publisher = PublishService(GenerationBuilder(repo, keys, "k1"), cp)
    store = InMemoryChangeObjectStore()
    return cp, publisher, store, StoragePublicationAdapter(publisher, store)


def claim(text="Product A | supports | feature X | positive | version=1"):
    return DeterministicMockExtractor().extract(text, "s" * 64, "r" * 64).claims[0]


def changeset(store, *, parent=None, workspace="ws-1", value=None):
    item = store.add(workspace, value or claim())
    return ChangeSetBuilder.build(
        workspace_id=workspace,
        parent_generation_id=parent,
        command_ids=("cmd-1",),
        objects=(item,),
    )


def test_prepare_does_not_move_publication_pointer(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    prepared = adapter.prepare(cs)
    assert cp.current_pointer() is None
    assert prepared.publication.candidate is not None
    assert cp.generation_state(prepared.publication.candidate.generation_id) == "read_models_ready"


def test_signed_generation_binds_exact_changeset(tmp_path):
    cp, publisher, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    result = adapter.publish(cs)
    assert result.status == "ok"
    commit = cp.generation_commit(result.generation_id)
    assert commit is not None
    assert publisher.builder.verify_manifest(commit, result.generation_id)
    descriptor = __import__("json").loads(
        publisher.builder.repo.cat_file(f"{commit}:manifest/{result.generation_id}.json")
    )["descriptor"]
    assert descriptor["accepted_changeset"]["changeset_id"] == cs.changeset_id
    assert descriptor["accepted_changeset"]["changes_root"] == cs.changes_root


def test_root_mismatch_is_rejected_before_prepare(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = replace(changeset(store), changes_root="0" * 64)
    result = adapter.publish(cs)
    assert result.status == "rejected"
    assert result.error_code == "changeset_root_mismatch"
    assert cp.current_pointer() is None
    assert cp.orphan_generations() == []


def test_partial_changeset_missing_object_is_rejected(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    del store._objects[(cs.workspace_id, cs.object_refs[0])]
    result = adapter.publish(cs)
    assert result.status == "rejected"
    assert result.error_code == "changeset_incomplete"
    assert cp.current_pointer() is None


def test_stale_parent_is_retry_later_without_rebase(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    first = changeset(store)
    first_result = adapter.publish(first)
    stale = changeset(store, parent=None, value=claim("Product B | supports | Y | positive | version=1"))
    result = adapter.publish(stale)
    assert result.status == "retry_later"
    assert result.error_code == "stale_generation"
    assert cp.current_pointer() == first_result.generation_id


def test_crash_after_activation_is_repaired_idempotently(tmp_path):
    cp, publisher, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    prepared = adapter.prepare(cs)
    p = prepared.publication
    assert p.candidate is not None and p.release_commit_oid is not None
    cp.activate(p.candidate.generation_id, p.parent_generation_id, p.release_commit_oid)
    assert cp.current_pointer() == p.candidate.generation_id
    assert cp.current_search_pointer() is None
    result = adapter.activate(prepared)
    assert result.status == "ok"
    assert cp.current_search_pointer() == p.candidate.generation_id
    assert cp.accepted_claims(p.candidate.generation_id)


def test_same_changeset_replay_returns_same_generation(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    first = adapter.publish(cs)
    second = adapter.publish(cs)
    assert second.status == "ok"
    assert second.generation_id == first.generation_id
    assert second.result["replayed"] is True
    assert cp.current_pointer() == first.generation_id


def test_revision_content_mismatch_is_rejected(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    item = store.resolve(cs.workspace_id, cs.object_refs[0])
    store._objects[(cs.workspace_id, cs.object_refs[0])] = replace(item, revision_hash="f" * 64)
    result = adapter.publish(cs)
    assert result.status == "rejected"
    assert result.error_code == "changeset_binding_mismatch"
    assert cp.current_pointer() is None


def test_pointer_move_between_prepare_and_activate_is_not_rebased(tmp_path):
    cp, publisher, store, adapter = make_stack(tmp_path)
    cs = changeset(store)
    prepared = adapter.prepare(cs)

    other_claim = claim("Product Z | supports | other | positive | version=1")
    publisher.publish([other_claim], "other-source")
    current = cp.current_pointer()

    result = adapter.activate(prepared)
    assert result.status == "retry_later"
    assert result.error_code == "stale_generation"
    assert cp.current_pointer() == current


def test_prepare_rejects_tampered_changeset_id(tmp_path):
    cp, _, store, adapter = make_stack(tmp_path)
    cs = replace(changeset(store), changeset_id="a" * 64)
    result = adapter.publish(cs)
    assert result.status == "rejected"
    assert result.error_code == "changeset_binding_mismatch"
    assert cp.current_pointer() is None


def test_contract_schema_includes_strict_accepted_changeset():
    import json
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    schema = json.loads((root / "schemas/phase3/core-contracts.schema.json").read_text("utf-8"))
    definition = schema["$defs"]["acceptedChangeSet"]
    assert definition["additionalProperties"] is False
    assert set(definition["required"]) == {
        "contract_version", "changeset_id", "workspace_id", "parent_generation_id",
        "command_ids", "object_refs", "changes_root",
    }
    assert {item["$ref"] for item in schema["oneOf"]} >= {"#/$defs/acceptedChangeSet"}


def test_adversarial_report_contains_exactly_20_rounds():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/adversarial/P3-05_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))
