from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.check_architecture_boundaries import lint_boundaries
from wiki_spike.composition.second_brain_capture import CaptureCompositionError, compose_non_serving_fixture_capture
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.second_brain_capture_contracts import SourceScopeRefV1

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "second_brain" / "capture"
PROFILES = ("Codex", "Claude/Memory Bank", "Git", "Markdown")
DEK = bytes(range(32))


def ref(kind: str, value: str) -> str:
    return f"{kind}:{sha256(value.encode()).hexdigest()}"


def resolved_scope() -> SourceScopeRefV1:
    return SourceScopeRefV1.from_mapping({"scope_version": "second-brain-source-scope-ref-v1", "source_profile": "Codex", "source_domain": "codex", "source_ref": ref("codex-source", "scope"), "workspace_ref": ref("workspace", "stage2"), "scope_ref": ref("codex-scope", "scope"), "scope_epoch": "1"})


def test_moved_non_serving_composition_wires_four_fixture_sources_without_activation_or_serving(tmp_path: Path):
    request_refs = {profile: [ref("fixture-request", profile)] for profile in PROFILES}
    payloads = {request_refs[profile][0]: json.dumps(json.loads((FIXTURES / name).read_text()), sort_keys=True).encode() for profile, name in zip(PROFILES, ("codex.json", "claude_memory_bank.json", "git.json", "markdown.json"))}
    database = LifecycleDatabase(tmp_path / "fixture.sqlite", fixture_capture_mode=True)
    database.initialize()
    composition = compose_non_serving_fixture_capture(database=database, cas=EncryptedContentStore(tmp_path / "cas"), encryption_key=DEK, fixture_clients=FixtureCaptureClients(payloads=payloads), fixture_request_refs=request_refs, read_only_migration_capabilities={})
    assert tuple(composition.connectors) == PROFILES
    assert not hasattr(composition, "activate") and not hasattr(composition, "serve")
    database.close()


def test_fixture_composition_rejects_production_database_and_scope_unbound_capability(tmp_path: Path):
    production = LifecycleDatabase(tmp_path / "production.sqlite")
    production.initialize()
    clients = FixtureCaptureClients()
    kwargs = dict(cas=EncryptedContentStore(tmp_path / "cas"), encryption_key=DEK, fixture_clients=clients, fixture_request_refs={profile: [ref("fixture-request", profile)] for profile in PROFILES}, read_only_migration_capabilities={})
    with pytest.raises(CaptureCompositionError, match="synthetic database"):
        compose_non_serving_fixture_capture(database=production, **kwargs)
    capability = clients.issue_read_only_migration_capability(ref("unified-db-migration", "one"), resolved_scope())
    with pytest.raises(Exception, match="scope"):
        clients.verify_read_only_migration_capability(capability, ref("unified-db-migration", "one"), SourceScopeRefV1.from_mapping({**resolved_scope().to_mapping(), "scope_epoch": "2"}))
    production.close()


def test_architecture_checker_has_one_rule_per_stage2_boundary(tmp_path: Path):
    repo = tmp_path / "repo"
    for package in ("applications", "connectors", "composition", "memory_core"):
        (repo / "src/wiki_spike" / package).mkdir(parents=True, exist_ok=True)
    config = Path(__file__).resolve().parents[2] / "architecture-boundaries.json"
    (repo / "architecture-boundaries.json").write_text(config.read_text())
    (repo / "src/wiki_spike/applications/fixture_capture_service.py").write_text("import wiki_spike.infrastructure.lifecycle_db\n")
    (repo / "src/wiki_spike/connectors/bad.py").write_text("import wiki_spike.infrastructure.encrypted_cas\n")
    (repo / "src/wiki_spike/composition/second_brain_capture.py").write_text("import wiki_spike.memory_runtime.orchestrator\n")
    found = lint_boundaries(repo, repo / "architecture-boundaries.json")
    assert [(item.path, item.imported_module) for item in found] == [
        ("src/wiki_spike/applications/fixture_capture_service.py", "wiki_spike.infrastructure.lifecycle_db"),
        ("src/wiki_spike/composition/second_brain_capture.py", "wiki_spike.memory_runtime.orchestrator"),
        ("src/wiki_spike/connectors/bad.py", "wiki_spike.infrastructure.encrypted_cas"),
    ]
