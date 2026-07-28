from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.check_architecture_boundaries import lint_boundaries
from wiki_spike.applications.capture_composition import (
    CaptureCompositionError,
    compose_non_serving_fixture_capture,
)
from wiki_spike.connectors import (
    ClaudeMemoryBankFixtureConnector,
    CodexFixtureConnector,
    GitFixtureConnector,
    MarkdownFixtureConnector,
)
from wiki_spike.infrastructure.fixture_capture_clients import (
    FixtureCaptureClients,
    FixtureNativeMappingSealer,
)
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "second_brain" / "capture"
PROFILES = {
    "Codex": ("codex.json", CodexFixtureConnector),
    "Claude/Memory Bank": ("claude_memory_bank.json", ClaudeMemoryBankFixtureConnector),
    "Git": ("git.json", GitFixtureConnector),
    "Markdown": ("markdown.json", MarkdownFixtureConnector),
}


def ref(label: str) -> str:
    return "fixture-request:" + sha256(label.encode("ascii")).hexdigest()


def test_composition_wires_exactly_four_fixture_sources_and_no_runtime_entrypoint(tmp_path: Path):
    payloads = {}
    request_refs = {}
    for profile, (fixture_name, _) in PROFILES.items():
        request_ref = ref(profile)
        payloads[request_ref] = json.dumps(json.loads((FIXTURES / fixture_name).read_text()), sort_keys=True).encode()
        request_refs[profile] = [request_ref]
    database = LifecycleDatabase(tmp_path / "fixture.sqlite")
    database.initialize()

    composition = compose_non_serving_fixture_capture(
        database=database,
        fixture_clients=FixtureCaptureClients(payloads=payloads),
        native_mapping_sealer=FixtureNativeMappingSealer(),
        fixture_request_refs=request_refs,
        read_only_migration_capabilities={},
    )

    assert {name: type(connector) for name, connector in composition.connectors.items()} == {
        name: connector_type for name, (_, connector_type) in PROFILES.items()
    }
    assert not hasattr(composition, "activate")
    assert not hasattr(composition, "serve")
    database.close()


def test_migration_capability_registry_is_read_only_and_client_gated(tmp_path: Path):
    database = LifecycleDatabase(tmp_path / "fixture.sqlite")
    database.initialize()
    migration_ref = "migration:" + sha256(b"readonly").hexdigest()
    clients = FixtureCaptureClients()
    capability = clients.issue_read_only_migration_capability(migration_ref)

    composition = compose_non_serving_fixture_capture(
        database=database,
        fixture_clients=clients,
        native_mapping_sealer=FixtureNativeMappingSealer(),
        fixture_request_refs={profile: [ref(profile)] for profile in PROFILES},
        read_only_migration_capabilities={migration_ref: capability},
    )

    assert composition.read_only_migration_capabilities[migration_ref] is capability
    with pytest.raises(TypeError):
        composition.read_only_migration_capabilities[migration_ref] = capability  # type: ignore[index]
    with pytest.raises(CaptureCompositionError, match="four Stage-2 source profiles"):
        compose_non_serving_fixture_capture(
            database=database,
            fixture_clients=clients,
            native_mapping_sealer=FixtureNativeMappingSealer(),
            fixture_request_refs={},
            read_only_migration_capabilities={},
        )
    database.close()


def test_architecture_checker_rejects_stage2_ownership_and_gate8_imports(tmp_path: Path):
    repo = tmp_path / "repo"
    (repo / "src/wiki_spike/connectors").mkdir(parents=True)
    (repo / "src/wiki_spike/memory_core").mkdir(parents=True)
    (repo / "src/wiki_spike/applications").mkdir(parents=True)
    config = Path(__file__).resolve().parents[2] / "architecture-boundaries.json"
    (repo / "architecture-boundaries.json").write_text(config.read_text())
    (repo / "src/wiki_spike/connectors/forbidden.py").write_text("import wiki_spike.infrastructure.lifecycle_db\n")
    (repo / "src/wiki_spike/memory_core/forbidden.py").write_text("import wiki_spike.infrastructure.lifecycle_db\n")
    (repo / "src/wiki_spike/applications/capture_composition.py").write_text("import wiki_spike.memory_runtime.orchestrator\n")

    found = lint_boundaries(repo, repo / "architecture-boundaries.json")

    assert {violation.imported_module for violation in found} == {
        "wiki_spike.infrastructure.lifecycle_db",
        "wiki_spike.memory_runtime.orchestrator",
    }
