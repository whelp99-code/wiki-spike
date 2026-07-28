from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest

from scripts.check_architecture_boundaries import lint_boundaries
from wiki_spike.composition.second_brain_capture import CaptureCompositionError, compose_non_serving_fixture_capture
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients, FixtureCaptureClientError, FixtureEncryptedContentSealer, FixtureNativeMappingSealer
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, fixture_capture_database
from wiki_spike.memory_core.second_brain_capture_contracts import SourceScopeRefV1, canonical_identity_body_digest

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
    database = fixture_capture_database(tmp_path / "fixture.sqlite")
    database.initialize()
    clients = FixtureCaptureClients(payloads=payloads)
    capability = clients.issue_read_only_migration_capability(ref("unified-db-migration", "one"), resolved_scope())
    identity = canonical_identity_body_digest("migration-registration-identity-v1", {"migration_ref": capability.migration_ref, "scope": resolved_scope().to_mapping()})
    composition = compose_non_serving_fixture_capture(database=database, cas=EncryptedContentStore(tmp_path / "cas"), encryption_key=DEK, fixture_clients=clients, fixture_request_refs=request_refs, migration_capability_registry={identity: capability})
    assert tuple(composition.connectors) == PROFILES
    assert not hasattr(composition, "activate") and not hasattr(composition, "serve")
    assert tuple(composition.capture_service.capture.__annotations__) == ("aggregate", "reader", "return")
    database.close()


def test_fixture_composition_rejects_production_database_and_scope_unbound_capability(tmp_path: Path):
    production = LifecycleDatabase(tmp_path / "production.sqlite")
    production.initialize()
    clients = FixtureCaptureClients()
    kwargs = dict(cas=EncryptedContentStore(tmp_path / "cas"), encryption_key=DEK, fixture_clients=clients, fixture_request_refs={profile: [ref("fixture-request", profile)] for profile in PROFILES}, migration_capability_registry={})
    with pytest.raises(CaptureCompositionError, match="synthetic database"):
        compose_non_serving_fixture_capture(database=production, **kwargs)
    capability = clients.issue_read_only_migration_capability(ref("unified-db-migration", "one"), resolved_scope())
    with pytest.raises(Exception, match="scope"):
        clients.verify_read_only_migration_capability(capability, ref("unified-db-migration", "one"), SourceScopeRefV1.from_mapping({**resolved_scope().to_mapping(), "scope_epoch": "2"}))
    for field, replacement in {
        "workspace_ref": ref("workspace", "substituted"),
        "source_ref": ref("codex-source", "substituted"),
        "scope_ref": ref("codex-scope", "substituted"),
        "scope_epoch": "2",
    }.items():
        with pytest.raises(FixtureCaptureClientError):
            clients.verify_read_only_migration_capability(
                capability,
                ref("unified-db-migration", "one"),
                SourceScopeRefV1.from_mapping({**resolved_scope().to_mapping(), field: replacement}),
            )
    substituted_source = SourceScopeRefV1.from_mapping({
        **resolved_scope().to_mapping(),
        "source_profile": "Git",
        "source_domain": "git",
        "source_ref": ref("git-source", "substituted"),
        "scope_ref": ref("git-scope", "substituted"),
    })
    with pytest.raises(FixtureCaptureClientError):
        clients.verify_read_only_migration_capability(
            capability,
            ref("unified-db-migration", "one"),
            substituted_source,
        )
    with pytest.raises(FixtureCaptureClientError):
        clients.verify_read_only_migration_capability(
            capability, ref("unified-db-migration", "substituted"), resolved_scope()
        )
    synthetic = fixture_capture_database(tmp_path / "fixture.sqlite")
    synthetic.initialize()
    with pytest.raises(CaptureCompositionError, match="registry key"):
        compose_non_serving_fixture_capture(database=synthetic, cas=EncryptedContentStore(tmp_path / "synthetic-cas"), encryption_key=DEK, fixture_clients=clients, fixture_request_refs=kwargs["fixture_request_refs"], migration_capability_registry={ref("registration", "wrong"): capability})
    synthetic.close()
    production.close()


def test_content_and_mapping_sealers_bind_actual_cas_output_and_reject_substitution_or_changed_evidence(tmp_path: Path):
    database = fixture_capture_database(tmp_path / "fixture.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    scope = resolved_scope()
    capture_ref = ref("capture", "one")
    content = FixtureEncryptedContentSealer(database, cas, DEK)
    mapping = FixtureNativeMappingSealer(database, cas, DEK)
    sealed_content = content.seal_content(scope, capture_ref, b"ciphertext")
    sealed_mapping = mapping.seal_native_mapping(scope, capture_ref, b'{"native":"one"}')
    assert sealed_content.encrypted_content_ref.startswith("encrypted-content:")
    assert sealed_mapping.encrypted_native_mapping_ref.startswith("encrypted-native-mapping:")
    bindings = database.con.execute(
        "SELECT evidence_kind, identity_ref, cas_locator_ref FROM capture_identity_binding "
        "WHERE capture_ref=? ORDER BY evidence_kind",
        (capture_ref,),
    ).fetchall()
    assert bindings == [
        ("content", sealed_content.encrypted_content_ref, bindings[0][2]),
        ("native-mapping", sealed_mapping.encrypted_native_mapping_ref, bindings[1][2]),
    ]
    assert all(cas.exists(locator.removeprefix("encrypted-cas:")) for _, _, locator in bindings)
    assert len(tuple(cas.objects.iterdir())) == 2
    assert content.seal_content(scope, capture_ref, b"ciphertext") == sealed_content
    assert mapping.seal_native_mapping(scope, capture_ref, b'{"native":"one"}') == sealed_mapping
    assert len(tuple(cas.objects.iterdir())) == 2
    with pytest.raises(FixtureCaptureClientError, match="different sealed evidence"):
        content.seal_content(scope, capture_ref, b"changed-ciphertext")
    with pytest.raises(FixtureCaptureClientError, match="different sealed evidence"):
        mapping.seal_native_mapping(scope, capture_ref, b'{"native":"changed"}')
    assert len(tuple(cas.objects.iterdir())) == 2
    database.close()

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
