from __future__ import annotations

from dataclasses import replace
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core import (
    HistoricalKeyRegistry,
    HistoricalPublicKey,
    InvalidContractValue,
    KeyUsageDenied,
    KindDefinition,
    KindRegistrationError,
    KindRegistry,
    MigrationPathError,
    SchemaDefinition,
    SchemaRegistry,
    SchemaValidationError,
    UnknownKind,
    UnknownSchema,
    UnknownSigningKey,
    UnsupportedSchemaVersion,
    VersionedArtifact,
    signature_frame,
)


ROOT = Path(__file__).resolve().parents[2]


def load_fixture(name: str) -> VersionedArtifact:
    data = json.loads((ROOT / "tests/fixtures/phase3/schema" / name).read_text("utf-8"))
    return VersionedArtifact.from_mapping(data)


def validate_v1(payload):
    if set(payload) != {"title", "body"}:
        raise ValueError("v1 requires title/body")
    if not all(isinstance(payload[key], str) and payload[key] for key in payload):
        raise ValueError("v1 strings required")
    return dict(payload)


def validate_v2(payload):
    if set(payload) != {"title", "body", "importance"}:
        raise ValueError("v2 requires title/body/importance")
    if not all(isinstance(payload[key], str) and payload[key] for key in payload):
        raise ValueError("v2 strings required")
    if payload["importance"] not in {"0", "1", "2", "3", "4", "5"}:
        raise ValueError("invalid importance")
    return dict(payload)


def schema_registry(*, migration=True):
    registry = SchemaRegistry()
    v1 = load_fixture("note-v1.json")
    v2 = load_fixture("note-v2.json")
    registry.register(
        SchemaDefinition(
            "memory.note",
            "1",
            "1" * 64,
            True,
            False,
            v1.artifact_digest,
        ),
        validate_v1,
        fixture=v1,
    )
    registry.register(
        SchemaDefinition(
            "memory.note",
            "2",
            "2" * 64,
            True,
            True,
            v2.artifact_digest,
        ),
        validate_v2,
        fixture=v2,
    )
    if migration:
        registry.register_migration(
            "memory.note",
            "1",
            "2",
            lambda payload: {**payload, "importance": "0"},
        )
    return registry


def raw_public_key(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def key_record(
    key_id: str,
    private_key: Ed25519PrivateKey,
    *,
    purposes=("generation",),
    domains=("wiki.generation.v1",),
    valid_from="2026-01-01T00:00:00Z",
    valid_until=None,
    predecessor=None,
):
    return HistoricalPublicKey.create(
        key_id=key_id,
        public_key_bytes=raw_public_key(private_key),
        purposes=purposes,
        domains=domains,
        valid_from=valid_from,
        valid_until=valid_until,
        predecessor_key_id=predecessor,
    )


def test_old_fixture_canonical_bytes_are_stable():
    fixture = load_fixture("note-v1.json")
    assert fixture.canonical_bytes() == (
        b'{"artifact_schema_version":"phase3-schema-artifact-v1",'
        b'"payload":{"body":"Legacy body","title":"Legacy note"},'
        b'"schema_family":"memory.note","schema_version":"1"}'
    )
    assert len(fixture.artifact_digest) == 64


def test_read_old_upcasts_in_memory_and_write_uses_current_only():
    registry = schema_registry()
    old = registry.read_latest(load_fixture("note-v1.json"))
    assert old.schema_version == "2"
    assert old.payload == {
        "body": "Legacy body",
        "importance": "0",
        "title": "Legacy note",
    }
    written = registry.write(
        "memory.note",
        {"title": "New", "body": "Body", "importance": "5"},
    )
    assert written.schema_version == "2"
    assert registry.current_write_version("memory.note") == "2"


def test_old_fixture_is_not_mutated_by_read():
    registry = schema_registry()
    old = load_fixture("note-v1.json")
    before = old.canonical_bytes()
    upgraded = registry.read_latest(old)
    assert old.canonical_bytes() == before
    assert old.schema_version == "1"
    assert upgraded.schema_version == "2"


def test_unknown_family_and_version_fail_closed():
    registry = schema_registry()
    with pytest.raises(UnknownSchema):
        registry.read_latest(VersionedArtifact.create("unknown", "1", {"title": "x"}))
    with pytest.raises(UnsupportedSchemaVersion):
        registry.read_latest(
            VersionedArtifact.create("memory.note", "999", {"title": "x"})
        )


def test_missing_migration_path_fails_closed():
    registry = schema_registry(migration=False)
    with pytest.raises(MigrationPathError):
        registry.read_latest(load_fixture("note-v1.json"))


def test_validator_rejects_invalid_payload_and_raw_numbers():
    registry = schema_registry()
    with pytest.raises(SchemaValidationError):
        registry.write("memory.note", {"title": "x", "body": "y"})
    with pytest.raises(ValueError):
        VersionedArtifact.create(
            "memory.note",
            "2",
            {"title": "x", "body": "y", "importance": 1},
        )


def test_fixture_digest_mismatch_rejects_registration():
    fixture = load_fixture("note-v1.json")
    registry = SchemaRegistry()
    with pytest.raises(SchemaValidationError):
        registry.register(
            SchemaDefinition("memory.note", "1", "1" * 64, True, False, "0" * 64),
            validate_v1,
            fixture=fixture,
        )


def test_write_version_cannot_move_backwards():
    registry = schema_registry()
    with pytest.raises(SchemaValidationError):
        registry.set_write_version("memory.note", "1")


def test_schema_snapshot_is_deterministic_and_content_bound():
    first = schema_registry().snapshot()
    second = schema_registry().snapshot()
    assert first == second
    assert len(first["snapshot_digest"]) == 64
    body = {key: value for key, value in first.items() if key != "snapshot_digest"}
    from wiki_spike.memory_core import canonical_bytes
    from hashlib import sha256

    assert first["snapshot_digest"] == sha256(canonical_bytes(body)).hexdigest()


def test_builtin_and_namespaced_extension_kinds_are_registered():
    schemas = schema_registry()
    kinds = KindRegistry(schemas)
    note = KindDefinition.create(
        kind="note",
        schema_family="memory.note",
        schema_version="2",
        lifecycle_states=("active", "archived", "tombstoned"),
    )
    extension = KindDefinition.create(
        kind="crm.contact_note",
        schema_family="memory.note",
        schema_version="2",
        lifecycle_states=("active", "archived"),
    )
    kinds.register(note)
    kinds.register(extension)
    assert kinds.assert_creatable("note") == note
    assert kinds.resolve("crm.contact_note") == extension


def test_unregistered_and_unnamespaced_extension_kind_fail_closed():
    kinds = KindRegistry(schema_registry())
    with pytest.raises(UnknownKind):
        kinds.resolve("crm.unknown")
    with pytest.raises(KindRegistrationError):
        KindDefinition.create(
            kind="custom",
            schema_family="memory.note",
            schema_version="2",
            lifecycle_states=("active",),
        )


def test_creatable_kind_must_target_current_write_schema():
    kinds = KindRegistry(schema_registry())
    old_kind = KindDefinition.create(
        kind="crm.legacy_note",
        schema_family="memory.note",
        schema_version="1",
        lifecycle_states=("active",),
    )
    with pytest.raises(KindRegistrationError):
        kinds.register(old_kind)


def test_kind_collision_is_rejected_but_idempotent_reregister_is_allowed():
    kinds = KindRegistry(schema_registry())
    first = KindDefinition.create(
        kind="note",
        schema_family="memory.note",
        schema_version="2",
        lifecycle_states=("active", "archived"),
    )
    kinds.register(first)
    kinds.register(first)
    changed = KindDefinition.create(
        kind="note",
        schema_family="memory.note",
        schema_version="2",
        lifecycle_states=("active", "archived", "tombstoned"),
    )
    with pytest.raises(KindRegistrationError):
        kinds.register(changed)


def test_retired_kind_remains_readable_but_not_creatable():
    schemas = schema_registry()
    kinds = KindRegistry(schemas)
    definition = KindDefinition.create(
        kind="note",
        schema_family="memory.note",
        schema_version="2",
        lifecycle_states=("active", "archived"),
    )
    kinds.register(definition)
    kinds.retire("note")
    with pytest.raises(KindRegistrationError):
        kinds.assert_creatable("note")
    old = kinds.validate_artifact("note", load_fixture("note-v1.json"))
    assert old.schema_version == "2"


def test_kind_schema_family_mismatch_is_rejected():
    schemas = schema_registry()
    kinds = KindRegistry(schemas)
    kinds.register(
        KindDefinition.create(
            kind="note",
            schema_family="memory.note",
            schema_version="2",
            lifecycle_states=("active",),
        )
    )
    with pytest.raises(KindRegistrationError):
        kinds.validate_artifact(
            "note", VersionedArtifact.create("other", "1", {"title": "x"})
        )


def test_kind_snapshot_is_deterministic():
    schemas = schema_registry()
    first = KindRegistry(schemas)
    second = KindRegistry(schemas)
    definitions = [
        KindDefinition.create(
            kind="note",
            schema_family="memory.note",
            schema_version="2",
            lifecycle_states=("active",),
        ),
        KindDefinition.create(
            kind="crm.contact_note",
            schema_family="memory.note",
            schema_version="2",
            lifecycle_states=("active",),
        ),
    ]
    for item in definitions:
        first.register(item)
    for item in reversed(definitions):
        second.register(item)
    assert first.snapshot() == second.snapshot()


def test_key_record_is_content_bound_and_private_material_is_absent():
    private = Ed25519PrivateKey.generate()
    record = key_record("k1", private)
    assert len(record.record_id) == 64
    mapping = record.to_mapping()
    assert "private" not in json.dumps(mapping).lower()
    assert mapping["public_key_b64"]
    with pytest.raises(InvalidContractValue):
        replace(record, record_id="0" * 64)


def test_rotation_changes_active_key_but_old_signature_still_verifies():
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old = key_record("k1", old_private)
    new = key_record("k2", new_private, predecessor="k1")
    registry = HistoricalKeyRegistry()
    registry.register(old)
    registry.activate("k1", "generation", "wiki.generation.v1", at="2026-02-01T00:00:00Z")
    payload = b"generation-one"
    signature = old_private.sign(signature_frame("generation", "wiki.generation.v1", payload))

    registry.register(new)
    registry.activate("k2", "generation", "wiki.generation.v1", at="2026-03-01T00:00:00Z")
    assert registry.active_key_id("generation", "wiki.generation.v1") == "k2"
    assert registry.verify(
        key_id="k1",
        purpose="generation",
        domain="wiki.generation.v1",
        payload=payload,
        signature=signature,
        signed_at="2026-02-01T00:00:00Z",
    )
    assert registry.record("k1") == old


def test_wrong_domain_and_wrong_purpose_signatures_fail():
    private = Ed25519PrivateKey.generate()
    record = key_record(
        "k1",
        private,
        purposes=("generation", "release"),
        domains=("wiki.generation.v1", "wiki.release.v1"),
    )
    registry = HistoricalKeyRegistry()
    registry.register(record)
    payload = b"artifact"
    signature = private.sign(signature_frame("generation", "wiki.generation.v1", payload))
    assert registry.verify(
        key_id="k1",
        purpose="generation",
        domain="wiki.generation.v1",
        payload=payload,
        signature=signature,
        signed_at="2026-02-01T00:00:00Z",
    )
    assert not registry.verify(
        key_id="k1",
        purpose="release",
        domain="wiki.generation.v1",
        payload=payload,
        signature=signature,
        signed_at="2026-02-01T00:00:00Z",
    )
    assert not registry.verify(
        key_id="k1",
        purpose="generation",
        domain="wiki.release.v1",
        payload=payload,
        signature=signature,
        signed_at="2026-02-01T00:00:00Z",
    )


def test_key_usage_and_validity_are_fail_closed():
    private = Ed25519PrivateKey.generate()
    registry = HistoricalKeyRegistry()
    registry.register(
        key_record(
            "k1",
            private,
            valid_from="2026-02-01T00:00:00Z",
            valid_until="2026-03-01T00:00:00Z",
        )
    )
    with pytest.raises(KeyUsageDenied):
        registry.activate(
            "k1", "generation", "wiki.generation.v1", at="2026-01-01T00:00:00Z"
        )
    signature = private.sign(
        signature_frame("generation", "wiki.generation.v1", b"artifact")
    )
    assert not registry.verify(
        key_id="k1",
        purpose="generation",
        domain="wiki.generation.v1",
        payload=b"artifact",
        signature=signature,
        signed_at="2026-03-01T00:00:00Z",
    )
    assert not registry.verify(
        key_id="missing",
        purpose="generation",
        domain="wiki.generation.v1",
        payload=b"artifact",
        signature=signature,
        signed_at="2026-02-15T00:00:00Z",
    )


def test_unknown_predecessor_and_duplicate_key_id_are_rejected():
    private = Ed25519PrivateKey.generate()
    registry = HistoricalKeyRegistry()
    with pytest.raises(UnknownSigningKey):
        registry.register(key_record("k2", private, predecessor="missing"))
    first = key_record("k1", private)
    registry.register(first)
    registry.register(first)
    different = key_record("k1", Ed25519PrivateKey.generate())
    with pytest.raises(InvalidContractValue):
        registry.register(different)


def test_key_snapshot_is_deterministic_and_keeps_historical_records():
    old_private = Ed25519PrivateKey.generate()
    new_private = Ed25519PrivateKey.generate()
    old = key_record("k1", old_private)
    new = key_record("k2", new_private, predecessor="k1")
    first = HistoricalKeyRegistry()
    first.register(old)
    first.register(new)
    first.activate("k2", "generation", "wiki.generation.v1", at="2026-03-01T00:00:00Z")
    snapshot = first.snapshot()
    assert [item["key_id"] for item in snapshot["keys"]] == ["k1", "k2"]
    assert snapshot["active"] == [
        {"purpose": "generation", "domain": "wiki.generation.v1", "key_id": "k2"}
    ]
    assert len(snapshot["snapshot_digest"]) == 64


def test_public_core_import_stays_storage_independent():
    import subprocess
    import sys

    code = """
import sys
import wiki_spike.memory_core
forbidden = {'wiki_spike.cas','wiki_spike.controlplane','wiki_spike.generation','wiki_spike.publish','wiki_spike.workspace','wiki_spike.signing'}
loaded = forbidden.intersection(sys.modules)
assert not loaded, loaded
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "src")
    subprocess.run([sys.executable, "-c", code], check=True, env=env)


def test_registry_contract_schema_is_strict():
    schema = json.loads(
        (ROOT / "schemas/phase3/registry-contracts.schema.json").read_text("utf-8")
    )
    for name in ("versionedArtifact", "schemaDefinition", "kindDefinition", "historicalPublicKey"):
        assert schema["$defs"][name]["additionalProperties"] is False


def test_adversarial_report_contains_exactly_20_rounds():
    import re

    text = (ROOT / "docs/adversarial/P3-09_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))
