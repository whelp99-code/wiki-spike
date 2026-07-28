from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from wiki_spike.memory_core.second_brain_capture_contracts import (
    CaptureItemReceiptV1, CaptureReconciliationV1, CaptureScanManifestV1,
    MigrationRegistrationV1, NonServingCaptureCohortV1, ReconciledCheckpointAdvanceV1,
    ScanCheckpointV1, SourceScopeRefV1,
)

REF = lambda key: key + ":" + "a" * 64
DIGEST = "b" * 64
SCHEMA = Draft202012Validator(json.loads((Path(__file__).resolve().parents[2] / "schemas" / "second-brain" / "source-capture-v1.schema.json").read_text()))


def scope(**changes):
    value = {"scope_version": "second-brain-source-scope-ref-v1", "source_profile": "Codex", "source_domain": "codex", "source_ref": REF("codex-source"), "workspace_ref": REF("workspace"), "scope_ref": REF("codex-scope"), "scope_epoch": "1"}
    value.update(changes)
    return value


def receipt(**changes):
    value = {"receipt_version": "second-brain-capture-item-receipt-v1", "scope": scope(), "scan_epoch": "1", "capture_ref": REF("capture"), "ciphertext_digest": DIGEST, "disposition": "ACCEPTED"}
    value.update(changes)
    return value


def reconciliation(**changes):
    value = {"reconciliation_version": "second-brain-capture-reconciliation-v1", "scope": scope(), "scan_epoch": "1", "manifest_ref": REF("manifest"), "reconciliation_ref": REF("reconciliation"), "reconciliation_epoch": "1", "completion": "COMPLETE", "outcome": "RECONCILED", "expected_receipt_count": "2", "accounted_receipt_count": "2", "disposition_counts": {"ACCEPTED": "1", "DUPLICATE": "1", "TOMBSTONE": "0", "SKIPPED": "0", "QUARANTINED": "0"}, "reconciliation_digest": DIGEST}
    value.update(changes)
    return value


def checkpoint(**changes):
    value = {"checkpoint_version": "second-brain-scan-checkpoint-v1", "scope": scope(), "scan_epoch": "1", "checkpoint_ref": REF("checkpoint"), "checkpoint_digest": DIGEST, "manifest_ref": REF("manifest"), "reconciliation_ref": REF("reconciliation"), "reconciliation_digest": DIGEST, "reconciliation_epoch": "1", "reconciliation_completion": "COMPLETE", "reconciliation_outcome": "RECONCILED"}
    value.update(changes)
    return value


def manifest(**changes):
    value = {"manifest_version": "second-brain-capture-scan-manifest-v1", "scope": scope(), "scan_epoch": "1", "checkpoint_ref": REF("checkpoint"), "receipt_refs": [REF("capture")], "manifest_ref": REF("manifest"), "manifest_digest": DIGEST}
    value.update(changes)
    return value


def migration(**changes):
    value = {"registration_version": "second-brain-migration-registration-v1", "migration_source": "unified-db", "migration_ref": REF("unified-db-migration"), "migration_scope_ref": REF("unified-db-migration-scope"), "scope": scope(), "migration_epoch": "1", "registration_ref": REF("migration-registration"), "ciphertext_digest": DIGEST}
    value.update(changes)
    return value


def cohort(**changes):
    value = {"cohort_version": "second-brain-non-serving-capture-cohort-v1", "cohort_ref": REF("cohort"), "final_workspace_ref": REF("workspace"), "state": "NON_SERVING", "source_roster": [{"source_domain": "codex", "source_ref": REF("codex-source"), "registration_ref": REF("migration-registration"), "scope_ref": REF("codex-scope"), "manifest_ref": REF("manifest"), "ownership_binding": {"workspace_ref": REF("workspace"), "source_ref": REF("codex-source"), "registration_ref": REF("migration-registration"), "scope_ref": REF("codex-scope"), "manifest_ref": REF("manifest")}}], "cohort_digest": DIGEST}
    value.update(changes)
    return value


def runtime_valid(parser, value):
    try:
        parser.from_mapping(value)
    except (InvalidContractValue, UnknownContractField, UnsupportedContractVersion):
        return False
    return True


@pytest.mark.parametrize(("parser", "value"), [
    (SourceScopeRefV1, scope()), (ScanCheckpointV1, checkpoint()),
    (CaptureItemReceiptV1, receipt()), (CaptureScanManifestV1, manifest()),
    (CaptureReconciliationV1, reconciliation()), (MigrationRegistrationV1, migration()),
    (NonServingCaptureCohortV1, cohort()),
])
def test_all_seven_wire_contracts_accept_the_same_valid_fixture(parser, value):
    assert not list(SCHEMA.iter_errors(value))
    assert parser.from_mapping(value).to_mapping() == value


@pytest.mark.parametrize(("parser", "value"), [
    (SourceScopeRefV1, scope(source_domain="git")),
    (ScanCheckpointV1, checkpoint(reconciliation_completion="INCOMPLETE")),
    (CaptureItemReceiptV1, receipt(disposition="RAW")),
    (CaptureScanManifestV1, manifest(checkpoint_ref=REF("manifest"))),
    (CaptureReconciliationV1, reconciliation(completion="PARTIAL")),
    (MigrationRegistrationV1, migration(migration_source="unknown")),
    (NonServingCaptureCohortV1, cohort(state="SERVING")),
])
def test_all_seven_wire_contracts_reject_closed_invalid_values(parser, value):
    assert list(SCHEMA.iter_errors(value))
    assert not runtime_valid(parser, value)


@pytest.mark.parametrize("forbidden", ["native_id", "path", "revision", "cursor", "body", "locator", "label", "url", "credential", "activation", "gate8"])
@pytest.mark.parametrize(("parser", "factory"), [
    (SourceScopeRefV1, scope), (ScanCheckpointV1, checkpoint), (CaptureItemReceiptV1, receipt),
    (CaptureScanManifestV1, manifest), (CaptureReconciliationV1, reconciliation),
    (MigrationRegistrationV1, migration), (NonServingCaptureCohortV1, cohort),
])
def test_all_durable_wire_contracts_deny_raw_and_activation_fields(parser, factory, forbidden):
    candidate = factory(**{forbidden: "raw-source-value"})
    assert list(SCHEMA.iter_errors(candidate))
    assert not runtime_valid(parser, candidate)


@pytest.mark.parametrize(("profile", "domain"), [("Claude/Memory Bank", "claude-memory-bank"), ("Git", "git"), ("Markdown", "markdown")])
def test_source_scope_accepts_each_closed_profile_with_its_typed_domain(profile, domain):
    candidate = scope(source_profile=profile, source_domain=domain, source_ref=REF(f"{domain}-source"), scope_ref=REF(f"{domain}-scope"))
    assert not list(SCHEMA.iter_errors(candidate))
    assert runtime_valid(SourceScopeRefV1, candidate)


@pytest.mark.parametrize("changes", [
    {"source_domain": "git"}, {"source_ref": REF("git-source")}, {"scope_ref": REF("git-scope")}, {"workspace_ref": REF("project")},
])
def test_source_scope_rejects_cross_domain_and_workspace_substitution(changes):
    candidate = scope(**changes)
    assert list(SCHEMA.iter_errors(candidate))
    assert not runtime_valid(SourceScopeRefV1, candidate)


@pytest.mark.parametrize("changes", [
    {"reconciliation_epoch": "2"}, {"completion": "INCOMPLETE"}, {"outcome": "FAILED"},
    {"expected_receipt_count": "3"}, {"accounted_receipt_count": "1"},
    {"disposition_counts": {"ACCEPTED": "1", "DUPLICATE": "0", "TOMBSTONE": "0", "SKIPPED": "0", "QUARANTINED": "0"}},
])
def test_reconciliation_rejects_incomplete_failed_or_unaccounted_epochs(changes):
    candidate = reconciliation(**changes)
    assert not runtime_valid(CaptureReconciliationV1, candidate)


@pytest.mark.parametrize(("changes", "schema_rejects"), [
    ({"reconciliation_epoch": "2"}, False),
    ({"reconciliation_completion": "INCOMPLETE"}, True),
    ({"reconciliation_outcome": "FAILED"}, True),
])
def test_checkpoint_advancement_requires_complete_reconciled_matching_epoch(changes, schema_rejects):
    candidate = checkpoint(**changes)
    assert bool(list(SCHEMA.iter_errors(candidate))) is schema_rejects
    assert not runtime_valid(ScanCheckpointV1, candidate)


@pytest.mark.parametrize(("source", "domain"), [("legacy Mem0/RAG", "legacy-mem0-rag"), ("me-wiki", "me-wiki")])
def test_migration_requires_exact_source_identity_and_migration_scope(source, domain):
    candidate = migration(migration_source=source, migration_ref=REF(f"{domain}-migration"), migration_scope_ref=REF(f"{domain}-migration-scope"))
    assert not list(SCHEMA.iter_errors(candidate))
    assert runtime_valid(MigrationRegistrationV1, candidate)
    substituted = dict(candidate, migration_scope_ref=REF("unified-db-migration-scope"))
    assert list(SCHEMA.iter_errors(substituted))
    assert not runtime_valid(MigrationRegistrationV1, substituted)


def test_non_serving_cohort_binds_final_workspace_and_exact_unique_roster():
    assert runtime_valid(NonServingCaptureCohortV1, cohort())
    wrong_workspace = cohort(final_workspace_ref=REF("project"))
    duplicate_registration = cohort(source_roster=[cohort()["source_roster"][0], {"source_domain": "git", "source_ref": REF("git-source"), "registration_ref": REF("migration-registration"), "scope_ref": REF("git-scope"), "manifest_ref": REF("manifest-2")}])
    for candidate in (wrong_workspace, duplicate_registration):
        assert not runtime_valid(NonServingCaptureCohortV1, candidate)
    assert list(SCHEMA.iter_errors(wrong_workspace))
def advance(**changes):
    value = {"advance_version": "second-brain-reconciled-checkpoint-advance-v1", "previous_checkpoint_ref": None, "reconciliation": reconciliation(), "checkpoint": checkpoint()}
    value.update(changes)
    return value


def test_checkpoint_advance_authoritatively_correlates_reconciliation():
    candidate = advance()
    assert not list(SCHEMA.iter_errors(candidate))
    assert ReconciledCheckpointAdvanceV1.from_mapping(candidate).to_mapping() == candidate
    for field, value in (("scope", scope(scope_epoch="2")), ("manifest_ref", REF("manifest-other")), ("reconciliation_ref", REF("reconciliation-other")), ("reconciliation_digest", "c" * 64), ("scan_epoch", "2")):
        assert not runtime_valid(ReconciledCheckpointAdvanceV1, advance(checkpoint=checkpoint(**{field: value})))


def test_cohort_ownership_binding_rejects_same_kind_substitutions():
    binding = dict(cohort()["source_roster"][0]["ownership_binding"])
    for field, value in (("workspace_ref", REF("workspace-other")), ("source_ref", REF("codex-source-other")), ("registration_ref", REF("migration-registration-other")), ("manifest_ref", REF("manifest-other"))):
        candidate = cohort(source_roster=[dict(cohort()["source_roster"][0], ownership_binding=dict(binding, **{field: value}))])
        assert not runtime_valid(NonServingCaptureCohortV1, candidate)


def test_reconciliation_counts_are_deeply_immutable_and_serialized_by_copy():
    parsed = CaptureReconciliationV1.from_mapping(reconciliation())
    with pytest.raises(TypeError):
        parsed.disposition_counts["ACCEPTED"] = "9"
    serialized = parsed.to_mapping()
    serialized["disposition_counts"]["ACCEPTED"] = "9"
    assert parsed.disposition_counts["ACCEPTED"] == "1"


@pytest.mark.parametrize(("parser", "factory", "field"), [
    (SourceScopeRefV1, scope, "source_profile"),
    (CaptureItemReceiptV1, receipt, "disposition"),
    (MigrationRegistrationV1, migration, "migration_source"),
    (NonServingCaptureCohortV1, cohort, "state"),
])
@pytest.mark.parametrize("malformed", [[], {}, 1])
def test_non_string_closed_values_raise_invalid_contract_value(parser, factory, field, malformed):
    with pytest.raises(InvalidContractValue):
        parser.from_mapping(factory(**{field: malformed}))


def test_package_exports_connector_reader_and_native_mapping_sealer():
    from wiki_spike.memory_core import ConnectorSourceReaderPort, EncryptedNativeMappingSealerPort

    assert ConnectorSourceReaderPort.__name__ == "ConnectorSourceReaderPort"
    assert EncryptedNativeMappingSealerPort.__name__ == "EncryptedNativeMappingSealerPort"
def test_cohort_rejects_duplicate_source_with_distinct_registration():
    first = cohort()["source_roster"][0]
    second = dict(first, registration_ref=REF("migration-registration-other"), ownership_binding=dict(first["ownership_binding"], registration_ref=REF("migration-registration-other")))
    assert not runtime_valid(NonServingCaptureCohortV1, cohort(source_roster=[first, second]))
