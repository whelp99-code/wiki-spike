from __future__ import annotations

import base64
import json
from copy import deepcopy
from hashlib import sha256

import pytest

from wiki_spike.connectors import CodexFixtureConnector, FixtureConnectorError
from wiki_spike.memory_core.second_brain_capture_contracts import (
    CapturePersistenceAggregateV1,
    CaptureReconciliationV1,
    CaptureScanManifestV1,
    EncryptedNativeMappingRefV1,
    InvalidContractValue,
    NonServingCaptureCohortV1,
    ReconciledCheckpointAdvanceV1,
    ScanCheckpointV1,
    canonical_identity_body_digest,
)
from wiki_spike.memory_core.second_brain_capture_ports import AtomicCapturePersistencePort

REF = lambda key: key + ":" + "a" * 64
DIGEST = "b" * 64


def bound(domain, value, digest_field):
    value[digest_field] = canonical_identity_body_digest(domain, {key: item for key, item in value.items() if key != digest_field})
    return value


def scope():
    return {"scope_version": "second-brain-source-scope-ref-v1", "source_profile": "Codex", "source_domain": "codex", "source_ref": REF("codex-source"), "workspace_ref": REF("workspace"), "scope_ref": REF("codex-scope"), "scope_epoch": "1"}


def receipt():
    return {"receipt_version": "second-brain-capture-item-receipt-v1", "scope": scope(), "scan_epoch": "1", "capture_ref": REF("capture"), "ciphertext_digest": sha256(b"ciphertext").hexdigest(), "disposition": "ACCEPTED"}


def manifest():
    return bound("manifest-v1", {"manifest_version": "second-brain-capture-scan-manifest-v1", "scope": scope(), "scan_epoch": "1", "checkpoint_ref": REF("checkpoint"), "receipt_refs": [REF("capture")], "manifest_ref": REF("manifest"), "manifest_digest": ""}, "manifest_digest")


def reconciliation():
    return bound("reconciliation-v1", {"reconciliation_version": "second-brain-capture-reconciliation-v1", "scope": scope(), "scan_epoch": "1", "manifest_ref": REF("manifest"), "reconciliation_ref": REF("reconciliation"), "reconciliation_epoch": "1", "completion": "COMPLETE", "outcome": "RECONCILED", "expected_receipt_count": "1", "accounted_receipt_count": "1", "disposition_counts": {"ACCEPTED": "1", "DUPLICATE": "0", "TOMBSTONE": "0", "SKIPPED": "0", "QUARANTINED": "0"}, "reconciliation_digest": ""}, "reconciliation_digest")


def checkpoint():
    reconciled = reconciliation()
    return bound("checkpoint-v1", {"checkpoint_version": "second-brain-scan-checkpoint-v1", "scope": scope(), "scan_epoch": "1", "checkpoint_ref": REF("checkpoint"), "checkpoint_digest": "", "manifest_ref": REF("manifest"), "reconciliation_ref": REF("reconciliation"), "reconciliation_digest": reconciled["reconciliation_digest"], "reconciliation_epoch": "1", "reconciliation_completion": "COMPLETE", "reconciliation_outcome": "RECONCILED"}, "checkpoint_digest")


def cohort():
    entry = {"source_domain": "codex", "source_ref": REF("codex-source"), "registration_ref": REF("migration-registration"), "scope_ref": REF("codex-scope"), "manifest_ref": REF("manifest"), "reconciliation_ref": REF("reconciliation"), "reconciliation_epoch": "1", "checkpoint_ref": REF("checkpoint"), "checkpoint_epoch": "1"}
    entry["ownership_binding"] = {
        "workspace_ref": REF("workspace"),
        **{key: value for key, value in entry.items() if key != "source_domain"},
    }
    return bound("cohort-v1", {"cohort_version": "second-brain-non-serving-capture-cohort-v1", "cohort_ref": REF("cohort"), "final_workspace_ref": REF("workspace"), "state": "NON_SERVING", "source_roster": [entry], "cohort_digest": ""}, "cohort_digest")


def advance():
    reconciled = reconciliation()
    checked = checkpoint()
    checked["reconciliation_digest"] = reconciled["reconciliation_digest"]
    bound("checkpoint-v1", checked, "checkpoint_digest")
    return {"advance_version": "second-brain-reconciled-checkpoint-advance-v1", "previous_checkpoint_ref": None, "reconciliation": reconciled, "checkpoint": checked}


@pytest.mark.parametrize(("parser", "factory", "field"), [
    (CaptureScanManifestV1, manifest, "receipt_refs"),
    (CaptureReconciliationV1, reconciliation, "manifest_ref"),
    (ScanCheckpointV1, checkpoint, "manifest_ref"),
    (NonServingCaptureCohortV1, cohort, "final_workspace_ref"),
])
def test_identity_body_digest_rejects_each_mutated_authoritative_field(parser, factory, field):
    value = factory()
    parser.from_mapping(value)
    value[field] = [] if field == "receipt_refs" else REF("substituted")
    with pytest.raises(InvalidContractValue):
        parser.from_mapping(value)


def test_digest_is_domain_separated_even_for_the_same_canonical_body():
    body = {"identity": REF("capture")}
    assert canonical_identity_body_digest("manifest-v1", body) != canonical_identity_body_digest("reconciliation-v1", body)


def test_cohort_owns_exact_reconciled_checkpoint_and_reconciliation_refs_and_epochs():
    value = cohort()
    NonServingCaptureCohortV1.from_mapping(value)
    for field, replacement in (("checkpoint_ref", REF("other-checkpoint")), ("reconciliation_ref", REF("other-reconciliation")), ("checkpoint_epoch", "2"), ("reconciliation_epoch", "2")):
        candidate = deepcopy(value)
        candidate["source_roster"][0][field] = replacement
        candidate["source_roster"][0]["ownership_binding"][field] = replacement
        with pytest.raises(InvalidContractValue):
            NonServingCaptureCohortV1.from_mapping(candidate)


def test_checkpoint_advance_requires_exact_bound_reconciliation_digest():
    value = advance()
    ReconciledCheckpointAdvanceV1.from_mapping(value)
    value["checkpoint"]["reconciliation_digest"] = DIGEST
    bound("checkpoint-v1", value["checkpoint"], "checkpoint_digest")
    with pytest.raises(InvalidContractValue):
        ReconciledCheckpointAdvanceV1.from_mapping(value)


class FixtureClient:
    def __init__(self, payloads): self.payloads = payloads
    def read_fixture_payload(self, request_ref): return self.payloads[request_ref]


class ExactSealer:
    def seal_native_mapping(self, scope, capture_ref, native_mapping):
        return EncryptedNativeMappingRefV1(capture_ref, REF("encrypted-native-mapping"))


class SwappingSealer:
    def seal_native_mapping(self, scope, capture_ref, native_mapping):
        return EncryptedNativeMappingRefV1(f"capture:{'b' * 64}", REF("encrypted-native-mapping"))


def fixture(capture_ref=REF("capture")):
    return json.dumps({"fixture_version": "second-brain-connector-fixture-v1", "source_profile": "Codex", "source_domain": "codex", "scope_ref": REF("codex-scope"), "scan_epoch": "1", "capture_ref": capture_ref, "ciphertext_b64": base64.b64encode(b"ciphertext").decode(), "native_mapping": {"fixture_only": "opaque"}}).encode()


def test_connector_returns_complete_identity_bound_transient_items():
    connector = CodexFixtureConnector(FixtureClient({REF("request"): fixture()}), ExactSealer(), [REF("request")])
    items = connector.read_fixture_capture_items(__import__("wiki_spike.memory_core.second_brain_capture_contracts", fromlist=["SourceScopeRefV1"]).SourceScopeRefV1.from_mapping(scope()), "1")
    assert len(items) == 1
    assert items[0].capture_ref == REF("capture")
    assert items[0].ciphertext == b"ciphertext"
    assert items[0].encrypted_native_mapping_ref == REF("encrypted-native-mapping")


def test_connector_rejects_a_swapped_sealed_native_mapping_identity():
    connector = CodexFixtureConnector(FixtureClient({REF("request"): fixture()}), SwappingSealer(), [REF("request")])
    source_scope = __import__("wiki_spike.memory_core.second_brain_capture_contracts", fromlist=["SourceScopeRefV1"]).SourceScopeRefV1.from_mapping(scope())
    with pytest.raises(FixtureConnectorError):
        connector.read_fixture_capture_items(source_scope, "1")


def test_atomic_persistence_port_exposes_only_one_complete_aggregate_operation():
    assert hasattr(AtomicCapturePersistencePort, "persist_capture_aggregate")
    assert not hasattr(AtomicCapturePersistencePort, "record_capture_receipt")


def test_aggregate_requires_complete_matching_receipt_manifest_scope():
    value = {"aggregate_version": "second-brain-capture-persistence-aggregate-v1", "scope": scope(), "receipts": [receipt()], "manifest": manifest(), "registration": {"registration_version": "second-brain-migration-registration-v1", "migration_source": "unified-db", "migration_ref": REF("unified-db-migration"), "migration_scope_ref": REF("unified-db-migration-scope"), "scope": scope(), "migration_epoch": "1", "registration_ref": REF("migration-registration"), "ciphertext_digest": DIGEST}, "advance": advance(), "cohort": cohort(), "aggregate_digest": ""}
    bound("aggregate-v1", value, "aggregate_digest")
    CapturePersistenceAggregateV1.from_mapping(value)
    value["manifest"]["receipt_refs"] = [REF("other-capture")]
    with pytest.raises(InvalidContractValue):
        CapturePersistenceAggregateV1.from_mapping(value)
