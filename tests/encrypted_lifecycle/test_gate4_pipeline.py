"""Gate 4 pipeline integration tests.

Tests the CORRECT / evidence-fragment / evidence-edge / TOMBSTONE /
new-consent workflows added to ``EncryptedLifecyclePipeline``.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.keystore import AbsenceReceipt
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


def _absence_receipt(namespace: str, ark_handle: str) -> AbsenceReceipt:
    return AbsenceReceipt(
        namespace=namespace,
        ark_handle=ark_handle,
        prior_metadata_digest="ab" * 32,
        destroyed_at="2026-01-01T00:00:00Z",
        receipt_digest="cd" * 32,
    )


# ---------------------------------------------------------------------------
# CORRECT
# ---------------------------------------------------------------------------


def test_correct_happy_path(pipeline):
    r = pipeline.remember(raw_body=b"original body", project_id="proj-1")
    result = pipeline.correct(
        artifact_id=r.artifact_semantic_digest,
        reviewer_handle="reviewer-1",
        corrected_raw_body=b"corrected body",
    )

    assert len(result["command_id"]) == 64
    assert len(result["revision_id"]) == 64
    assert len(result["artifact_semantic_digest"]) == 64
    assert result["revision_id"] != r.revision_id
    assert result["artifact_semantic_digest"] != r.artifact_semantic_digest

    # new revision persisted, parent = prior revision
    with pipeline.db.unit_of_work() as uow:
        new_art = uow.get_canonical_artifact(result["artifact_semantic_digest"])
        assert new_art is not None
        assert new_art["artifact_kind"] == "MEMORY_REVISION"
        assert new_art["revision_id"] == result["revision_id"]

        deltas = uow.list_state_deltas(result["changeset_id"])
        assert len(deltas) == 2
        ops = {d["operation_kind"] for d in deltas}
        assert ops == {"RETRACT", "ADD"}
        retract = next(d for d in deltas if d["operation_kind"] == "RETRACT")
        add = next(d for d in deltas if d["operation_kind"] == "ADD")
        assert retract["object_id"] == r.artifact_semantic_digest
        assert retract["revision_id"] == r.revision_id
        assert retract["expected_active_revision_id"] == r.revision_id
        assert add["object_id"] == result["artifact_semantic_digest"]
        assert add["revision_id"] == result["revision_id"]
        assert add["expected_active_revision_id"] == result["revision_id"]

    # CORRECT_ACCEPTED event appended
    rows = pipeline.db.event_log_rows()
    kinds = [row["event_kind"] for row in rows]
    assert "CORRECT_ACCEPTED" in kinds

    # corrected body decrypts from CAS
    stored_bytes = pipeline.cas.get(result["blob_id"])
    envelope = json.loads(stored_bytes)
    aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(result["artifact_semantic_digest"])
    decrypted = crypto.aes_gcm_open(
        TEST_DEK, envelope["nonce"], envelope["ciphertext"], envelope["tag"], aad
    )
    assert decrypted == b"corrected body"


def test_correct_conflict_on_wrong_expected_active(pipeline):
    r = pipeline.remember(raw_body=b"original body", project_id="proj-1")
    with pytest.raises(PipelineError) as excinfo:
        pipeline.correct(
            artifact_id=r.artifact_semantic_digest,
            reviewer_handle="reviewer-1",
            corrected_raw_body=b"corrected body",
            expected_active_revision_id="ff" * 32,
        )
    assert excinfo.value.code == "correction_conflict"


def test_correct_unknown_artifact(pipeline):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.correct(
            artifact_id="ff" * 32,
            reviewer_handle="reviewer-1",
            corrected_raw_body=b"corrected body",
        )
    assert excinfo.value.code == "artifact_not_found"


# ---------------------------------------------------------------------------
# Evidence fragments
# ---------------------------------------------------------------------------


def test_add_evidence_fragment_byte_range(pipeline):
    body = b"hello world evidence body"
    source_digest = hashlib.sha256(body).hexdigest()
    result = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={
            "locator_kind": "BYTE_RANGE",
            "locator_start": "0",
            "locator_end": "5",
            "locator_text": None,
        },
    )
    assert result["normalized_excerpt"] == "hello"
    assert len(result["fragment_semantic_digest"]) == 64
    assert len(result["locator_digest"]) == 64
    assert pipeline.cas.exists(result["blob_id"])


def test_add_evidence_fragment_line_range(pipeline):
    body = b"line one\nline two\nline three"
    source_digest = hashlib.sha256(body).hexdigest()
    result = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={
            "locator_kind": "LINE_RANGE",
            "locator_start": "2",
            "locator_end": "2",
            "locator_text": None,
        },
    )
    assert result["normalized_excerpt"] == "line two"


def test_add_evidence_fragment_json_pointer(pipeline):
    body = json.dumps({"a": {"b": "target value"}}).encode("utf-8")
    source_digest = hashlib.sha256(body).hexdigest()
    result = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={
            "locator_kind": "JSON_POINTER",
            "locator_start": None,
            "locator_end": None,
            "locator_text": "/a/b",
        },
    )
    assert result["normalized_excerpt"] == '"target value"'


def test_add_evidence_fragment_whole_source(pipeline):
    body = b"the entire source body"
    source_digest = hashlib.sha256(body).hexdigest()
    result = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={
            "locator_kind": "WHOLE_SOURCE",
            "locator_start": None,
            "locator_end": None,
            "locator_text": None,
        },
    )
    assert result["normalized_excerpt"] == "the entire source body"


def test_evidence_fragment_locator_kinds_produce_distinct_digests(pipeline):
    body = b"shared source body text"
    source_digest = hashlib.sha256(body).hexdigest()
    byte_range = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "6", "locator_text": None},
    )
    whole = pipeline.add_evidence_fragment(
        project_id="proj-1",
        source_content_digest=source_digest,
        normalized_source_body=body,
        locator={"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": None, "locator_text": None},
    )
    assert byte_range["fragment_semantic_digest"] != whole["fragment_semantic_digest"]
    assert byte_range["locator_digest"] != whole["locator_digest"]


# ---------------------------------------------------------------------------
# Evidence edges
# ---------------------------------------------------------------------------


def test_add_evidence_edge_supports(pipeline):
    result = pipeline.add_evidence_edge(
        project_id="proj-1",
        assertion_semantic_digest="aa" * 32,
        fragment_semantic_digest="bb" * 32,
        locator_digest="cc" * 32,
        support_kind="SUPPORTS",
    )
    assert len(result["edge_semantic_digest"]) == 64
    with pipeline.db.unit_of_work() as uow:
        art = uow.get_canonical_artifact(result["edge_semantic_digest"])
        assert art is not None
        assert art["artifact_kind"] == "EVIDENCE_EDGE"


def test_add_evidence_edge_contradicts(pipeline):
    result = pipeline.add_evidence_edge(
        project_id="proj-1",
        assertion_semantic_digest="aa" * 32,
        fragment_semantic_digest="bb" * 32,
        locator_digest="cc" * 32,
        support_kind="CONTRADICTS",
    )
    assert len(result["edge_semantic_digest"]) == 64


def test_add_evidence_edge_invalid_support_kind(pipeline):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.add_evidence_edge(
            project_id="proj-1",
            assertion_semantic_digest="aa" * 32,
            fragment_semantic_digest="bb" * 32,
            locator_digest="cc" * 32,
            support_kind="MAYBE",
        )
    assert excinfo.value.code == "invalid_support_kind"


# ---------------------------------------------------------------------------
# Tombstone
# ---------------------------------------------------------------------------


def test_tombstone_object(pipeline):
    r = pipeline.remember(raw_body=b"to be forgotten", project_id="proj-1")
    deletion_command_id = "ee" * 32
    result = pipeline.tombstone_object(
        object_id=r.artifact_semantic_digest,
        deletion_command_id=deletion_command_id,
    )
    assert len(result["changeset_id"]) == 64
    assert len(result["delta_id"]) == 64

    with pipeline.db.unit_of_work() as uow:
        deltas = uow.list_state_deltas(result["changeset_id"])
        assert len(deltas) == 1
        assert deltas[0]["operation_kind"] == "TOMBSTONE"
        assert deltas[0]["object_id"] == r.artifact_semantic_digest
        assert deltas[0]["deletion_command_id"] == deletion_command_id

    ears = pipeline.project_expected_active(result["changeset_id"])
    assert len(ears) == 1
    assert ears[0]["object_id"] == r.artifact_semantic_digest
    assert ears[0]["expected_active_revision_id"] is None

    rows = pipeline.db.event_log_rows()
    kinds = [row["event_kind"] for row in rows]
    assert "OBJECT_TOMBSTONED" in kinds


# ---------------------------------------------------------------------------
# New consent
# ---------------------------------------------------------------------------


def _row_counts(pipeline):
    con = pipeline.db.con
    command_count = con.execute("SELECT COUNT(*) FROM command").fetchone()[0]
    artifact_count = con.execute("SELECT COUNT(*) FROM canonical_artifact").fetchone()[0]
    return command_count, artifact_count


def test_new_consent_fails_without_deletion_state(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    before = _row_counts(pipeline)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_prior_deletion_incomplete"
    assert _row_counts(pipeline) == before


def test_new_consent_fails_when_deletion_incomplete(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    with pipeline.db.unit_of_work() as uow:
        uow.insert_deletion_state(
            deletion_id="dd" * 32,
            artifact_id=r.artifact_semantic_digest,
            phase_state="PENDING",
            updated_at="2026-01-01T00:00:00Z",
        )
    before = _row_counts(pipeline)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_prior_deletion_incomplete"
    assert _row_counts(pipeline) == before


def _seed_complete_deletion(pipeline, artifact_id: str) -> None:
    with pipeline.db.unit_of_work() as uow:
        uow.insert_deletion_state(
            deletion_id="dd" * 32,
            artifact_id=artifact_id,
            phase_state="COMPLETE",
            updated_at="2026-01-01T00:00:00Z",
        )


def test_new_consent_fails_without_absence_receipts(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=None,
            recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_missing_absence_receipts"
    assert _row_counts(pipeline) == before

    with pytest.raises(PipelineError) as excinfo2:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
            recovery_absence_receipt=None,
        )
    assert excinfo2.value.code == "new_consent_missing_absence_receipts"
    assert _row_counts(pipeline) == before


def test_new_consent_fails_when_epoch_not_greater(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="2",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_epoch_not_greater"
    assert _row_counts(pipeline) == before


def test_new_consent_fails_when_body_empty(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_body_required"
    assert _row_counts(pipeline) == before


def test_new_consent_happy_path(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    result = pipeline.remember_new_consent(
        prior_object_id=r.artifact_semantic_digest,
        prior_consent_epoch="1",
        consent_epoch="2",
        raw_body=b"fresh consented body",
        project_id="proj-1",
        platform_absence_receipt=_absence_receipt("platform", r.artifact_semantic_digest),
        recovery_absence_receipt=_absence_receipt("recovery", r.artifact_semantic_digest),
    )

    assert len(result.command_id) == 64
    assert len(result.artifact_semantic_digest) == 64
    # Fresh, independent logical object/revision (different consent epoch).
    assert result.logical_object_id != r.logical_object_id
    assert result.artifact_semantic_digest != r.artifact_semantic_digest

    after = _row_counts(pipeline)
    assert after[0] == before[0] + 1  # +1 command
    assert after[1] == before[1] + 1  # +1 canonical_artifact

    with pipeline.db.unit_of_work() as uow:
        art = uow.get_canonical_artifact(result.artifact_semantic_digest)
        assert art is not None
        assert art["artifact_kind"] == "MEMORY_REVISION"

    stored_bytes = pipeline.cas.get(result.blob_id)
    envelope = json.loads(stored_bytes)
    aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(result.artifact_semantic_digest)
    decrypted = crypto.aes_gcm_open(
        TEST_DEK, envelope["nonce"], envelope["ciphertext"], envelope["tag"], aad
    )
    assert decrypted == b"fresh consented body"

    rows = pipeline.db.event_log_rows()
    kinds = [row["event_kind"] for row in rows]
    assert "NEW_CONSENT_ACCEPTED" in kinds

# ---------------------------------------------------------------------------
# persist_changeset delta-conformance guard (must fail-closed on the exact
# P1 defect class: object_kind not in the frozen StateDeltaV1 enum, and an
# uppercase reason_code) on BOTH the jsonschema and manual-fallback paths.
# ---------------------------------------------------------------------------


def _bad_object_kind_delta():
    from wiki_spike.infrastructure.changeset import build_state_delta

    return build_state_delta(
        operation="ADD",
        object_kind="MEMORY",  # not in the frozen enum
        object_id="aa" * 32,
        revision_id="bb" * 32,
        expected_active_revision_id="bb" * 32,
        envelope_ref="aa" * 32,
    )


def _bad_reason_code_delta():
    from wiki_spike.infrastructure.changeset import build_state_delta

    return build_state_delta(
        operation="TOMBSTONE",
        object_kind="MEMORY_REVISION",
        object_id="aa" * 32,
        deletion_command_id="cc" * 32,
        scope_digest="dd" * 32,
        reason_code="FORGET",  # violates safeReasonCode ^[a-z][a-z0-9_]{0,63}$
    )


def test_validate_state_delta_rejects_defect_class_jsonschema_path():
    from wiki_spike.applications import encrypted_lifecycle_pipeline as elp

    for delta in (_bad_object_kind_delta(), _bad_reason_code_delta()):
        with pytest.raises(elp.PipelineError) as exc:
            elp._validate_state_delta(delta)
        assert exc.value.code == "state_delta_schema_violation"


def test_validate_state_delta_rejects_defect_class_manual_fallback(monkeypatch):
    from wiki_spike.applications import encrypted_lifecycle_pipeline as elp

    monkeypatch.setattr(elp, "_HAVE_JSONSCHEMA", False)
    for delta in (_bad_object_kind_delta(), _bad_reason_code_delta()):
        with pytest.raises(elp.PipelineError) as exc:
            elp._validate_state_delta(delta)
        assert exc.value.code == "state_delta_schema_violation"


def test_validate_state_delta_accepts_conformant_delta():
    from wiki_spike.infrastructure.changeset import build_state_delta
    from wiki_spike.applications import encrypted_lifecycle_pipeline as elp

    good = build_state_delta(
        operation="ADD",
        object_kind="MEMORY_REVISION",
        object_id="aa" * 32,
        revision_id="bb" * 32,
        expected_active_revision_id="bb" * 32,
        envelope_ref="aa" * 32,
    )
    elp._validate_state_delta(good)  # must not raise
