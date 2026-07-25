"""Gate 4 adversarial red-team suite.

Attempts to BREAK the Gate 4 workflows (locators, CORRECT, evidence
fragments/edges, TOMBSTONE, new-consent) rather than merely confirm the
happy paths already covered by ``test_gate4_locators.py`` /
``test_gate4_pipeline.py``. Assertions here are deliberately adversarial:
malformed inputs, boundary-exact extraction, atomicity of multi-delta
changesets, fail-closed preconditions with zero-state-mutation guarantees,
and encrypted-before-durability (no plaintext leakage into CAS blobs).

No assertion in this file is weakened to make a workflow "pass" -- any
invariant that does not hold is reported as a blocker, not patched around.
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
from wiki_spike.infrastructure.locators import LocatorError, extract_excerpt, validate_locator
from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


class _SpyCas:
    """Wraps a real EncryptedContentStore, recording every blob_id passed to
    ``get`` so tests can assert prior ciphertext was never touched."""

    def __init__(self, inner: EncryptedContentStore) -> None:
        self._inner = inner
        self.get_calls: list[str] = []

    def put(self, envelope_bytes: bytes) -> str:
        return self._inner.put(envelope_bytes)

    def get(self, blob_id: str) -> bytes:
        self.get_calls.append(blob_id)
        return self._inner.get(blob_id)

    def exists(self, blob_id: str) -> bool:
        return self._inner.exists(blob_id)

    def is_tombstoned(self, blob_id: str) -> bool:
        return self._inner.is_tombstoned(blob_id)


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
    from wiki_spike.memory_core.contracts import canonical_bytes

    receipt_digest = hashlib.sha256(
        canonical_bytes(
            {
                "namespace": namespace,
                "ark_handle": ark_handle,
                "prior_metadata_digest": "ab" * 32,
                "destroyed_at": "2026-01-01T00:00:00Z",
            }
        )
    ).hexdigest()
    return AbsenceReceipt(
        namespace=namespace,
        ark_handle=ark_handle,
        prior_metadata_digest="ab" * 32,
        destroyed_at="2026-01-01T00:00:00Z",
        receipt_digest=receipt_digest,
    )


def _seed_complete_deletion(pipeline, artifact_id: str) -> None:
    with pipeline.db.unit_of_work() as uow:
        uow.insert_deletion_state(
            deletion_id="dd" * 32,
            artifact_id=artifact_id,
            phase_state="COMPLETE",
            updated_at="2026-01-01T00:00:00Z",
        )


def _row_counts(pipeline):
    con = pipeline.db.con
    command_count = con.execute("SELECT COUNT(*) FROM command").fetchone()[0]
    artifact_count = con.execute("SELECT COUNT(*) FROM canonical_artifact").fetchone()[0]
    key_state_count = con.execute("SELECT COUNT(*) FROM key_state").fetchone()[0]
    event_count = con.execute("SELECT COUNT(*) FROM event_log").fetchone()[0]
    return (command_count, artifact_count, key_state_count, event_count)


# ---------------------------------------------------------------------------
# (a) LOCATORS: malformed-input rejection matrix
# ---------------------------------------------------------------------------

_MALFORMED_LOCATORS = [
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": None, "locator_end": "3", "locator_text": None},
        "locator.field_required",
        id="byte_range_null_start",
    ),
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": None, "locator_text": None},
        "locator.field_required",
        id="byte_range_null_end",
    ),
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": "+1", "locator_end": "3", "locator_text": None},
        "locator.field_not_decimal",
        id="byte_range_plus_sign",
    ),
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": "1.0", "locator_end": "3", "locator_text": None},
        "locator.field_not_decimal",
        id="byte_range_float_string",
    ),
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": "5", "locator_end": "4", "locator_text": None},
        "locator.byte_range_not_increasing",
        id="byte_range_end_lt_start",
    ),
    pytest.param(
        {"locator_kind": "BYTE_RANGE", "locator_start": "5", "locator_end": "5", "locator_text": None},
        "locator.byte_range_not_increasing",
        id="byte_range_end_eq_start",
    ),
    pytest.param(
        {"locator_kind": "LINE_RANGE", "locator_start": None, "locator_end": "2", "locator_text": None},
        "locator.field_required",
        id="line_range_null_start",
    ),
    pytest.param(
        {"locator_kind": "LINE_RANGE", "locator_start": "3", "locator_end": "0", "locator_text": None},
        "locator.field_out_of_range",
        id="line_range_zero_end",
    ),
    pytest.param(
        {"locator_kind": "LINE_RANGE", "locator_start": "2", "locator_end": "1", "locator_text": None},
        "locator.line_range_not_ordered",
        id="line_range_start_gt_end",
    ),
    pytest.param(
        {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/a~2b"},
        "locator.pointer_bad_escape",
        id="json_pointer_bad_escape_digit",
    ),
    pytest.param(
        {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None},
        "locator.field_required",
        id="json_pointer_missing_text_key",
    ),
    pytest.param(
        {"locator_kind": "WHOLE_SOURCE", "locator_start": "0", "locator_end": "1", "locator_text": "x"},
        "locator.field_must_be_null",
        id="whole_source_all_non_null",
    ),
]


@pytest.mark.parametrize("locator,expected_code", _MALFORMED_LOCATORS)
def test_red_team_malformed_locator_rejected(locator, expected_code):
    with pytest.raises(LocatorError) as excinfo:
        validate_locator(locator)
    assert excinfo.value.code == expected_code


def test_red_team_json_pointer_over_1024_bytes_multibyte_rejected():
    # Use multi-byte UTF-8 chars so the *byte* length (not char length)
    # crosses the 1024 boundary while char length alone would not.
    long_text = "/" + ("λ" * 600)  # 600 * 2 bytes = 1200 bytes > 1024
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": long_text}
    with pytest.raises(LocatorError) as excinfo:
        validate_locator(locator)
    assert excinfo.value.code == "locator.pointer_too_long"


def test_red_team_json_pointer_descend_into_scalar_rejected():
    body = json.dumps({"a": "scalar"}).encode("utf-8")
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/a/b"}
    validate_locator(locator)
    with pytest.raises(LocatorError) as excinfo:
        extract_excerpt(locator, body)
    assert excinfo.value.code == "locator.pointer_not_found"


def test_red_team_json_pointer_null_text_value_rejected():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": None}
    with pytest.raises(LocatorError) as excinfo:
        extract_excerpt(locator, b"{}")
    assert excinfo.value.code == "locator.field_required"


def test_red_team_byte_range_end_exclusive_is_exact():
    body = b"ABCDE"
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "1", "locator_end": "3", "locator_text": None}
    excerpt = extract_excerpt(locator, body)
    assert excerpt == "BC"
    assert "D" not in excerpt  # byte at index `end` (exclusive) must not leak in


def test_red_team_line_range_inclusive_is_exact():
    body = b"L0\nL1\nL2\n"
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "2", "locator_text": None}
    excerpt = extract_excerpt(locator, body)
    assert excerpt == "L0\nL1"
    assert "L2" not in excerpt  # line 3 (end+1) must not leak in


def test_red_team_json_pointer_nested_tilde_and_array_index_combined():
    doc = {"a/b": {"c~d": ["zero", "one", {"x": "deep"}]}}
    body = json.dumps(doc).encode("utf-8")
    locator = {
        "locator_kind": "JSON_POINTER",
        "locator_start": None,
        "locator_end": None,
        "locator_text": "/a~1b/c~0d/2/x",
    }
    validate_locator(locator)
    assert extract_excerpt(locator, body) == '"deep"'


# ---------------------------------------------------------------------------
# (b) CORRECTION: conflict fail-closed, atomicity, ciphertext isolation
# ---------------------------------------------------------------------------


def test_red_team_correction_conflict_writes_zero_new_state(pipeline):
    r = pipeline.remember(raw_body=b"original body", project_id="proj-1")
    before = _row_counts(pipeline)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.correct(
            artifact_id=r.artifact_semantic_digest,
            reviewer_handle="reviewer-1",
            corrected_raw_body=b"attacker-supplied body",
            expected_active_revision_id="ff" * 32,
        )
    assert excinfo.value.code == "correction_conflict"
    assert _row_counts(pipeline) == before


def test_red_team_correction_is_one_atomic_changeset(pipeline):
    r = pipeline.remember(raw_body=b"original body", project_id="proj-1")
    result = pipeline.correct(
        artifact_id=r.artifact_semantic_digest,
        reviewer_handle="reviewer-1",
        corrected_raw_body=b"corrected body",
    )
    con = pipeline.db.con
    changeset_rows = con.execute(
        "SELECT COUNT(*) FROM accepted_changeset WHERE changeset_id=?",
        (result["changeset_id"],),
    ).fetchone()[0]
    assert changeset_rows == 1

    delta_rows = con.execute(
        "SELECT operation_kind FROM state_delta WHERE changeset_id=?",
        (result["changeset_id"],),
    ).fetchall()
    assert {row[0] for row in delta_rows} == {"RETRACT", "ADD"}
    assert len(delta_rows) == 2  # exactly one RETRACT + one ADD, nothing more


def test_red_team_correction_corrected_body_correct_prior_body_unchanged(pipeline):
    r = pipeline.remember(raw_body=b"original body", project_id="proj-1")
    result = pipeline.correct(
        artifact_id=r.artifact_semantic_digest,
        reviewer_handle="reviewer-1",
        corrected_raw_body=b"corrected body",
    )

    corrected_bytes = pipeline.cas.get(result["blob_id"])
    corrected_envelope = json.loads(corrected_bytes)
    aad_c = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(result["artifact_semantic_digest"])
    corrected_decrypted = crypto.aes_gcm_open(
        TEST_DEK, corrected_envelope["nonce"], corrected_envelope["ciphertext"], corrected_envelope["tag"], aad_c
    )
    assert corrected_decrypted == b"corrected body"

    prior_bytes = pipeline.cas.get(r.blob_id)
    prior_envelope = json.loads(prior_bytes)
    aad_p = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(r.artifact_semantic_digest)
    prior_decrypted = crypto.aes_gcm_open(
        TEST_DEK, prior_envelope["nonce"], prior_envelope["ciphertext"], prior_envelope["tag"], aad_p
    )
    assert prior_decrypted == b"original body"  # prior blob must remain byte-for-byte intact


# ---------------------------------------------------------------------------
# (c) EVIDENCE FRAGMENT: distinct digests per locator kind + no plaintext leak
# ---------------------------------------------------------------------------


def test_red_team_four_locator_kinds_yield_distinct_digests(pipeline):
    body = b"shared adversarial source body for digest distinctness"
    source_digest = hashlib.sha256(body).hexdigest()
    locators = {
        "BYTE_RANGE": {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "6", "locator_text": None},
        "LINE_RANGE": {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "1", "locator_text": None},
        "JSON_POINTER": None,  # body isn't JSON; built separately below
        "WHOLE_SOURCE": {"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": None, "locator_text": None},
    }

    json_body = json.dumps({"k": "shared adversarial source body for digest distinctness"}).encode("utf-8")
    json_source_digest = hashlib.sha256(json_body).hexdigest()
    locators["JSON_POINTER"] = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/k"}

    results = {}
    for kind, loc in locators.items():
        use_body = json_body if kind == "JSON_POINTER" else body
        use_digest = json_source_digest if kind == "JSON_POINTER" else source_digest
        results[kind] = pipeline.add_evidence_fragment(
            project_id="proj-1",
            source_content_digest=use_digest,
            normalized_source_body=use_body,
            locator=loc,
        )

    fragment_digests = {r["fragment_semantic_digest"] for r in results.values()}
    locator_digests = {r["locator_digest"] for r in results.values()}
    assert len(fragment_digests) == 4  # all four kinds must be pairwise distinct
    assert len(locator_digests) == 4


def test_red_team_evidence_fragment_cas_blob_has_no_plaintext_leak(pipeline):
    body = b"top secret excerpt payload that must never appear in the sealed CAS blob"
    source_digest = hashlib.sha256(body).hexdigest()

    cases = [
        {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "9", "locator_text": None},
        {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "1", "locator_text": None},
        {"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": None, "locator_text": None},
    ]
    for locator in cases:
        result = pipeline.add_evidence_fragment(
            project_id="proj-1",
            source_content_digest=source_digest,
            normalized_source_body=body,
            locator=locator,
        )
        excerpt = result["normalized_excerpt"]
        assert excerpt  # sanity: extraction actually produced something
        stored = pipeline.cas.get(result["blob_id"])
        assert excerpt.encode("utf-8") not in stored  # plaintext excerpt must not be durable
        assert b"top secret" not in stored
        assert b"\"excerpt\"" not in stored
        assert b"\"body\"" not in stored
        assert b"\"locator_text\"" not in stored


# ---------------------------------------------------------------------------
# (d) EVIDENCE EDGE: support_kind validation + digest distinctness
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "support_kind",
    ["supports", "contradicts", "", "SUPPORT", "CONTRADICT", "NEUTRAL", "supports "],
)
def test_red_team_evidence_edge_rejects_bad_support_kind_variants(pipeline, support_kind):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.add_evidence_edge(
            project_id="proj-1",
            assertion_semantic_digest="aa" * 32,
            fragment_semantic_digest="bb" * 32,
            locator_digest="cc" * 32,
            support_kind=support_kind,
        )
    assert excinfo.value.code == "invalid_support_kind"


def test_red_team_evidence_edge_supports_vs_contradicts_distinct_digest(pipeline):
    common = dict(
        project_id="proj-1",
        assertion_semantic_digest="aa" * 32,
        fragment_semantic_digest="bb" * 32,
        locator_digest="cc" * 32,
    )
    supports = pipeline.add_evidence_edge(support_kind="SUPPORTS", **common)
    contradicts = pipeline.add_evidence_edge(support_kind="CONTRADICTS", **common)
    assert supports["edge_semantic_digest"] != contradicts["edge_semantic_digest"]


# ---------------------------------------------------------------------------
# (e) NEW-CONSENT: fail-closed preconditions, zero-state-on-failure, no
#     reads of prior ciphertext
# ---------------------------------------------------------------------------


def test_red_team_new_consent_missing_deletion_state_blocks_and_writes_nothing(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    before = _row_counts(pipeline)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_prior_deletion_incomplete"
    assert _row_counts(pipeline) == before


def test_red_team_new_consent_incomplete_deletion_phase_blocks_and_writes_nothing(pipeline):
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
            platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_prior_deletion_incomplete"
    assert _row_counts(pipeline) == before


@pytest.mark.parametrize("missing", ["platform", "recovery", "both"])
def test_red_team_new_consent_missing_either_absence_receipt_blocks_and_writes_nothing(pipeline, missing):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    platform = None if missing in ("platform", "both") else _absence_receipt("ws-test-1", r.artifact_semantic_digest)
    recovery = None if missing in ("recovery", "both") else _absence_receipt("ws-test-1", r.artifact_semantic_digest)

    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=platform,
            recovery_absence_receipt=recovery,
        )
    assert excinfo.value.code == "new_consent_missing_absence_receipts"
    assert _row_counts(pipeline) == before


@pytest.mark.parametrize("prior_epoch,new_epoch", [("2", "2"), ("3", "2"), ("5", "1")])
def test_red_team_new_consent_epoch_not_strictly_greater_blocks_and_writes_nothing(pipeline, prior_epoch, new_epoch):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)
    with pytest.raises(PipelineError) as excinfo:
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch=prior_epoch,
            consent_epoch=new_epoch,
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_epoch_not_greater"
    assert _row_counts(pipeline) == before


def test_red_team_new_consent_empty_body_blocks_and_writes_nothing(pipeline):
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
            platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        )
    assert excinfo.value.code == "new_consent_body_required"
    assert _row_counts(pipeline) == before


def test_red_team_new_consent_happy_path_creates_new_state_with_new_consent_options(pipeline):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    before = _row_counts(pipeline)

    result = pipeline.remember_new_consent(
        prior_object_id=r.artifact_semantic_digest,
        prior_consent_epoch="1",
        consent_epoch="2",
        raw_body=b"fresh consented body",
        project_id="proj-1",
        platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
    )

    after = _row_counts(pipeline)
    assert after[0] == before[0] + 1  # +1 command
    assert after[1] == before[1] + 1  # +1 canonical_artifact
    assert after[2] == before[2] + 1  # +1 key_state
    assert result.artifact_semantic_digest != r.artifact_semantic_digest
    assert result.logical_object_id != r.logical_object_id

    with pipeline.db.unit_of_work() as uow:
        art = uow.get_canonical_artifact(result.artifact_semantic_digest)
        assert art is not None
        assert art["artifact_kind"] == "MEMORY_REVISION"


def test_red_team_new_consent_never_reads_prior_ciphertext(pipeline, tmp_path):
    r = pipeline.remember(raw_body=b"original", project_id="proj-1")
    spy = _SpyCas(pipeline.cas)
    pipeline.cas = spy

    # Failure paths first -- must not read prior blob either.
    with pytest.raises(PipelineError):
        pipeline.remember_new_consent(
            prior_object_id=r.artifact_semantic_digest,
            prior_consent_epoch="1",
            consent_epoch="2",
            raw_body=b"fresh body",
            project_id="proj-1",
            platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
            recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        )
    assert r.blob_id not in spy.get_calls

    _seed_complete_deletion(pipeline, r.artifact_semantic_digest)
    result = pipeline.remember_new_consent(
        prior_object_id=r.artifact_semantic_digest,
        prior_consent_epoch="1",
        consent_epoch="2",
        raw_body=b"fresh consented body",
        project_id="proj-1",
        platform_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
        recovery_absence_receipt=_absence_receipt("ws-test-1", r.artifact_semantic_digest),
    )
    assert r.blob_id not in spy.get_calls  # happy path must not unwrap prior ciphertext either

    # Sanity: the new blob decrypts to the fresh body (spy is transparent).
    stored = spy.get(result.blob_id)
    envelope = json.loads(stored)
    aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(result.artifact_semantic_digest)
    decrypted = crypto.aes_gcm_open(TEST_DEK, envelope["nonce"], envelope["ciphertext"], envelope["tag"], aad)
    assert decrypted == b"fresh consented body"


# ---------------------------------------------------------------------------
# (f) TOMBSTONE: no active revision after tombstoning
# ---------------------------------------------------------------------------


def test_red_team_tombstoned_object_has_no_active_revision(pipeline):
    r = pipeline.remember(raw_body=b"to be forgotten", project_id="proj-1")
    deletion_command_id = "ee" * 32
    result = pipeline.tombstone_object(
        object_id=r.artifact_semantic_digest,
        deletion_command_id=deletion_command_id,
    )

    ears = pipeline.project_expected_active(result["changeset_id"])
    matching = [ear for ear in ears if ear["object_id"] == r.artifact_semantic_digest]
    assert len(matching) == 1
    assert matching[0]["expected_active_revision_id"] is None  # projection shows no active revision
