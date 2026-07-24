"""Gate 3 infrastructure module tests.

Covers identities (frozen vector reproduction), changeset construction
(delta_id, changes_root, changeset_id, conflict detection), input
normalization, and floor protocol (state machine, serve gate, R9-1
exact-A CAS readback).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from wiki_spike.infrastructure import crypto, identities
from wiki_spike.infrastructure.changeset import (
    ChangeSetError,
    build_encrypted_accepted_changeset,
    build_state_delta,
    compute_changes_root,
    compute_delta_id,
    project_expected_active_revisions,
)
from wiki_spike.infrastructure.floor_protocol import (
    CandidateDisposition,
    CandidateKind,
    FloorProtocolError,
    FloorState,
    ServeGateError,
    _assert_transition,
    build_floor_candidate,
    build_freshness_serve_gate,
    floor_hash,
    serve_gate_allows_serving,
    verify_cas_readback,
)
from wiki_spike.infrastructure.ingestion import (
    InputNormalizationError,
    input_content_digest,
    normalize_lifecycle_input_v1,
    remember_options,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY_VECTORS = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle" / "identity-vectors-v1.json"
FLOOR_VECTORS = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle" / "floor-state-vectors-v1.json"

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()


@pytest.fixture(scope="module")
def derived_keys() -> dict[str, bytes]:
    return crypto.derive_identity_keys(TEST_ONLY_IKM)


@pytest.fixture(scope="module")
def identity_vectors() -> dict:
    return json.loads(IDENTITY_VECTORS.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def floor_vectors() -> dict:
    return json.loads(FLOOR_VECTORS.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. Identity builders reproduce frozen vectors
# ---------------------------------------------------------------------------


def test_command_digest_reproduces_frozen_vectors(derived_keys, identity_vectors):
    for case in identity_vectors["cases"]:
        if "command_message" not in case:
            continue
        m = case["command_message"]
        _, digest = identities.command_digest(
            derived_keys,
            workspace_id=m["workspace_id"],
            command_kind=m["command_kind"],
            normalized_options=m["normalized_options"],
            input_content_digest=m["input_content_digest"],
            policy_context_digest=m["policy_context_digest"],
        )
        assert digest == case["command_id"], f"command_id mismatch: {case['name']}"


def test_artifact_semantic_digest_reproduces_frozen_vectors(derived_keys, identity_vectors):
    for case in identity_vectors["cases"]:
        if "artifact_semantic_message" not in case:
            continue
        m = case["artifact_semantic_message"]
        _, digest = identities.artifact_semantic_digest(
            derived_keys,
            workspace_id=m["workspace_id"],
            artifact_kind=m["artifact_kind"],
            consent_epoch=m["consent_epoch"],
            semantic_schema=m.get("semantic_schema", "wiki-memory-revision-semantic-v1"),
            semantic_plaintext=m["semantic_plaintext"],
        )
        assert digest == case["artifact_semantic_digest"], f"artifact mismatch: {case['name']}"


def test_logical_object_id_reproduces_frozen_vectors(derived_keys, identity_vectors):
    for case in identity_vectors["cases"]:
        if "object_id_message" not in case:
            continue
        m = case["object_id_message"]
        _, digest = identities.logical_object_id(
            derived_keys,
            workspace_id=m["workspace_id"],
            object_kind=m["object_kind"],
            consent_epoch=m["consent_epoch"],
            subject_key_digest=m["subject_key_digest"],
        )
        assert digest == case["logical_object_id"], f"object_id mismatch: {case['name']}"


def test_revision_id_reproduces_frozen_vectors(derived_keys, identity_vectors):
    for case in identity_vectors["cases"]:
        if "revision_id_message" not in case:
            continue
        m = case["revision_id_message"]
        _, digest = identities.revision_id(
            derived_keys,
            workspace_id=m["workspace_id"],
            object_kind=m["object_kind"],
            logical_object_id_hex=m["logical_object_id"],
            consent_epoch=m["consent_epoch"],
            revision_number=m["revision_number"],
            parent_revision_id=m["parent_revision_id"],
            artifact_semantic_digest_hex=m["artifact_semantic_digest"],
        )
        assert digest == case["revision_id"], f"revision_id mismatch: {case['name']}"


def test_manifest_digest_reproduces_frozen_vectors(derived_keys, identity_vectors):
    for case in identity_vectors["cases"]:
        if "manifest_message" not in case:
            continue
        m = case["manifest_message"]
        _, digest = identities.manifest_digest(
            derived_keys,
            workspace_id=m["workspace_id"],
            command_digest_hex=m["command_digest"],
            entries=m["entries"],
        )
        assert digest == case["manifest_digest"], f"manifest mismatch: {case['name']}"


# ---------------------------------------------------------------------------
# 2. Change set construction
# ---------------------------------------------------------------------------

_H = lambda s: hashlib.sha256(s.encode()).hexdigest()


def test_delta_id_is_deterministic():
    d1 = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r"), envelope_ref=_H("e"))
    d2 = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r"), envelope_ref=_H("e"))
    assert d1["delta_id"] == d2["delta_id"]
    assert len(d1["delta_id"]) == 64


def test_delta_id_changes_with_operation():
    d1 = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r"))
    d2 = build_state_delta(operation="RETRACT", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r"), expected_active_revision_id=_H("x"))
    assert d1["delta_id"] != d2["delta_id"]


def test_changeset_construction():
    d = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r"), envelope_ref=_H("e"))
    cs = build_encrypted_accepted_changeset(
        workspace_id="ws-test-1", parent_generation_id=None,
        command_ids=[_H("c1")], deltas=[d],
    )
    assert cs["contract_version"] == "wiki-encrypted-accepted-change-set-v1"
    assert len(cs["changeset_id"]) == 64
    assert len(cs["changes_root"]) == 64
    assert len(cs["expected_active_revisions"]) == 1
    assert cs["command_ids"] == [_H("c1")]


def test_changeset_conflict_detection():
    d1 = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r1"), envelope_ref=_H("e1"))
    d2 = build_state_delta(operation="RETRACT", object_kind="MEMORY_REVISION", object_id=_H("o"), revision_id=_H("r2"), expected_active_revision_id=_H("x"))
    with pytest.raises(ChangeSetError) as excinfo:
        build_encrypted_accepted_changeset(
            workspace_id="ws-test-1", parent_generation_id=None,
            command_ids=[_H("c")], deltas=[d1, d2],
        )
    assert excinfo.value.code == "conflicting_expected_active_revision"


def test_changes_root_is_sorted_by_delta_id():
    d1 = build_state_delta(operation="ADD", object_kind="MEMORY_REVISION", object_id=_H("a"), revision_id=_H("r1"), envelope_ref=_H("e1"))
    d2 = build_state_delta(operation="ADD", object_kind="ASSERTION", object_id=_H("b"), revision_id=_H("r2"), assertion_id=_H("a1"))
    root_ab = compute_changes_root([d1, d2])
    root_ba = compute_changes_root([d2, d1])
    assert root_ab == root_ba


# ---------------------------------------------------------------------------
# 3. Input normalization
# ---------------------------------------------------------------------------


def test_normalize_basic():
    result = normalize_lifecycle_input_v1(b"hello world")
    assert result == b"hello world"


def test_normalize_crlf_to_lf():
    result = normalize_lifecycle_input_v1(b"line1\r\nline2\rline3\n")
    assert result == b"line1\nline2\nline3\n"


def test_normalize_nfc():
    import unicodedata
    decomposed = unicodedata.normalize("NFD", "café").encode("utf-8")
    result = normalize_lifecycle_input_v1(decomposed)
    assert result == unicodedata.normalize("NFC", "café").encode("utf-8")


def test_normalize_rejects_bom():
    with pytest.raises(InputNormalizationError) as excinfo:
        normalize_lifecycle_input_v1(b"\xef\xbb\xbfhello")
    assert excinfo.value.code == "bom_rejected"


def test_normalize_rejects_nul():
    with pytest.raises(InputNormalizationError) as excinfo:
        normalize_lifecycle_input_v1(b"hello\x00world")
    assert excinfo.value.code == "nul_rejected"


def test_normalize_rejects_invalid_utf8():
    with pytest.raises(InputNormalizationError) as excinfo:
        normalize_lifecycle_input_v1(b"\xff\xfe")
    assert excinfo.value.code == "invalid_utf8"


def test_input_content_digest():
    body = normalize_lifecycle_input_v1(b"test body")
    digest = input_content_digest(body)
    assert digest == hashlib.sha256(b"test body").hexdigest()


def test_remember_options_shape():
    opts = remember_options(
        project_id="proj-1", source_kind="INLINE_TEXT", input_format="PLAIN_TEXT",
        source_instance_id="src-1", subject_ordinal="0", sensitivity="INTERNAL",
        consent_epoch="1", extractor_profile="LOCAL_RULES_V1",
    )
    assert opts["schema"] == "wiki-remember-options-v1"
    assert opts["command_kind"] == "REMEMBER"
    assert opts["new_consent"] == "NO"
    assert opts["consent_reason"] is None


# ---------------------------------------------------------------------------
# 4. Floor protocol state machine
# ---------------------------------------------------------------------------


def test_valid_floor_transitions():
    _assert_transition(FloorState.FLOOR_STABLE, FloorState.CHALLENGE_RESERVED)
    _assert_transition(FloorState.CHALLENGE_RESERVED, FloorState.COUNTER_UPDATE_PREPARED)
    _assert_transition(FloorState.CHALLENGE_RESERVED, FloorState.FLOOR_UPDATE_PREPARED)
    _assert_transition(FloorState.COUNTER_UPDATE_PREPARED, FloorState.KEYCHAIN_COMMITTED)
    _assert_transition(FloorState.FLOOR_UPDATE_PREPARED, FloorState.KEYCHAIN_COMMITTED)
    _assert_transition(FloorState.KEYCHAIN_COMMITTED, FloorState.FLOOR_STABLE)


def test_illegal_floor_transitions():
    for src, tgt in [
        (FloorState.FLOOR_STABLE, FloorState.FLOOR_UPDATE_PREPARED),
        (FloorState.FLOOR_STABLE, FloorState.KEYCHAIN_COMMITTED),
        (FloorState.FLOOR_UPDATE_PREPARED, FloorState.COUNTER_UPDATE_PREPARED),
        (FloorState.COUNTER_UPDATE_PREPARED, FloorState.FLOOR_UPDATE_PREPARED),
        (FloorState.QUARANTINED_FLOOR_CONFLICT, FloorState.FLOOR_STABLE),
    ]:
        with pytest.raises(FloorProtocolError):
            _assert_transition(src, tgt)


def test_quarantine_reachable_from_active_states():
    for state in [FloorState.CHALLENGE_RESERVED, FloorState.COUNTER_UPDATE_PREPARED,
                  FloorState.FLOOR_UPDATE_PREPARED, FloorState.KEYCHAIN_COMMITTED]:
        _assert_transition(state, FloorState.QUARANTINED_FLOOR_CONFLICT)


def test_quarantine_not_reachable_from_stable():
    with pytest.raises(FloorProtocolError):
        _assert_transition(FloorState.FLOOR_STABLE, FloorState.QUARANTINED_FLOOR_CONFLICT)


# ---------------------------------------------------------------------------
# 5. Floor candidate and CAS readback
# ---------------------------------------------------------------------------


def test_cas_readback_accepts_exact_candidate():
    floor_bytes = {"veto_set_size": "0", "veto_set_root": "aa" * 32,
                   "transition_size": "0", "transition_root": "bb" * 32,
                   "transition_head": "cc" * 32, "prior_floor_hash": "dd" * 32}
    candidate = build_floor_candidate(
        candidate_kind=CandidateKind.VALIDATED_ADVANCE,
        expected_old_floor_hash="dd" * 32,
        expected_keychain_generation="1",
        candidate_floor=floor_bytes,
        attempt_id="ee" * 32, counter="2", nonce_digest="ff" * 32,
    )
    verify_cas_readback(candidate, floor_bytes)


def test_cas_readback_rejects_different_value():
    floor_a = {"veto_set_size": "0", "veto_set_root": "aa" * 32,
               "transition_size": "0", "transition_root": "bb" * 32,
               "transition_head": "cc" * 32, "prior_floor_hash": "dd" * 32}
    floor_b = {**floor_a, "veto_set_size": "1"}
    candidate = build_floor_candidate(
        candidate_kind=CandidateKind.VALIDATED_ADVANCE,
        expected_old_floor_hash="dd" * 32,
        expected_keychain_generation="1",
        candidate_floor=floor_a,
        attempt_id="ee" * 32, counter="2", nonce_digest="ff" * 32,
    )
    with pytest.raises(FloorProtocolError) as excinfo:
        verify_cas_readback(candidate, floor_b)
    assert excinfo.value.code == "quarantined_floor_conflict"


# ---------------------------------------------------------------------------
# 6. Freshness serve gate (frozen vector reproduction)
# ---------------------------------------------------------------------------


def test_serve_gate_valid_pairs_reproduce_vectors(floor_vectors):
    sg = floor_vectors["freshness_serve_gate"]
    for vp in sg["valid_pairs"]:
        gate = build_freshness_serve_gate(
            workspace_id=vp["workspace_id"], state=vp["state"],
            stable_floor_generation=vp["stable_floor_generation"],
            stable_checkpoint_id=vp["stable_checkpoint_id"],
            source_candidate_digest=vp["source_candidate_digest"],
            reason=vp["reason"], updated_at=vp["updated_at"],
        )
        assert gate == vp


def test_serve_gate_invalid_pairs_rejected(floor_vectors):
    sg = floor_vectors["freshness_serve_gate"]
    for ip in sg["invalid_in_enum_pairs"]:
        gate = ip["gate"]
        with pytest.raises(ServeGateError):
            build_freshness_serve_gate(
                workspace_id=gate["workspace_id"], state=gate["state"],
                stable_floor_generation=gate["stable_floor_generation"],
                stable_checkpoint_id=gate["stable_checkpoint_id"],
                source_candidate_digest=gate["source_candidate_digest"],
                reason=gate["reason"], updated_at=gate["updated_at"],
            )


def test_serve_gate_allows_serving():
    assert serve_gate_allows_serving({"state": "CLEAR", "reason": "NONE"}) is True
    assert serve_gate_allows_serving({"state": "FRESH_CHALLENGE_REQUIRED", "reason": "ATTESTATION_EXPIRED_BEFORE_STABILIZE"}) is False
    assert serve_gate_allows_serving(None) is False
    assert serve_gate_allows_serving({}) is False
