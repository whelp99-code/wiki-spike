"""Gate 3 adversarial red-team QA suite.

Attempts to BREAK the encrypted single-memory lifecycle deterministic
vertical: identity collision/separation, envelope tamper resistance, input
normalization edge cases, changeset integrity, ExpectedActiveRevisionV1
projection correctness, review/activation state-machine guards, signed
generation domain separation, floor-protocol forward-only guards, and
event-chain tamper resistance.

Reuses fixtures/builders from ``test_gate3_pipeline.py`` and
``test_gate3_infrastructure.py`` (same TEST_ONLY_IKM/TEST_DEK convention,
same pipeline construction shape) but does not copy their assertions —
every assertion here is a distinct adversarial probe.
"""
from __future__ import annotations

import hashlib
import unicodedata
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    GENERATION_DOMAIN,
    EncryptedLifecyclePipeline,
    PipelineError,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.changeset import (
    build_state_delta,
    compute_changes_root,
    project_expected_active_revisions,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.floor_protocol import (
    CandidateKind,
    FloorProtocolError,
    FloorState,
    ServeGateError,
    _assert_transition,
    build_floor_candidate,
    build_freshness_serve_gate,
    serve_gate_allows_serving,
    verify_cas_readback,
)
from wiki_spike.infrastructure.ingestion import (
    InputNormalizationError,
    input_content_digest,
    normalize_lifecycle_input_v1,
)
from wiki_spike.infrastructure.lifecycle_db import (
    EVENT_LOG_DOMAIN,
    EventChainError,
    LifecycleDatabase,
)
from wiki_spike.memory_core.contracts import canonical_bytes

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


def _make_pipeline(tmp_path: Path, suffix: str, workspace_id: str = "ws-redteam") -> EncryptedLifecyclePipeline:
    root = tmp_path / suffix
    root.mkdir()
    db = LifecycleDatabase(db_path=root / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=root / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id=workspace_id,
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


# ---------------------------------------------------------------------------
# (a) Identity determinism + separation
# ---------------------------------------------------------------------------


def test_identity_determinism_and_option_separation(tmp_path):
    p1 = _make_pipeline(tmp_path, "p1")
    p2 = _make_pipeline(tmp_path, "p2")

    baseline_opts = dict(project_id="proj-a", subject_ordinal="0", consent_epoch="1", sensitivity="INTERNAL")
    r1 = p1.remember(raw_body=b"red team body", **baseline_opts)
    r2 = p2.remember(raw_body=b"red team body", **baseline_opts)

    assert r1.command_id == r2.command_id
    assert r1.revision_id == r2.revision_id
    assert r1.artifact_semantic_digest == r2.artifact_semantic_digest
    assert r1.logical_object_id == r2.logical_object_id

    baseline = (r1.command_id, r1.revision_id, r1.artifact_semantic_digest, r1.logical_object_id)
    all_ids = {baseline}
    for i, override in enumerate([
        {"project_id": "proj-b"},
        {"subject_ordinal": "1"},
        {"consent_epoch": "2"},
        {"sensitivity": "RESTRICTED"},
    ]):
        opts = dict(baseline_opts)
        opts.update(override)
        pv = _make_pipeline(tmp_path, f"variant-{i}")
        rv = pv.remember(raw_body=b"red team body", **opts)
        variant_ids = (rv.command_id, rv.revision_id, rv.artifact_semantic_digest, rv.logical_object_id)
        assert variant_ids != baseline, f"changing {override} did not change identities"
        assert variant_ids not in all_ids, f"collision introduced by {override}"
        all_ids.add(variant_ids)

    assert len(all_ids) == 5


# ---------------------------------------------------------------------------
# (b) Envelope integrity: tamper resistance
# ---------------------------------------------------------------------------


def test_envelope_tamper_resistance(tmp_path):
    p = _make_pipeline(tmp_path, "envtamper")
    original = b"top secret memory body"
    r = p.remember(raw_body=original, project_id="proj-1")
    aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(r.artifact_semantic_digest)

    decrypted = crypto.aes_gcm_open(
        TEST_DEK, r.envelope["nonce"], r.envelope["ciphertext"], r.envelope["tag"], aad
    )
    assert decrypted == original
    assert r.envelope["aad_digest"] == hashlib.sha256(aad).hexdigest()

    ct = bytearray(bytes.fromhex(r.envelope["ciphertext"]))
    ct[0] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(TEST_DEK, r.envelope["nonce"], ct.hex(), r.envelope["tag"], aad)

    tag = bytearray(bytes.fromhex(r.envelope["tag"]))
    tag[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(TEST_DEK, r.envelope["nonce"], r.envelope["ciphertext"], tag.hex(), aad)

    wrong_semantic_digest = hashlib.sha256(b"a different artifact entirely").hexdigest()
    wrong_aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(wrong_semantic_digest)
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(TEST_DEK, r.envelope["nonce"], r.envelope["ciphertext"], r.envelope["tag"], wrong_aad)


# ---------------------------------------------------------------------------
# (c) Input normalization: determinism + rejection
# ---------------------------------------------------------------------------


def test_input_normalization_determinism_and_rejection(tmp_path):
    source_text = "café\r\nnewline\rmix\n"
    nfd_bom_free = unicodedata.normalize("NFD", source_text).encode("utf-8")

    normalized_1 = normalize_lifecycle_input_v1(nfd_bom_free)
    normalized_2 = normalize_lifecycle_input_v1(nfd_bom_free)
    assert normalized_1 == normalized_2
    assert normalized_1 == unicodedata.normalize("NFC", "café\nnewline\nmix\n").encode("utf-8")
    assert input_content_digest(normalized_1) == input_content_digest(normalized_2)

    p1 = _make_pipeline(tmp_path, "norm1")
    p2 = _make_pipeline(tmp_path, "norm2")
    r1 = p1.remember(raw_body=nfd_bom_free, project_id="proj-1")
    r2 = p2.remember(raw_body=nfd_bom_free, project_id="proj-1")
    assert r1.command_id == r2.command_id

    with pytest.raises(InputNormalizationError) as excinfo:
        p1.remember(raw_body=b"\xef\xbb\xbfhello", project_id="proj-1")
    assert excinfo.value.code == "bom_rejected"


# ---------------------------------------------------------------------------
# (d) Changeset integrity
# ---------------------------------------------------------------------------


def test_changeset_integrity(tmp_path):
    p = _make_pipeline(tmp_path, "cs")
    r = p.remember(raw_body=b"changeset body", project_id="proj-1")
    cs = p.build_changeset(command_ids=[r.command_id])
    original_root = cs["changes_root"]

    reversed_root = compute_changes_root(list(reversed(cs["deltas"])))
    assert reversed_root == original_root, "changes_root must be order-independent of input order"

    mutated_delta = dict(cs["deltas"][0])
    mutated_delta["revision_id"] = "ff" * 32
    mutated_root = compute_changes_root([mutated_delta])
    assert mutated_root != original_root, "mutating a delta must change changes_root"

    with pytest.raises(PipelineError) as excinfo:
        p.build_changeset(command_ids=["ab" * 32])
    assert excinfo.value.code == "command_not_found"


# ---------------------------------------------------------------------------
# (e) ExpectedActiveRevisionV1 projection
# ---------------------------------------------------------------------------


def test_expected_active_revision_projection_sorted_unique_and_discriminators():
    d_add = build_state_delta(
        operation="ADD", object_kind="MEMORY_REVISION",
        object_id="aa" * 32, revision_id="bb" * 32, envelope_ref="cc" * 32,
    )
    d_add_dup = build_state_delta(
        operation="ADD", object_kind="MEMORY_REVISION",
        object_id="aa" * 32, revision_id="bb" * 32, envelope_ref="cc" * 32,
    )
    d_retract = build_state_delta(
        operation="RETRACT", object_kind="ASSERTION",
        object_id="11" * 32, expected_active_revision_id="22" * 32, assertion_id="33" * 32,
    )
    d_tombstone = build_state_delta(
        operation="TOMBSTONE", object_kind="ASSERTION",
        object_id="00" * 32, expected_active_revision_id="44" * 32, assertion_id="55" * 32,
    )

    ears = project_expected_active_revisions([d_add, d_add_dup, d_retract, d_tombstone])
    assert len(ears) == 3, "duplicate identical ADD delta must dedupe, not double-count"

    six_fields = {
        "object_kind", "object_id", "assertion_id",
        "evidence_edge_id", "evidence_fragment_ref", "expected_active_revision_id",
    }
    for ear in ears:
        assert set(ear.keys()) == six_fields

    keys = [(e["object_kind"].encode(), bytes.fromhex(e["object_id"])) for e in ears]
    assert keys == sorted(keys), "projection output must be in the spec sort order"

    ops_by_id = {d["delta_id"]: d["operation"] for d in (d_add, d_retract, d_tombstone)}
    assert ops_by_id[d_add["delta_id"]] == "ADD"
    assert ops_by_id[d_retract["delta_id"]] == "RETRACT"
    assert ops_by_id[d_tombstone["delta_id"]] == "TOMBSTONE"


# ---------------------------------------------------------------------------
# (f) Review / activation state machine
# ---------------------------------------------------------------------------


def test_review_and_activation_state_machine_guards(tmp_path):
    p = _make_pipeline(tmp_path, "review")
    r = p.remember(raw_body=b"reviewed body", project_id="proj-1")

    with pytest.raises(PipelineError) as excinfo:
        p.review_candidate(artifact_id=r.artifact_semantic_digest, reviewer_handle="rev-1", review_state="MAYBE")
    assert excinfo.value.code == "invalid_review_state"

    p.review_candidate(artifact_id=r.artifact_semantic_digest, reviewer_handle="rev-1", review_state="APPROVED")
    with p.db.unit_of_work() as uow:
        ks = uow.get_key_state(r.artifact_semantic_digest)
        assert ks["custody_state"] == "APPROVED"

    # Force custody into a terminal/invalid state and assert activation refuses it.
    with p.db.unit_of_work() as uow:
        uow.upsert_key_state(
            artifact_id=r.artifact_semantic_digest,
            custody_state="REJECTED",
            updated_at="1970-01-01T00:00:00Z",
        )
    with pytest.raises(PipelineError) as excinfo:
        p.activate_artifact(artifact_id=r.artifact_semantic_digest, blob_id=r.blob_id)
    assert excinfo.value.code == "invalid_activation_state"

    # Activating a non-existent blob must raise even for a healthy artifact.
    r2 = p.remember(raw_body=b"another body", project_id="proj-1")
    with pytest.raises(PipelineError) as excinfo:
        p.activate_artifact(artifact_id=r2.artifact_semantic_digest, blob_id="ff" * 32)
    assert excinfo.value.code == "blob_readback_failed"

    # Activating a non-existent artifact entirely must raise.
    with pytest.raises(PipelineError) as excinfo:
        p.activate_artifact(artifact_id="ff" * 32, blob_id=r2.blob_id)
    assert excinfo.value.code == "artifact_not_found"


# ---------------------------------------------------------------------------
# (g) Signed generation domain separation
# ---------------------------------------------------------------------------


def test_generation_signature_domain_and_key_separation(tmp_path):
    p = _make_pipeline(tmp_path, "gen")
    r = p.remember(raw_body=b"generation body", project_id="proj-1")
    cs = p.build_changeset(command_ids=[r.command_id])
    p.persist_changeset(cs)

    signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"redteam-gen-key").digest())
    attacker_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"attacker-key").digest())

    gen = p.create_generation(changeset_id=cs["changeset_id"], signing_key=signing_key, signer_key_id="signer-1")
    pubkey = signing_key.public_key()

    crypto.verify(pubkey, GENERATION_DOMAIN, gen["payload"], gen["signature"])

    with pytest.raises(InvalidSignature):
        crypto.verify(pubkey, "wiki.some-other-domain.v1", gen["payload"], gen["signature"])

    with pytest.raises(InvalidSignature):
        crypto.verify(attacker_key.public_key(), GENERATION_DOMAIN, gen["payload"], gen["signature"])

    tampered_payload = dict(gen["payload"])
    tampered_payload["changes_root"] = "ff" * 32
    with pytest.raises(InvalidSignature):
        crypto.verify(pubkey, GENERATION_DOMAIN, tampered_payload, gen["signature"])


# ---------------------------------------------------------------------------
# (h) Floor protocol: forward-only + serve gate + CAS readback
# ---------------------------------------------------------------------------


def test_floor_protocol_forward_only_and_serve_gate_withholds():
    with pytest.raises(FloorProtocolError):
        _assert_transition(FloorState.KEYCHAIN_COMMITTED, FloorState.CHALLENGE_RESERVED)  # backward
    with pytest.raises(FloorProtocolError):
        _assert_transition(FloorState.FLOOR_STABLE, FloorState.KEYCHAIN_COMMITTED)  # skip

    with pytest.raises(ServeGateError):
        build_freshness_serve_gate(
            workspace_id="ws-1", state="CLEAR", stable_floor_generation="1",
            stable_checkpoint_id="aa" * 32, source_candidate_digest="bb" * 32,
            reason="ATTESTATION_EXPIRED_BEFORE_STABILIZE", updated_at="1970-01-01T00:00:00Z",
        )

    # A structurally plausible but non-CLEAR gate must withhold serving.
    assert serve_gate_allows_serving({"state": "FRESH_CHALLENGE_REQUIRED", "reason": "CLOCK_WINDOW_EXPIRED"}) is False
    assert serve_gate_allows_serving({"state": "CLEAR", "reason": "SOME_UNKNOWN_REASON"}) is False

    floor_a = {
        "veto_set_size": "0", "veto_set_root": "aa" * 32, "transition_size": "0",
        "transition_root": "bb" * 32, "transition_head": "cc" * 32, "prior_floor_hash": "dd" * 32,
    }
    floor_mismatched = {**floor_a, "transition_head": "ee" * 32}
    candidate = build_floor_candidate(
        candidate_kind=CandidateKind.VALIDATED_ADVANCE, expected_old_floor_hash="dd" * 32,
        expected_keychain_generation="1", candidate_floor=floor_a, attempt_id="11" * 32,
        counter="1", nonce_digest="22" * 32,
    )
    with pytest.raises(FloorProtocolError) as excinfo:
        verify_cas_readback(candidate, floor_mismatched)
    assert excinfo.value.code == "quarantined_floor_conflict"


# ---------------------------------------------------------------------------
# (i) Event chain tamper resistance
# ---------------------------------------------------------------------------


def test_event_chain_rejects_stale_prev_digest_and_self_verifies(tmp_path):
    p = _make_pipeline(tmp_path, "events")
    p.remember(raw_body=b"event body one", project_id="proj-1")

    with pytest.raises(EventChainError):
        p.db.append_event(prev_digest=None, kind="FORCED_REPLAY", ref_digest="ab" * 32)
    with pytest.raises(EventChainError):
        p.db.append_event(prev_digest="ff" * 32, kind="FORCED_STALE", ref_digest="ab" * 32)

    p.remember(raw_body=b"event body two", project_id="proj-1")

    rows = p.db.event_log_rows()
    assert len(rows) >= 2
    prev = None
    for row in rows:
        payload = {
            "schema": "wiki-lifecycle-event-v1",
            "prev_digest": row["prev_digest"] or "",
            "event_kind": row["event_kind"],
            "ref_digest": row["ref_digest"],
        }
        message = EVENT_LOG_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(payload)
        expected_digest = hashlib.sha256(message).hexdigest()
        assert row["event_digest"] == expected_digest, "event_digest must self-verify"
        assert row["prev_digest"] == prev, "chain must be strictly forward-linked"
        prev = row["event_digest"]
    assert prev == p.db.event_chain_head()
