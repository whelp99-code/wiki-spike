"""Gate 2 encrypted-foundation red-team QA suite.

Adversarial mutation tests that TRY TO BREAK the Encrypted Single-Memory
Lifecycle foundation modules (ADR-0026 / ADR-0027, Gate 2): AES-256-GCM
envelope authentication, the nonce type split, the Ed25519 single
signature-input rule, the RFC 6962 history Merkle tree, the 256-level
sparse Merkle current map, the acyclic bundle self-field projection, dual
create-only keystore custody, binding-aware reconciliation, the opaque
encrypted content-addressed store, the lifecycle-db plaintext-column guard
and hash-chained event log, and the workspace-format no-fallback assertion.

Every attack below is expected to be RESISTED (the assertion is that the
invariant holds under adversarial mutation); a failure here means the Gate 2
foundation has a real bug, not a test bug.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import sqlite3

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike import workspace_format as wf
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure import encrypted_cas
from wiki_spike.infrastructure import keystore as ks
from wiki_spike.infrastructure import lifecycle_db as ldb
from wiki_spike.memory_core.contracts import canonical_bytes

DEK = os.urandom(32)
KEY_A = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"red-team-key-a").digest())
KEY_B = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"red-team-key-b").digest())


# ---------------------------------------------------------------------------
# Local proof-verification helpers (mirror the exact recursive constructions
# in crypto.py / binding_registry.py so tampering can be detected without
# depending on those modules' private helpers).
# ---------------------------------------------------------------------------


def _replay_inclusion(leaf_h: bytes, index: int, audit_path: list, tree_size: int) -> bytes:
    proof = list(audit_path)

    def replay(lo: int, hi: int) -> bytes:
        n = hi - lo
        if n <= 1:
            return leaf_h
        split = 1
        while split * 2 < n:
            split *= 2
        if index - lo < split:
            left = replay(lo, lo + split)
            right = proof.pop(0)
            return crypto.node_hash(left, right)
        right = replay(lo + split, hi)
        left = proof.pop(0)
        return crypto.node_hash(left, right)

    return replay(0, tree_size)


def _replay_consistency(old_size: int, new_size: int, audit_path: list) -> tuple:
    proof = list(audit_path)

    def replay(lo: int, hi: int, m: int) -> tuple:
        n = hi - lo
        if m == n:
            r = proof.pop(0)
            return r, r
        split = 1
        while split * 2 < n:
            split *= 2
        if m <= split:
            left_new, left_old = replay(lo, lo + split, m)
            right_new = proof.pop(0)
            return crypto.node_hash(left_new, right_new), left_old
        right_new, right_old = replay(lo + split, hi, m - split)
        left_new = proof.pop(0)
        return crypto.node_hash(left_new, right_new), crypto.node_hash(left_new, right_old)

    new_root, old_root = replay(0, new_size, old_size)
    assert not proof, "audit path not fully consumed"
    return old_root, new_root


def _replay_smt(key_int: int, leaf_value: bytes, siblings: list) -> bytes:
    node = leaf_value
    for depth in range(crypto.SMT_DEPTH - 1, -1, -1):
        sibling = siblings[depth]
        if crypto.smt_bit(key_int, depth) == 0:
            node = hashlib.sha256(b"\x02" + node + sibling).digest()
        else:
            node = hashlib.sha256(b"\x02" + sibling + node).digest()
    return node


def _map_key(label: str) -> int:
    return int(hashlib.sha256(label.encode("ascii")).hexdigest(), 16)


# ---------------------------------------------------------------------------
# (a) AES-256-GCM: tamper ciphertext/tag/AAD, reject bad DEK length/nonce shape.
# ---------------------------------------------------------------------------


def test_red_team_aes_gcm_tamper_ciphertext_byte_raises_invalid_tag():
    nonce_hex = os.urandom(12).hex()
    ct_hex, tag_hex = crypto.aes_gcm_seal(DEK, nonce_hex, b"top secret memory content", aad=b"aad-1")
    tampered = bytearray(bytes.fromhex(ct_hex))
    tampered[0] ^= 0x01
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(DEK, nonce_hex, bytes(tampered).hex(), tag_hex, aad=b"aad-1")


def test_red_team_aes_gcm_tamper_tag_byte_raises_invalid_tag():
    nonce_hex = os.urandom(12).hex()
    ct_hex, tag_hex = crypto.aes_gcm_seal(DEK, nonce_hex, b"payload", aad=b"aad-2")
    tampered_tag = bytearray(bytes.fromhex(tag_hex))
    tampered_tag[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(DEK, nonce_hex, ct_hex, bytes(tampered_tag).hex(), aad=b"aad-2")


def test_red_team_aes_gcm_tamper_aad_raises_invalid_tag():
    nonce_hex = os.urandom(12).hex()
    ct_hex, tag_hex = crypto.aes_gcm_seal(DEK, nonce_hex, b"payload", aad=b"correct-aad")
    with pytest.raises(InvalidTag):
        crypto.aes_gcm_open(DEK, nonce_hex, ct_hex, tag_hex, aad=b"attacker-forged-aad")


def test_red_team_aes_gcm_rejects_wrong_length_dek():
    nonce_hex = os.urandom(12).hex()
    with pytest.raises(ValueError):
        crypto.aes_gcm_seal(os.urandom(16), nonce_hex, b"payload")
    ct_hex, tag_hex = crypto.aes_gcm_seal(DEK, nonce_hex, b"payload")
    with pytest.raises(ValueError):
        crypto.aes_gcm_open(os.urandom(31), nonce_hex, ct_hex, tag_hex)


def test_red_team_aes_gcm_rejects_non_24_hex_nonce():
    with pytest.raises(ValueError):
        # 64-hex challenge-nonce-shaped value fed where a 24-hex AES-GCM
        # nonce is required.
        crypto.aes_gcm_seal(DEK, os.urandom(32).hex(), b"payload")
    with pytest.raises(ValueError):
        crypto.aes_gcm_open(DEK, "not-24-hex-chars", "", "")


# ---------------------------------------------------------------------------
# (b) Nonce type split: cross-type rejection both directions.
# ---------------------------------------------------------------------------


def test_red_team_nonce_type_split_rejects_cross_type_values():
    aes_nonce = os.urandom(12).hex()
    challenge_nonce = os.urandom(32).hex()
    assert crypto.is_aes_gcm_nonce_hex24(aes_nonce) is True
    assert crypto.is_aes_gcm_nonce_hex24(challenge_nonce) is False
    assert crypto.is_challenge_nonce_hex64(challenge_nonce) is True
    assert crypto.is_challenge_nonce_hex64(aes_nonce) is False


# ---------------------------------------------------------------------------
# (c) Ed25519 single signature-input rule: domain/key/payload binding.
# ---------------------------------------------------------------------------


def test_red_team_signature_fails_under_wrong_domain():
    payload = {"schema": "red-team-payload-v1", "value": "alpha"}
    sig = crypto.sign(KEY_A, "domain.one", payload)
    crypto.verify(KEY_A.public_key(), "domain.one", payload, sig)  # sanity: the honest path
    with pytest.raises(InvalidSignature):
        crypto.verify(KEY_A.public_key(), "domain.two", payload, sig)


def test_red_team_signature_fails_under_wrong_key():
    payload = {"schema": "red-team-payload-v1", "value": "beta"}
    sig = crypto.sign(KEY_A, "domain.one", payload)
    with pytest.raises(InvalidSignature):
        crypto.verify(KEY_B.public_key(), "domain.one", payload, sig)


def test_red_team_signature_fails_on_tampered_payload():
    payload = {"schema": "red-team-payload-v1", "value": "gamma"}
    sig = crypto.sign(KEY_A, "domain.one", payload)
    tampered_payload = dict(payload, value="gamma-tampered-by-attacker")
    with pytest.raises(InvalidSignature):
        crypto.verify(KEY_A.public_key(), "domain.one", tampered_payload, sig)


# ---------------------------------------------------------------------------
# (d) RFC 6962 Merkle: audit-path tamper breaks inclusion/consistency proofs.
# ---------------------------------------------------------------------------


def test_red_team_merkle_inclusion_proof_flipped_audit_node_breaks_verification():
    leaves = [crypto.leaf_hash(f"leaf-{i}".encode()) for i in range(7)]
    root = crypto.merkle_root(leaves)
    index = 3
    audit_path = crypto.merkle_inclusion_proof(leaves, index)
    assert audit_path, "a 7-leaf tree must have a non-trivial audit path"
    assert _replay_inclusion(leaves[index], index, audit_path, len(leaves)) == root

    flipped = list(audit_path)
    node = bytearray(flipped[0])
    node[0] ^= 0x01
    flipped[0] = bytes(node)
    assert _replay_inclusion(leaves[index], index, flipped, len(leaves)) != root


def test_red_team_merkle_consistency_proof_tampered_audit_path_forges_wrong_root():
    leaves = [crypto.leaf_hash(f"leaf-{i}".encode()) for i in range(7)]
    old_size, new_size = 4, 7
    audit_path = crypto.merkle_consistency_proof(leaves, old_size, new_size)
    old_root, new_root = _replay_consistency(old_size, new_size, audit_path)
    assert old_root == crypto.merkle_root(leaves[:old_size])
    assert new_root == crypto.merkle_root(leaves)

    tampered = list(audit_path)
    node = bytearray(tampered[0])
    node[0] ^= 0x01
    tampered[0] = bytes(node)
    tampered_old_root, tampered_new_root = _replay_consistency(old_size, new_size, tampered)
    # A verifier comparing against the checkpoint's real committed roots
    # must reject this: the tampered audit path must not reconstruct the
    # genuine old/new roots.
    assert tampered_old_root != old_root or tampered_new_root != new_root


# ---------------------------------------------------------------------------
# (e) 256-level SMT: leaf-value / sibling tamper breaks membership proofs.
# ---------------------------------------------------------------------------


def test_red_team_smt_membership_proof_fails_if_leaf_value_changed():
    items = {
        _map_key("key-a"): hashlib.sha256(b"value-a").digest(),
        _map_key("key-b"): hashlib.sha256(b"value-b").digest(),
    }
    root = crypto.smt_root(items)
    target = _map_key("key-a")
    siblings = crypto.smt_proof(items, target)
    assert _replay_smt(target, crypto.smt_leaf(target, items[target]), siblings) == root

    tampered_value = hashlib.sha256(b"value-a-tampered-by-attacker").digest()
    assert _replay_smt(target, crypto.smt_leaf(target, tampered_value), siblings) != root


def test_red_team_smt_nonmembership_proof_fails_if_sibling_tampered():
    items = {
        _map_key("key-a"): hashlib.sha256(b"value-a").digest(),
        _map_key("key-b"): hashlib.sha256(b"value-b").digest(),
    }
    root = crypto.smt_root(items)
    probe = _map_key("key-not-registered")
    assert probe not in items
    siblings = crypto.smt_proof(items, probe)
    default_leaf = crypto.SMT_DEFAULT[0]
    assert _replay_smt(probe, default_leaf, siblings) == root

    tampered = list(siblings)
    node = bytearray(tampered[0])
    node[0] ^= 0x01
    tampered[0] = bytes(node)
    assert _replay_smt(probe, default_leaf, tampered) != root


# ---------------------------------------------------------------------------
# (f) Bundle self-field projection: identity ignores self-fields, but raw
#     (non-projected) canonical bytes are NOT identity-stable.
# ---------------------------------------------------------------------------


def test_red_team_bundle_projection_invariant_to_self_fields_raw_bytes_are_not():
    base_manifest = {"schema": "wiki-artifact-bundle-manifest-v1", "entries": [{"path": "a.txt", "sha256": "x"}]}
    _manifest_bytes, bundle_sha256 = crypto.compute_bundle_digest(base_manifest)

    template_1 = {
        "schema": "wiki-encrypted-lifecycle-bundle-manifest-v1",
        "artifact_name": crypto.bundle_artifact_name("memory", "run-1", "attempt-1", bundle_sha256),
        "bundle_sha256": bundle_sha256,
        "manifest_digest": bundle_sha256,
    }
    projected_1, digest_1, size_1 = crypto.project_bundle_envelope(template_1)

    # Attack: mutate both self-fields — one to null, one to a different
    # nonempty value. The projected identity must not move, because both
    # self-fields are zeroed before canonicalization.
    template_2 = dict(template_1)
    template_2["artifact_name"] = None
    template_2["bundle_sha256"] = "0" * 64
    projected_2, digest_2, size_2 = crypto.project_bundle_envelope(template_2)
    assert projected_2 == projected_1
    assert digest_2 == digest_1
    assert size_2 == size_1

    # Attack: recompute the digest/size from RAW (non-projected) canonical
    # bytes instead of projected bytes. Raw bytes still embed the differing
    # self-field values, so this MUST diverge from the projected identity —
    # proving self-field projection (not raw canonicalization) is load-
    # bearing for the acyclic bundle identity.
    raw_bytes_1 = canonical_bytes(template_1)
    raw_bytes_2 = canonical_bytes(template_2)
    assert raw_bytes_1 != raw_bytes_2
    assert hashlib.sha256(raw_bytes_1).hexdigest() != digest_1
    assert len(raw_bytes_2) != size_1


# ---------------------------------------------------------------------------
# (g) Keystore create-only: overwrite/collision/re-create-after-destroy
#     rejection, receipt never leaks raw key material.
# ---------------------------------------------------------------------------


def _dek_hex() -> str:
    return os.urandom(32).hex()


def test_red_team_keystore_overwrite_with_different_key_material_rejected(tmp_path):
    store = ks.PlatformKeyStore(tmp_path / "platform")
    digest = hashlib.sha256(b"intent-x").hexdigest()
    store.create_only("ws-red", "handle-x", _dek_hex(), digest)
    with pytest.raises(ks.KeyAlreadyExists):
        # Same claimed intent, but the attacker supplies different wrapped
        # key bytes: create-only custody must never overwrite in place.
        store.create_only("ws-red", "handle-x", _dek_hex(), digest)


def test_red_team_keystore_never_recreates_destroyed_key(tmp_path):
    store = ks.PlatformKeyStore(tmp_path / "platform")
    digest = hashlib.sha256(b"intent-y").hexdigest()
    dek_hex = _dek_hex()
    store.create_only("ws-red", "handle-y", dek_hex, digest)
    store.destroy("ws-red", "handle-y")
    with pytest.raises(ks.KeyAlreadyDestroyed):
        # Attacker replays the ORIGINAL creation call verbatim after
        # destroy: forward-only custody must never resurrect a destroyed key.
        store.create_only("ws-red", "handle-y", dek_hex, digest)


def test_red_team_keystore_metadata_mismatch_collision_rejected(tmp_path):
    store = ks.PlatformKeyStore(tmp_path / "platform")
    store.create_only("ws-red", "handle-z", _dek_hex(), hashlib.sha256(b"intent-z1").hexdigest())
    with pytest.raises(ks.KeyCollision):
        # A different intent tries to claim the same handle.
        store.create_only("ws-red", "handle-z", _dek_hex(), hashlib.sha256(b"intent-z2").hexdigest())


def test_red_team_keystore_readback_receipt_never_carries_raw_key_material(tmp_path):
    store = ks.PlatformKeyStore(tmp_path / "platform")
    dek_hex = _dek_hex()
    digest = hashlib.sha256(b"intent-w").hexdigest()
    store.create_only("ws-red", "handle-w", dek_hex, digest)
    receipt = store.readback_challenge("ws-red", "handle-w")
    mapping = receipt.to_mapping()
    assert set(mapping) == {"namespace", "ark_handle", "metadata_digest", "receipt_digest", "verified"}
    serialized = json.dumps(mapping)
    assert dek_hex not in serialized
    assert "wrapped_dek_hex" not in mapping


# ---------------------------------------------------------------------------
# (h) Reconciliation fail-closed: corrupt/missing rows and ACTIVE/mismatch
#     bindings are never destroyed.
# ---------------------------------------------------------------------------


def test_red_team_reconciliation_corrupt_or_missing_rows_never_destroy():
    bindings = {
        "h1": ks.BindingRecord(status=ks.BindingStatus.UNBOUND, metadata_digest="d1"),
        "h2": ks.BindingRecord(status=ks.BindingStatus.LOSER, metadata_digest="d2"),
    }
    external = {
        "h1": ks.ExternalKeyRecord(metadata_digest="d1", corrupt=True),  # corrupted inventory row
        # h2 is entirely absent from the external inventory (missing row).
    }
    outcomes = ks.reconcile(bindings, external)
    destroy_count = sum(1 for v in outcomes.values() if v == ks.ReconciliationOutcome.DESTROY_UNBOUND)
    assert destroy_count == 0
    assert outcomes["h1"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN
    assert outcomes["h2"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_red_team_reconciliation_active_bound_or_metadata_mismatch_never_destroys():
    bindings = {
        "active-ok": ks.BindingRecord(status=ks.BindingStatus.ACTIVE, metadata_digest="match"),
        "active-forged": ks.BindingRecord(status=ks.BindingStatus.ACTIVE, metadata_digest="expected"),
    }
    external = {
        "active-ok": ks.ExternalKeyRecord(metadata_digest="match"),
        "active-forged": ks.ExternalKeyRecord(metadata_digest="attacker-forged"),
    }
    outcomes = ks.reconcile(bindings, external)
    assert outcomes["active-ok"] == ks.ReconciliationOutcome.RESUME_EXACT
    assert outcomes["active-forged"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN
    assert all(v != ks.ReconciliationOutcome.DESTROY_UNBOUND for v in outcomes.values())


# ---------------------------------------------------------------------------
# (i) Opaque CAS: plaintext markers rejected, malformed envelopes rejected,
#     write-once collision detection, corruption detection on read.
# ---------------------------------------------------------------------------


def test_red_team_cas_rejects_plaintext_bearing_json_object(tmp_path):
    store = encrypted_cas.EncryptedContentStore(tmp_path / "cas")
    poisoned = json.dumps({"schema": "wiki-envelope-v1", "plaintext": "attacker-leaked-secret"}).encode("utf-8")
    with pytest.raises(encrypted_cas.OpaqueViolation):
        store.put(poisoned)


def test_red_team_cas_rejects_malformed_envelope_json_object(tmp_path):
    store = encrypted_cas.EncryptedContentStore(tmp_path / "cas")
    malformed = json.dumps({"schema": "not-a-real-envelope-schema", "foo": "bar"}).encode("utf-8")
    with pytest.raises(encrypted_cas.OpaqueViolation):
        store.put(malformed)


def test_red_team_cas_put_is_write_once_rejects_colliding_id_for_different_bytes(tmp_path):
    store = encrypted_cas.EncryptedContentStore(tmp_path / "cas")
    original = b"\x01\x02\x03opaque-ciphertext-bytes-red-team"
    blob_id = store.put(original)

    # Simulate an adversary/disk-corruption scenario where the bytes stored
    # under this content-address no longer match the content that named it.
    path = store.objects / blob_id
    path.chmod(0o644)
    path.write_bytes(b"attacker-substituted-different-bytes")

    with pytest.raises(encrypted_cas.IntegrityError):
        store.put(original)  # re-put of the ORIGINAL content must detect the swap


def test_red_team_cas_get_detects_corruption_after_write(tmp_path):
    store = encrypted_cas.EncryptedContentStore(tmp_path / "cas")
    blob_id = store.put(b"\x09\x08\x07another-opaque-blob-red-team")
    path = store.objects / blob_id
    path.chmod(0o644)
    data = bytearray(path.read_bytes())
    data[0] ^= 0xFF
    path.write_bytes(bytes(data))
    with pytest.raises(encrypted_cas.IntegrityError):
        store.get(blob_id)


# ---------------------------------------------------------------------------
# (j) lifecycle_db: plaintext-column guard, stale prev_digest, hash chain
#     integrity, no body param, convergent winner election.
# ---------------------------------------------------------------------------


def test_red_team_lifecycle_db_injected_plaintext_column_trips_guard(tmp_path):
    db = ldb.LifecycleDatabase(db_path=tmp_path / "lifecycle.sqlite3")
    db.initialize()
    try:
        db.con.execute("ALTER TABLE candidate_review ADD COLUMN reviewer_comment_text TEXT")
        with pytest.raises(ldb.LifecycleDbError):
            ldb.assert_no_plaintext_columns(db.con)
    finally:
        db.close()


def test_red_team_lifecycle_db_stale_prev_digest_rejected_and_chain_verifies(tmp_path):
    db = ldb.LifecycleDatabase(db_path=tmp_path / "lifecycle.sqlite3")
    db.initialize()
    try:
        first_digest = db.append_event(None, "ARTIFACT_CREATED", hashlib.sha256(b"ref-1").hexdigest())
        with pytest.raises(ldb.EventChainError):
            # Adversary replays a stale prev_digest (None) instead of the
            # real current head, attempting to fork the chain.
            db.append_event(None, "ARTIFACT_CREATED", hashlib.sha256(b"ref-2").hexdigest())

        second_digest = db.append_event(first_digest, "ARTIFACT_SEALED", hashlib.sha256(b"ref-2").hexdigest())

        rows = db.event_log_rows()
        assert len(rows) == 2  # the rejected append must never have written a row
        prev = None
        for row in rows:
            assert row["prev_digest"] == prev
            payload = {
                "schema": "wiki-lifecycle-event-v1",
                "prev_digest": row["prev_digest"] or "",
                "event_kind": row["event_kind"],
                "ref_digest": row["ref_digest"],
            }
            message = ldb.EVENT_LOG_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(payload)
            assert hashlib.sha256(message).hexdigest() == row["event_digest"]
            prev = row["event_digest"]
        assert second_digest == rows[-1]["event_digest"]
    finally:
        db.close()


def test_red_team_lifecycle_db_append_event_signature_carries_no_body_parameter():
    params = set(inspect.signature(ldb.LifecycleDatabase.append_event).parameters)
    assert params == {"self", "prev_digest", "kind", "ref_digest"}


def test_red_team_lifecycle_db_canonical_artifact_duplicate_tuple_rejected(tmp_path):
    db = ldb.LifecycleDatabase(db_path=tmp_path / "lifecycle.sqlite3")
    db.initialize()
    try:
        with db.unit_of_work() as uow:
            uow.insert_canonical_artifact("art-1", "ws-1", "memory", "rev-1", "CANDIDATE", "2026-01-01T00:00:00Z")
        with pytest.raises(sqlite3.IntegrityError):
            with db.unit_of_work() as uow:
                # A different artifact_id claims the same (workspace_id,
                # artifact_kind, revision_id) tuple: only one winner may
                # ever be elected for that tuple.
                uow.insert_canonical_artifact(
                    "art-2", "ws-1", "memory", "rev-1", "CANDIDATE", "2026-01-01T00:00:01Z"
                )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# (k) workspace_format: profile mismatch is a hard error, no runtime fallback.
# ---------------------------------------------------------------------------


def test_red_team_workspace_format_profile_mismatch_raises_no_fallback():
    marker = wf.WorkspaceFormatMarker.create(
        workspace_id="ws-red-team",
        profile_selection=wf.ProfileSelection.SQLCIPHER,
        encrypted_lifecycle_enabled=True,
    )
    with pytest.raises(wf.WorkspaceFormatError):
        wf.assert_marker_matches(marker, expected_profile=wf.ProfileSelection.FIELD_AEAD)
    # The matching profile must not raise (this is not a runtime fallback,
    # just confirming the assertion is not vacuously always-raising).
    wf.assert_marker_matches(marker, expected_profile=wf.ProfileSelection.SQLCIPHER)
