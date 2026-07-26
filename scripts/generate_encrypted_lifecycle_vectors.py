#!/usr/bin/env python3
"""Reference encoder (generator/oracle #1) for the Encrypted Single-Memory
Lifecycle Gate 1 test vectors.

Authority: ADR-0026 (authority/identity), ADR-0027 (recovery/deletion), and
the ralplan Stage 08/09/10 plan artifacts (stage-10-revision.md, R10,
supersession authoritative).

This script is the ONLY vector producer permitted to import the frozen Core
canonicalizer (`wiki_spike.memory_core.contracts.canonical_bytes`). It MUST
NEVER be its own oracle: `scripts/validate_encrypted_lifecycle_vectors.py`
independently reimplements canonicalization and every hash/HMAC/HKDF/
signature/root/proof/digest from scratch, without importing this module or
`wiki_spike`, and asserts byte-for-byte equality against the fixtures this
script writes.

All keys below are DETERMINISTIC, HARDCODED, and TEST-ONLY. They MUST NEVER
be used for anything but generating/validating these fixtures.

Run: PYTHONPATH=src python3 scripts/generate_encrypted_lifecycle_vectors.py
"""
from __future__ import annotations

import hashlib
import hmac
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle"

# ---------------------------------------------------------------------------
# TEST-ONLY deterministic key material. Never use outside this vector suite.
# ---------------------------------------------------------------------------

TEST_ONLY_ROOT_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()

TEST_ONLY_ED25519_SEED_1 = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ED25519-SEED-1"
).digest()
TEST_ONLY_ED25519_SEED_2 = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ED25519-SEED-2"
).digest()

SIGNING_KEY_1 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_1)
SIGNING_KEY_2 = Ed25519PrivateKey.from_private_bytes(TEST_ONLY_ED25519_SEED_2)
SIGNER_KEY_ID_1 = "test-signer-1"
SIGNER_KEY_ID_2 = "test-signer-2"

HKDF_LABELS = [
    "command_digest_key_v1",
    "manifest_digest_key_v1",
    "artifact_identity_key_v1",
    "subject_identity_key_v1",
    "object_identity_key_v1",
    "revision_identity_key_v1",
    "stable_subject_key_v1",
    "locator_identity_key_v1",
]

# ---------------------------------------------------------------------------
# Crypto primitives (RFC 5869 HKDF-SHA-256, HMAC-SHA-256, SHA-256)
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hkdf_salt(label: str) -> bytes:
    return hashlib.sha256(b"WIKI-SPIKE-TEST-ONLY-HKDF-SALT-V1:" + label.encode("ascii")).digest()


def hkdf_info(label: str) -> bytes:
    return label.encode("ascii") + b"\x00v1"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


DERIVED_KEYS = {
    label: hkdf_sha256(TEST_ONLY_ROOT_IKM, hkdf_salt(label), hkdf_info(label))
    for label in HKDF_LABELS
}


def identity_hmac_hex(label: str, payload: dict) -> str:
    key = DERIVED_KEYS[label]
    msg = canonical_bytes(payload)
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def domain_prefix(domain: str) -> bytes:
    return domain.encode("ascii") + b"\x00"


def sign(key: Ed25519PrivateKey, domain: str, payload: dict) -> str:
    signature_input = domain_prefix(domain) + canonical_bytes(payload)
    return key.sign(signature_input).hex()


# ---------------------------------------------------------------------------
# RFC 6962-style append-only Merkle tree (history root / inclusion /
# consistency proofs).
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: list[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    split = 1
    while split * 2 < n:
        split *= 2
    return node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def merkle_root(leaves: list[bytes]) -> bytes:
    return _merkle_root(leaves)


def merkle_inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    def rec(lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        split = 1
        while split * 2 < n:
            split *= 2
        if index - lo < split:
            return rec(lo, lo + split) + [_merkle_root(leaves[lo + split:hi])]
        return rec(lo + split, hi) + [_merkle_root(leaves[lo:lo + split])]

    return rec(0, len(leaves))


def merkle_consistency_proof(leaves: list[bytes], old_size: int, new_size: int) -> list[bytes]:
    def subproof(lo: int, hi: int, m: int, complete: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            if complete:
                return []
            return [_merkle_root(leaves[lo:hi])]
        split = 1
        while split * 2 < n:
            split *= 2
        if m <= split:
            return subproof(lo, lo + split, m, False) + [_merkle_root(leaves[lo + split:hi])]
        right = subproof(lo + split, hi, m - split, complete and m == n)
        return right + [_merkle_root(leaves[lo:lo + split])]

    if old_size == 0 or old_size == new_size:
        return []
    return subproof(0, new_size, old_size, True)


# ---------------------------------------------------------------------------
# Sparse Merkle Tree (256-level, current-map root / membership /
# non-membership proofs).
# ---------------------------------------------------------------------------

SMT_DEPTH = 256
SMT_DEFAULT: list[bytes] = [hashlib.sha256(b"\x00").digest()]
for _i in range(SMT_DEPTH):
    SMT_DEFAULT.append(hashlib.sha256(b"\x02" + SMT_DEFAULT[-1] + SMT_DEFAULT[-1]).digest())


def smt_bit(key_int: int, depth: int) -> int:
    return (key_int >> (SMT_DEPTH - 1 - depth)) & 1


def smt_leaf(key_int: int, value: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + key_int.to_bytes(32, "big") + value).digest()


def smt_node(items: dict[int, bytes], depth: int) -> bytes:
    if not items:
        return SMT_DEFAULT[SMT_DEPTH - depth]
    if depth == SMT_DEPTH:
        ((key_int, value),) = items.items()
        return smt_leaf(key_int, value)
    left = {k: v for k, v in items.items() if smt_bit(k, depth) == 0}
    right = {k: v for k, v in items.items() if smt_bit(k, depth) == 1}
    return hashlib.sha256(b"\x02" + smt_node(left, depth + 1) + smt_node(right, depth + 1)).digest()


def smt_root(items: dict[int, bytes]) -> bytes:
    return smt_node(items, 0)


def smt_proof(items: dict[int, bytes], key_int: int) -> list[bytes]:
    siblings: list[bytes] = []

    def rec(cur_items: dict[int, bytes], depth: int) -> None:
        if depth == SMT_DEPTH:
            return
        left = {k: v for k, v in cur_items.items() if smt_bit(k, depth) == 0}
        right = {k: v for k, v in cur_items.items() if smt_bit(k, depth) == 1}
        if smt_bit(key_int, depth) == 0:
            siblings.append(smt_node(right, depth + 1))
            rec(left, depth + 1)
        else:
            siblings.append(smt_node(left, depth + 1))
            rec(right, depth + 1)

    rec(items, 0)
    return siblings


def hexkey_to_int(hex64: str) -> int:
    return int(hex64, 16)


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def write_json(name: str, payload: dict) -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    path = FIXTURES_DIR / name
    text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.write_text(text, encoding="utf-8")


WORKSPACE_ID = "ws-test-1"


# ---------------------------------------------------------------------------
# 1. identity-vectors-v1.json
# ---------------------------------------------------------------------------


def build_identity_vectors() -> dict:
    def command_msg(kind: str, options: dict, input_digest: str, policy_digest: str) -> dict:
        return {
            "domain": "wiki.command",
            "version": "1",
            "key_version": "1",
            "workspace_id": WORKSPACE_ID,
            "command_kind": kind,
            "normalized_options": options,
            "input_content_digest": input_digest,
            "policy_context_digest": policy_digest,
        }

    def artifact_semantic_msg(consent_epoch: str, body_text: str) -> dict:
        return {
            "domain": "wiki.artifact-semantic",
            "version": "1",
            "key_version": "1",
            "workspace_id": WORKSPACE_ID,
            "artifact_kind": "MEMORY_REVISION",
            "consent_epoch": consent_epoch,
            "semantic_schema": "MemoryRevisionSemanticV1",
            "semantic_plaintext": {"locator_text": body_text, "body": body_text},
        }

    def object_id_msg(consent_epoch: str, subject_digest: str) -> dict:
        return {
            "domain": "wiki.logical-object-id",
            "version": "1",
            "key_version": "1",
            "workspace_id": WORKSPACE_ID,
            "object_kind": "MEMORY",
            "consent_epoch": consent_epoch,
            "subject_key_digest": subject_digest,
        }

    def revision_id_msg(logical_object_id: str, consent_epoch: str, revision_number: str,
                         parent_revision_id, artifact_semantic_digest: str) -> dict:
        return {
            "domain": "wiki.revision-id",
            "version": "1",
            "key_version": "1",
            "workspace_id": WORKSPACE_ID,
            "object_kind": "MEMORY",
            "logical_object_id": logical_object_id,
            "consent_epoch": consent_epoch,
            "revision_number": revision_number,
            "parent_revision_id": parent_revision_id,
            "artifact_semantic_digest": artifact_semantic_digest,
        }

    def manifest_msg(command_digest: str, entries: list[dict]) -> dict:
        return {
            "domain": "wiki.command-manifest",
            "version": "1",
            "key_version": "1",
            "workspace_id": WORKSPACE_ID,
            "command_digest": command_digest,
            "entries": entries,
        }

    subject_digest = sha256_hex(b"subject:test-topic")
    obj_msg = object_id_msg("1", subject_digest)
    logical_object_id = identity_hmac_hex("object_identity_key_v1", obj_msg)

    cases = []

    # Case 1: first-remember
    body1 = "first remember body"
    input_digest1 = sha256_hex(body1.encode("utf-8"))
    policy_digest = sha256_hex(b"policy-v1")
    cmd1 = command_msg("REMEMBER", {"note": "first-remember"}, input_digest1, policy_digest)
    cmd1_id = identity_hmac_hex("command_digest_key_v1", cmd1)
    sem1 = artifact_semantic_msg("1", body1)
    sem1_digest = identity_hmac_hex("artifact_identity_key_v1", sem1)
    rev1 = revision_id_msg(logical_object_id, "1", "1", None, sem1_digest)
    rev1_id = identity_hmac_hex("revision_identity_key_v1", rev1)
    manifest1 = manifest_msg(cmd1_id, [{
        "artifact_role": "PRIMARY_MEMORY", "ordinal": "0", "artifact_kind": "MEMORY_REVISION",
        "revision_id": rev1_id, "artifact_semantic_digest": sem1_digest,
    }])
    manifest1_digest = identity_hmac_hex("manifest_digest_key_v1", manifest1)
    cases.append({
        "name": "first-remember",
        "object_id_message": obj_msg,
        "logical_object_id": logical_object_id,
        "command_message": cmd1,
        "command_id": cmd1_id,
        "artifact_semantic_message": sem1,
        "artifact_semantic_digest": sem1_digest,
        "revision_id_message": rev1,
        "revision_id": rev1_id,
        "manifest_message": manifest1,
        "manifest_digest": manifest1_digest,
    })

    # Case 2: correction R1 -> R2
    body2 = "corrected body"
    input_digest2 = sha256_hex(body2.encode("utf-8"))
    cmd2 = command_msg("CORRECT", {"note": "correction"}, input_digest2, policy_digest)
    cmd2_id = identity_hmac_hex("command_digest_key_v1", cmd2)
    sem2 = artifact_semantic_msg("1", body2)
    sem2_digest = identity_hmac_hex("artifact_identity_key_v1", sem2)
    rev2 = revision_id_msg(logical_object_id, "1", "2", rev1_id, sem2_digest)
    rev2_id = identity_hmac_hex("revision_identity_key_v1", rev2)
    cases.append({
        "name": "correction-r1-to-r2",
        "parent_revision_id": rev1_id,
        "command_message": cmd2,
        "command_id": cmd2_id,
        "artifact_semantic_message": sem2,
        "artifact_semantic_digest": sem2_digest,
        "revision_id_message": rev2,
        "revision_id": rev2_id,
    })

    # Case 3: semantic convergence -- two distinct commands, same resulting revision id
    body3 = "converged body"
    sem3 = artifact_semantic_msg("1", body3)
    sem3_digest = identity_hmac_hex("artifact_identity_key_v1", sem3)
    rev3 = revision_id_msg(logical_object_id, "1", "3", rev2_id, sem3_digest)
    rev3_id = identity_hmac_hex("revision_identity_key_v1", rev3)

    cmd3a = command_msg("REMEMBER", {"note": "path-a"}, sha256_hex(b"path-a-input"), policy_digest)
    cmd3a_id = identity_hmac_hex("command_digest_key_v1", cmd3a)
    cmd3b = command_msg("CORRECT", {"note": "path-b"}, sha256_hex(b"path-b-input"), policy_digest)
    cmd3b_id = identity_hmac_hex("command_digest_key_v1", cmd3b)
    cases.append({
        "name": "semantic-convergence",
        "artifact_semantic_message": sem3,
        "artifact_semantic_digest": sem3_digest,
        "revision_id_message": rev3,
        "revision_id": rev3_id,
        "command_a": {"message": cmd3a, "command_id": cmd3a_id},
        "command_b": {"message": cmd3b, "command_id": cmd3b_id},
        "assertion": "command_a.command_id != command_b.command_id; both converge on revision_id",
    })

    # Case 4: idempotency mismatch -- same kind/options/input, different policy context
    cmd4a = command_msg("REMEMBER", {"note": "idempotency-check"}, sha256_hex(b"same-input"), sha256_hex(b"policy-v1"))
    cmd4a_id = identity_hmac_hex("command_digest_key_v1", cmd4a)
    cmd4b = command_msg("REMEMBER", {"note": "idempotency-check"}, sha256_hex(b"same-input"), sha256_hex(b"policy-v2"))
    cmd4b_id = identity_hmac_hex("command_digest_key_v1", cmd4b)
    cases.append({
        "name": "idempotency-mismatch",
        "command_a": {"message": cmd4a, "command_id": cmd4a_id},
        "command_b": {"message": cmd4b, "command_id": cmd4b_id},
        "assertion": "differing policy_context_digest yields differing command_id (not idempotent)",
    })

    # Case 5: expected-active conflict -- stale parent_revision_id vs current active
    rev5_stale = revision_id_msg(logical_object_id, "1", "4", rev1_id, sem3_digest)
    rev5_stale_id = identity_hmac_hex("revision_identity_key_v1", rev5_stale)
    cases.append({
        "name": "expected-active-conflict",
        "revision_id_message": rev5_stale,
        "revision_id": rev5_stale_id,
        "expected_active_revision_id": rev3_id,
        "actual_parent_used": rev1_id,
        "assertion": "expected_active_revision_id != actual_parent_used => conflict",
        "expected_conflict": True,
    })

    return {"schema": "wiki-encrypted-lifecycle-identity-vectors-v1", "workspace_id": WORKSPACE_ID, "cases": cases}


# ---------------------------------------------------------------------------
# 2. kdf-vectors-v1.json
# ---------------------------------------------------------------------------


def build_kdf_vectors() -> dict:
    entries = []
    for label in HKDF_LABELS:
        salt = hkdf_salt(label)
        info = hkdf_info(label)
        output = DERIVED_KEYS[label]
        entries.append({
            "label": label,
            "ikm_ref": "test_only_root_ikm",
            "salt_hex": salt.hex(),
            "info_hex": info.hex(),
            "output_hex": output.hex(),
        })
    return {
        "schema": "wiki-encrypted-lifecycle-kdf-vectors-v1",
        "algorithm": "HKDF-SHA-256",
        "ikm_hex_test_only": TEST_ONLY_ROOT_IKM.hex(),
        "labels": entries,
    }


# ---------------------------------------------------------------------------
# 3. nonce-vectors-v1.json
# ---------------------------------------------------------------------------


def build_nonce_vectors() -> dict:
    aes_valid = sha256_hex(b"test-aes-nonce-1")[:24]
    aes_invalid_short = aes_valid[:22]
    aes_invalid_long = aes_valid + "ab"
    aes_invalid_nonhex = "g" + aes_valid[1:]

    challenge_valid = sha256_hex(b"test-challenge-nonce-1")
    challenge_invalid_short = challenge_valid[:62]
    challenge_invalid_long = challenge_valid + "ab"
    challenge_invalid_nonhex = "g" + challenge_valid[1:]

    return {
        "schema": "wiki-encrypted-lifecycle-nonce-vectors-v1",
        "aes_gcm_nonce_hex24": {
            "pattern": "^[0-9a-f]{24}$",
            "valid": [aes_valid],
            "invalid": [
                {"value": aes_invalid_short, "reason": "width_22_not_24"},
                {"value": aes_invalid_long, "reason": "width_26_not_24"},
                {"value": aes_invalid_nonhex, "reason": "non_hex_character"},
            ],
        },
        "challenge_nonce_hex64": {
            "pattern": "^[0-9a-f]{64}$",
            "valid": [challenge_valid],
            "invalid": [
                {"value": challenge_invalid_short, "reason": "width_62_not_64"},
                {"value": challenge_invalid_long, "reason": "width_66_not_64"},
                {"value": challenge_invalid_nonhex, "reason": "non_hex_character"},
            ],
        },
        "cross_use_rejection": [
            {
                "value": aes_valid,
                "tested_as": "challenge_nonce_hex64",
                "expected": "reject",
                "reason": "width_24_not_64_even_though_hex",
            },
            {
                "value": challenge_valid,
                "tested_as": "aes_gcm_nonce_hex24",
                "expected": "reject",
                "reason": "width_64_not_24_even_though_hex",
            },
        ],
    }


# ---------------------------------------------------------------------------
# 4. binding-wire-vectors-v1.json
# ---------------------------------------------------------------------------

DOMAIN_ATTESTATION = "wiki.binding.latest-read-attestation.v1"
DOMAIN_HISTORY_LEAF = "wiki.binding.history-leaf.v1"
DOMAIN_CHECKPOINT = "wiki.binding.checkpoint.v1"


def build_binding_wire_vectors() -> dict:
    # --- BindingLatestReadAttestationPayloadV1 ---
    attestation_payload = {
        "schema": "wiki-binding-latest-read-attestation-v1",
        "workspace_id": WORKSPACE_ID,
        "request_nonce": sha256_hex(b"test-challenge-nonce-1"),
        "challenge_counter": "1",
        "request_floor_checkpoint_id": sha256_hex(b"floor-checkpoint-genesis"),
        "checkpoint_id": sha256_hex(b"checkpoint-1"),
        "checkpoint_sha256": sha256_hex(b"checkpoint-1"),
        "checkpoint_sequence": "1",
        "history_size": "3",
        "history_root": "",  # filled below once history root is computed
        "current_map_size": "3",
        "current_map_root": "",  # filled below once map root is computed
        "signer_key_id": SIGNER_KEY_ID_1,
        "issued_at": "2026-07-24T00:00:00Z",
        "expires_at": "2026-07-24T00:05:00Z",
    }

    # --- Binding registry leaves (3) ---
    def make_leaf(seq: str, handle: str, status: str, prior_leaf_hash) -> dict:
        return {
            "schema": "wiki-binding-registry-leaf-v1",
            "workspace_id": WORKSPACE_ID,
            "registry_sequence": seq,
            "namespace": "encrypted-lifecycle",
            "provider_handle": handle,
            "provider_key_fingerprint": sha256_hex(handle.encode() + b"-fingerprint"),
            "intent_id": sha256_hex(handle.encode() + b"-intent"),
            "artifact_id": sha256_hex(handle.encode() + b"-artifact"),
            "revision_id": sha256_hex(handle.encode() + b"-revision"),
            "semantic_digest": sha256_hex(handle.encode() + b"-semantic"),
            "metadata_digest": sha256_hex(handle.encode() + b"-metadata"),
            "status": status,
            "activation_generation_id": sha256_hex(handle.encode() + b"-generation") if status == "ACTIVE" else None,
            "prior_leaf_hash": prior_leaf_hash,
        }

    leaves = []
    signed_leaves = []
    leaf_hashes = []
    prior = None
    for i, (handle, status) in enumerate([
        ("provider-a", "PREPARED"),
        ("provider-b", "ACTIVE"),
        ("provider-c", "LOSER"),
    ], start=1):
        leaf = make_leaf(str(i), handle, status, prior)
        lh = leaf_hash(canonical_bytes(leaf))
        prior = lh.hex()
        sig = sign(SIGNING_KEY_1, DOMAIN_HISTORY_LEAF, leaf)
        signed = {
            "leaf": leaf,
            "leaf_signature": {
                "schema": "wiki-binding-registry-leaf-signature-v1",
                "algorithm": "Ed25519",
                "key_id": SIGNER_KEY_ID_1,
                "leaf_hash": sha256_hex(canonical_bytes(leaf)),
                "signature": sig,
            },
        }
        leaves.append(leaf)
        signed_leaves.append(signed)
        leaf_hashes.append(leaf_hash(canonical_bytes(signed)))

    history_root = merkle_root(leaf_hashes)
    history_size = len(leaf_hashes)

    # --- Sparse current map (3 populated leaves out of 2^256) ---
    def map_key_for(leaf: dict) -> str:
        return sha256_hex(canonical_bytes({
            "domain": "wiki.binding-registry.current-key",
            "version": "1",
            "workspace_id": leaf["workspace_id"],
            "namespace": leaf["namespace"],
            "provider_handle": leaf["provider_handle"],
        }))

    smt_items: dict[int, bytes] = {}
    map_keys = []
    for leaf, signed in zip(leaves, signed_leaves):
        mk_hex = map_key_for(leaf)
        map_keys.append(mk_hex)
        smt_items[hexkey_to_int(mk_hex)] = hashlib.sha256(canonical_bytes(signed)).digest()

    current_map_root = smt_root(smt_items)

    attestation_payload["history_root"] = history_root.hex()
    attestation_payload["current_map_root"] = current_map_root.hex()
    attestation_signature = sign(SIGNING_KEY_1, DOMAIN_ATTESTATION, attestation_payload)
    attestation_wire = {
        "payload": attestation_payload,
        "signature_algorithm": "Ed25519",
        "signature": attestation_signature,
    }

    # --- Checkpoint ---
    checkpoint = {
        "schema": "wiki-binding-registry-checkpoint-v1",
        "workspace_id": WORKSPACE_ID,
        "generation_id": sha256_hex(b"generation-1"),
        "registry_sequence": "3",
        "history_size": str(history_size),
        "history_root": history_root.hex(),
        "current_leaf_count": "3",
        "current_map_root": current_map_root.hex(),
        "veto_set_size": "0",
        "veto_set_root": SMT_DEFAULT[SMT_DEPTH].hex(),
        "transition_size": "0",
        "transition_root": SMT_DEFAULT[SMT_DEPTH].hex(),
        "created_at": "2026-07-24T00:05:00Z",
        "prior_checkpoint_hash": None,
        "signer_key_id": SIGNER_KEY_ID_1,
    }
    checkpoint_sha256 = sha256_hex(canonical_bytes(checkpoint))
    checkpoint_signature = {
        "schema": "wiki-binding-registry-checkpoint-signature-v1",
        "algorithm": "Ed25519",
        "key_id": SIGNER_KEY_ID_1,
        "checkpoint_sha256": checkpoint_sha256,
        "signature": sign(SIGNING_KEY_1, DOMAIN_CHECKPOINT, checkpoint),
    }

    # --- Membership / non-membership proofs ---
    member_key_hex = map_keys[0]
    member_key_int = hexkey_to_int(member_key_hex)
    member_siblings = smt_proof(smt_items, member_key_int)
    membership_proof = {
        "schema": "wiki-binding-current-membership-proof-v1",
        "map_key": member_key_hex,
        "signed_leaf": signed_leaves[0],
        "siblings": [s.hex() for s in member_siblings],
    }

    nonmember_key_hex = sha256_hex(b"unregistered-provider-handle")
    nonmember_key_int = hexkey_to_int(nonmember_key_hex)
    nonmember_siblings = smt_proof(smt_items, nonmember_key_int)
    nonmembership_proof = {
        "schema": "wiki-binding-current-nonmembership-proof-v1",
        "map_key": nonmember_key_hex,
        "signed_leaf": None,
        "siblings": [s.hex() for s in nonmember_siblings],
    }

    # --- History inclusion + consistency proofs ---
    inclusion_index = 1  # second leaf (0-indexed)
    inclusion_audit = merkle_inclusion_proof(leaf_hashes, inclusion_index)
    inclusion_proof = {
        "schema": "wiki-binding-history-inclusion-proof-v1",
        "history_size": str(history_size),
        "leaf_index": str(inclusion_index),
        "audit_path": [h.hex() for h in inclusion_audit],
    }

    consistency_audit = merkle_consistency_proof(leaf_hashes, 2, 3)
    consistency_proof = {
        "schema": "wiki-binding-history-consistency-proof-v1",
        "old_size": "2",
        "new_size": "3",
        "audit_path": [h.hex() for h in consistency_audit],
    }

    proof_set = {
        "schema": "wiki-binding-registry-proof-set-v1",
        "attestation": attestation_wire,
        "checkpoint": checkpoint,
        "checkpoint_signature": checkpoint_signature,
        "current_leaf": signed_leaves[1],
        "current_sparse_proof": membership_proof,
        "predecessor_transition_leaves": [],
        "history_inclusion_proofs": [inclusion_proof],
        "history_consistency_proof": consistency_proof,
    }

    # --- Tamper mutations ---
    def flip_hex_char(value: str) -> str:
        ch = value[0]
        replacement = "0" if ch != "0" else "1"
        return replacement + value[1:]

    tamper_root = dict(checkpoint)
    tamper_root["history_root"] = flip_hex_char(checkpoint["history_root"])

    tamper_size = dict(checkpoint)
    tamper_size["history_size"] = str(int(checkpoint["history_size"]) + 1)

    tamper_leaf = dict(leaves[0])
    tamper_leaf["revision_id"] = flip_hex_char(tamper_leaf["revision_id"])

    tamper_signature = flip_hex_char(checkpoint_signature["signature"])

    tamper_cases = [
        {
            "case": "root_flip",
            "field": "history_root",
            "original": checkpoint,
            "mutated": tamper_root,
            "expected_error": "history_root_mismatch",
        },
        {
            "case": "size_flip",
            "field": "history_size",
            "original": checkpoint,
            "mutated": tamper_size,
            "expected_error": "history_size_mismatch",
        },
        {
            "case": "leaf_flip",
            "field": "revision_id",
            "original": leaves[0],
            "mutated": tamper_leaf,
            "expected_error": "leaf_hash_mismatch",
        },
        {
            "case": "signature_flip",
            "field": "checkpoint_signature.signature",
            "original_signature": checkpoint_signature["signature"],
            "mutated_signature": tamper_signature,
            "expected_error": "signature_invalid",
        },
        {
            "case": "domain_flip",
            "field": "verification_domain",
            "original_domain": DOMAIN_CHECKPOINT,
            "wrong_domain": DOMAIN_HISTORY_LEAF,
            "signature": checkpoint_signature["signature"],
            "signer_key_id": SIGNER_KEY_ID_1,
            "expected_error": "domain_mismatch",
        },
    ]

    return {
        "schema": "wiki-encrypted-lifecycle-binding-wire-vectors-v1",
        "signer_public_keys": {
            SIGNER_KEY_ID_1: SIGNING_KEY_1.public_key().public_bytes_raw().hex(),
            SIGNER_KEY_ID_2: SIGNING_KEY_2.public_key().public_bytes_raw().hex(),
        },
        "domains": {
            "attestation": DOMAIN_ATTESTATION + "\u0000",
            "history_leaf": DOMAIN_HISTORY_LEAF + "\u0000",
            "checkpoint": DOMAIN_CHECKPOINT + "\u0000",
        },
        "attestation": attestation_wire,
        "attestation_canonical_bytes_hex": canonical_bytes(attestation_payload).hex(),
        "leaves": leaves,
        "signed_leaves": signed_leaves,
        "leaf_hashes_hex": [h.hex() for h in leaf_hashes],
        "history_root": history_root.hex(),
        "current_map_root": current_map_root.hex(),
        "checkpoint": checkpoint,
        "checkpoint_signature": checkpoint_signature,
        "membership_proof": membership_proof,
        "nonmembership_proof": nonmembership_proof,
        "history_inclusion_proof": inclusion_proof,
        "history_consistency_proof": consistency_proof,
        "proof_set": proof_set,
        "cross_domain_vector": {
            "description": "attestation signature valid under its own domain must fail under checkpoint domain",
            "payload": attestation_payload,
            "signature": attestation_signature,
            "valid_domain": DOMAIN_ATTESTATION,
            "invalid_domain": DOMAIN_CHECKPOINT,
            "signer_key_id": SIGNER_KEY_ID_1,
        },
        "cross_key_vector": {
            "description": "checkpoint signature made by signer 2, verification under signer 1's public key must fail",
            "payload": checkpoint,
            "domain": DOMAIN_CHECKPOINT,
            "signature": sign(SIGNING_KEY_2, DOMAIN_CHECKPOINT, checkpoint),
            "signer_key_id_used": SIGNER_KEY_ID_2,
            "verify_against_key_id": SIGNER_KEY_ID_1,
        },
        "tamper_cases": tamper_cases,
    }


# ---------------------------------------------------------------------------
# 5. floor-state-vectors-v1.json
# ---------------------------------------------------------------------------


def floor_candidate_bytes(veto_size: str, veto_root: str, tsize: str, troot: str,
                           thead: str, prior_hash: str) -> dict:
    return {
        "veto_set_size": veto_size,
        "veto_set_root": veto_root,
        "transition_size": tsize,
        "transition_root": troot,
        "transition_head": thead,
        "prior_floor_hash": prior_hash,
    }


def build_floor_state_vectors() -> dict:
    old_floor_hash = sha256_hex(b"floor-genesis")
    candidate_bytes_a = floor_candidate_bytes(
        "1", sha256_hex(b"veto-root-1"), "1", sha256_hex(b"transition-root-1"),
        sha256_hex(b"transition-head-1"), old_floor_hash,
    )
    candidate_hash_a = sha256_hex(canonical_bytes(candidate_bytes_a))
    attempt_id = sha256_hex(b"attempt-1")

    def floor_state(state: str, counter: str, candidate, ts: str) -> dict:
        return {
            "schema": "wiki-floor-state-v1",
            "workspace_id": WORKSPACE_ID,
            "state": state,
            "last_challenge_counter": counter,
            "floor_candidate": candidate,
            "updated_at": ts,
        }

    def candidate(kind: str, disposition: str, counter: str, reason=None,
                  hash_override=None, bytes_override=None) -> dict:
        return {
            "schema": "wiki-floor-candidate-v1",
            "candidate_kind": kind,
            "expected_old_floor_hash": old_floor_hash,
            "expected_keychain_generation": "1",
            "candidate_floor": bytes_override or candidate_bytes_a,
            "candidate_floor_hash": hash_override or candidate_hash_a,
            "attempt_id": attempt_id,
            "counter": counter,
            "nonce_digest": sha256_hex(b"nonce-1"),
            "disposition": disposition,
            "reason_code": reason,
        }

    # Full four-state validated-advance walk.
    walk = [
        floor_state("FLOOR_STABLE", "0", None, "2026-07-24T00:00:00Z"),
        floor_state("CHALLENGE_RESERVED", "1", candidate("VALIDATED_ADVANCE", "RESERVED", "1"),
                    "2026-07-24T00:00:01Z"),
        floor_state("FLOOR_UPDATE_PREPARED", "1", candidate("VALIDATED_ADVANCE", "ACCEPTED_PREPARED", "1"),
                    "2026-07-24T00:00:02Z"),
        floor_state("KEYCHAIN_COMMITTED", "1", candidate("VALIDATED_ADVANCE", "COMMITTED", "1"),
                    "2026-07-24T00:00:03Z"),
        floor_state("FLOOR_STABLE", "1", None, "2026-07-24T00:00:04Z"),
    ]

    # Counter-only failure candidate path.
    counter_candidate_bytes = floor_candidate_bytes(
        "0", SMT_DEFAULT[SMT_DEPTH].hex(), "0", SMT_DEFAULT[SMT_DEPTH].hex(),
        SMT_DEFAULT[0].hex(), old_floor_hash,
    )
    counter_hash = sha256_hex(canonical_bytes(counter_candidate_bytes))
    counter_walk = [
        floor_state("CHALLENGE_RESERVED", "2",
                    candidate("VALIDATED_ADVANCE", "RESERVED", "2"), "2026-07-24T00:10:00Z"),
        floor_state("COUNTER_UPDATE_PREPARED", "2",
                    candidate("COUNTER_ONLY", "ACCEPTED_PREPARED", "2",
                              hash_override=counter_hash, bytes_override=counter_candidate_bytes),
                    "2026-07-24T00:10:01Z"),
        floor_state("KEYCHAIN_COMMITTED", "2",
                    candidate("COUNTER_ONLY", "COMMITTED", "2",
                              hash_override=counter_hash, bytes_override=counter_candidate_bytes),
                    "2026-07-24T00:10:02Z"),
        floor_state("FLOOR_STABLE", "2", None, "2026-07-24T00:10:03Z"),
    ]

    # R9-1/R10-1 exact-A cases.
    recovered_success = {
        "name": "recovered-success",
        "state": floor_state("KEYCHAIN_COMMITTED", "3",
                              candidate("VALIDATED_ADVANCE", "COMMITTED", "3"), "2026-07-24T00:20:00Z"),
        "assertion": "keychain readback bytes == candidate_floor_hash A exactly",
    }
    old_floor_retry = {
        "name": "old-floor-retry",
        "state": floor_state("FLOOR_UPDATE_PREPARED", "3",
                              candidate("VALIDATED_ADVANCE", "ACCEPTED_PREPARED", "3"), "2026-07-24T00:20:01Z"),
        "retry_state": floor_state("FLOOR_UPDATE_PREPARED", "3",
                                    candidate("VALIDATED_ADVANCE", "ACCEPTED_PREPARED", "3"),
                                    "2026-07-24T00:20:02Z"),
        "assertion": "outage retry re-dispatches identical candidate bytes A (attempt_id/hash unchanged)",
    }
    candidate_b_hash = sha256_hex(b"authenticated-direct-child-B")
    b_ne_a_quarantine = {
        "name": "b-ne-a-quarantine",
        "state": floor_state("QUARANTINED_FLOOR_CONFLICT", "3",
                              candidate("VALIDATED_ADVANCE", "QUARANTINED", "3",
                                        reason="quarantined_floor_conflict"),
                              "2026-07-24T00:20:03Z"),
        "audit_digest_a": candidate_hash_a,
        "audit_digest_b": candidate_b_hash,
        "assertion": "R10-1 AC 11: any B != A (including authenticated direct child) quarantines; no adoption",
    }

    exact_a_cases = [recovered_success, old_floor_retry, b_ne_a_quarantine]

    # FreshnessServeGateV1 valid + invalid-in-enum pairs (R10-3).
    def gate(state: str, reason: str) -> dict:
        return {
            "schema": "wiki-freshness-serve-gate-v1",
            "workspace_id": WORKSPACE_ID,
            "state": state,
            "stable_floor_generation": "1",
            "stable_checkpoint_id": sha256_hex(b"checkpoint-1"),
            "source_candidate_digest": candidate_hash_a,
            "reason": reason,
            "updated_at": "2026-07-24T00:00:04Z",
        }

    valid_gates = [
        gate("CLEAR", "NONE"),
        gate("FRESH_CHALLENGE_REQUIRED", "ATTESTATION_EXPIRED_BEFORE_STABILIZE"),
        gate("FRESH_CHALLENGE_REQUIRED", "CLOCK_WINDOW_EXPIRED"),
    ]
    invalid_gates = [
        {"gate": gate("CLEAR", "ATTESTATION_EXPIRED_BEFORE_STABILIZE"), "reason": "CLEAR with non-NONE reason"},
        {"gate": gate("CLEAR", "CLOCK_WINDOW_EXPIRED"), "reason": "CLEAR with non-NONE reason"},
        {"gate": gate("FRESH_CHALLENGE_REQUIRED", "NONE"), "reason": "FRESH_CHALLENGE_REQUIRED with NONE reason"},
    ]

    return {
        "schema": "wiki-encrypted-lifecycle-floor-state-vectors-v1",
        "validated_advance_walk": walk,
        "counter_only_walk": counter_walk,
        "exact_a_cases": exact_a_cases,
        "freshness_serve_gate": {
            "valid_pairs": valid_gates,
            "invalid_in_enum_pairs": invalid_gates,
        },
    }


# ---------------------------------------------------------------------------
# 6. bundle-one-pass-vectors-v1.json
# ---------------------------------------------------------------------------


def build_bundle_vectors() -> dict:
    payload_files = {
        "payload/gate1-decision.json": b'{"schema":"wiki-gate1-decision-v1"}',
        "payload/macos/sqlcipher-feasibility.json": b'{"schema":"wiki-sqlcipher-feasibility-v1","platform":"macos"}',
        "payload/ubuntu/import-receipt.json": b'{"schema":"wiki-import-receipt-v1","platform":"ubuntu"}',
        "payload/vector-validation.json": b'{"schema":"wiki-vector-validation-v1"}',
    }
    payload_paths = [
        "payload/gate1-decision.json",
        "payload/macos/sqlcipher-feasibility.json",
        "payload/ubuntu/import-receipt.json",
        "payload/vector-validation.json",
    ]
    payload_sha256 = [sha256_hex(payload_files[path]) for path in payload_paths]

    run = "123"
    attempt = "1"
    artifact_kind = "GATE1_DECISION"
    lower_kind = "gate1-decision"

    template = {
        "schema": "wiki-artifact-bundle-envelope-v1",
        "artifact_kind": artifact_kind,
        "repository": "wiki-spike/wiki-spike",
        "producer_commit": "0" * 40,
        "contract_digest": sha256_hex(b"contract-v1"),
        "toolchain_lock_digest": sha256_hex(b"toolchain-lock-v1"),
        "workflow_file_digest": sha256_hex(b"workflow-file-v1"),
        "workflow_run_id": run,
        "workflow_run_attempt": attempt,
        "platform": "github-hosted/ubuntu-24.04/x86_64",
        "artifact_name": "",
        "payload_paths": payload_paths,
        "payload_sha256": payload_sha256,
        "bundle_sha256": "",
        "produced_at": "2026-07-24T00:00:00Z",
    }

    projected_bytes = canonical_bytes(template)
    projected_sha256 = sha256_hex(projected_bytes)
    projected_size = len(projected_bytes)

    manifest_entries = [
        {"path": "artifact-envelope.json", "sha256": projected_sha256, "size": str(projected_size)},
        *[
            {"path": path, "sha256": sha256_hex(payload_files[path]), "size": str(len(payload_files[path]))}
            for path in payload_paths
        ],
    ]
    manifest_entries.sort(key=lambda entry: entry["path"].encode())
    manifest = {"schema": "wiki-artifact-bundle-manifest-v1", "entries": manifest_entries}
    manifest_canonical_bytes = canonical_bytes(manifest)
    bundle_sha256 = sha256_hex(manifest_canonical_bytes)
    artifact_name = f"encrypted-lifecycle-{lower_kind}-{run}-{attempt}-{bundle_sha256[:16]}"

    stored_envelope = dict(template)
    stored_envelope["artifact_name"] = artifact_name
    stored_envelope["bundle_sha256"] = bundle_sha256
    stored_envelope_bytes = canonical_bytes(stored_envelope)

    manifest_text = manifest_canonical_bytes.decode("utf-8")
    # Mutations of the *stored raw manifest text* that must be rejected as
    # noncanonical even though they may parse to equivalent JSON values.
    whitespace_mutation = manifest_text + " "
    key_order_mutation = json.dumps(
        {"entries": manifest_entries, "schema": manifest["schema"]},
        ensure_ascii=False, separators=(",", ":"),
    )
    duplicate_key_mutation = (
        manifest_text[:-1].replace('"schema":"wiki-artifact-bundle-manifest-v1"',
                                    '"schema":"wiki-artifact-bundle-manifest-v1","schema":"wiki-artifact-bundle-manifest-v1"', 1)
        + "}"
    )
    self_field_entries = manifest_entries + [{
        "path": "bundle-manifest.json",
        "sha256": sha256_hex(manifest_canonical_bytes),
        "size": str(len(manifest_canonical_bytes)),
    }]
    self_field_manifest = {"schema": "wiki-artifact-bundle-manifest-v1", "entries": self_field_entries}
    self_field_mutation = canonical_bytes(self_field_manifest).decode("utf-8")

    mutation_cases = [
        {"case": "whitespace", "raw_manifest_text": whitespace_mutation, "expected_error": "noncanonical_bundle_manifest"},
        {"case": "key_order", "raw_manifest_text": key_order_mutation, "expected_error": "noncanonical_bundle_manifest"},
        {"case": "duplicate_key", "raw_manifest_text": duplicate_key_mutation, "expected_error": "noncanonical_bundle_manifest"},
        {"case": "self_field", "raw_manifest_text": self_field_mutation, "expected_error": "self_field_violation"},
    ]

    return {
        "schema": "wiki-encrypted-lifecycle-bundle-one-pass-vectors-v1",
        "template_envelope": template,
        "payload_files": {path: payload_files[path].decode() for path in payload_paths},
        "projected_envelope_bytes_hex": projected_bytes.hex(),
        "projected_envelope_sha256": projected_sha256,
        "projected_envelope_size": str(projected_size),
        "manifest": manifest,
        "manifest_canonical_bytes_hex": manifest_canonical_bytes.hex(),
        "bundle_sha256": bundle_sha256,
        "artifact_name": artifact_name,
        "stored_envelope": stored_envelope,
        "stored_envelope_bytes_hex": stored_envelope_bytes.hex(),
        "mutation_cases": mutation_cases,
    }


# ---------------------------------------------------------------------------
# 7. crash-matrix-vectors-v1.json
# ---------------------------------------------------------------------------


def build_crash_matrix_vectors() -> dict:
    ark_points = [
        {"crash_after": "intent_prepared", "durable_state": "KEY_INTENT_PREPARED", "resume_outcome": "resume_platform_create"},
        {"crash_after": "platform_create_before_readback", "durable_state": "KEY_INTENT_PREPARED", "resume_outcome": "resume_platform_readback"},
        {"crash_after": "platform_readback_verified", "durable_state": "PLATFORM_KEY_VERIFIED", "resume_outcome": "resume_recovery_create"},
        {"crash_after": "recovery_create_before_readback", "durable_state": "PLATFORM_KEY_VERIFIED", "resume_outcome": "resume_recovery_readback"},
        {"crash_after": "recovery_readback_verified", "durable_state": "RECOVERY_KEY_VERIFIED", "resume_outcome": "resume_cas_materialization"},
        {"crash_after": "cas_materialized", "durable_state": "CAS_MATERIALIZED", "resume_outcome": "resume_active_election"},
        {"crash_after": "active_elected", "durable_state": "ACTIVE", "resume_outcome": "none_terminal"},
    ]

    deletion_points = [
        {"crash_after": "requested", "durable_state": "REQUESTED", "resume_outcome": "resume_api_veto"},
        {"crash_after": "api_veto_active", "durable_state": "API_VETO_ACTIVE", "resume_outcome": "resume_tombstone"},
        {"crash_after": "tombstone_active", "durable_state": "TOMBSTONE_ACTIVE", "resume_outcome": "resume_checkpoint_commit"},
        {"crash_after": "checkpoint_committed", "durable_state": "CHECKPOINT_COMMITTED", "resume_outcome": "resume_revocation_keys_destroy"},
        {"crash_after": "revocation_keys_destroyed", "durable_state": "REVOCATION_KEYS_DESTROYED", "resume_outcome": "resume_crypto_shred_complete"},
        {"crash_after": "crypto_shred_complete", "durable_state": "CRYPTO_SHRED_COMPLETE", "resume_outcome": "resume_purge"},
        {"crash_after": "purge_pending", "durable_state": "PURGE_PENDING", "resume_outcome": "resume_complete"},
        {"crash_after": "complete", "durable_state": "COMPLETE", "resume_outcome": "none_terminal"},
    ]

    return {
        "schema": "wiki-encrypted-lifecycle-crash-matrix-vectors-v1",
        "ark_creation_crash_points": ark_points,
        "deletion_crash_points": deletion_points,
    }


# ---------------------------------------------------------------------------
# 8. new-consent-vectors-v1.json
# ---------------------------------------------------------------------------


def build_new_consent_vectors() -> dict:
    cases = [
        {
            "name": "zero-body-rejected",
            "prior_deletion_phase": "COMPLETE",
            "command_kind": "REMEMBER",
            "new_consent_flag": True,
            "body_present": False,
            "body_content_digest": None,
            "prior_consent_epoch": "1",
            "expected_result": "rejected",
            "expected_error": "new_consent_zero_body_rejected",
        },
        {
            "name": "body-bearing-accepted",
            "prior_deletion_phase": "COMPLETE",
            "command_kind": "REMEMBER",
            "new_consent_flag": True,
            "body_present": True,
            "body_content_digest": sha256_hex(b"post-deletion remember body"),
            "prior_consent_epoch": "1",
            "new_consent_epoch": "2",
            "expected_result": "accepted",
        },
    ]
    return {"schema": "wiki-encrypted-lifecycle-new-consent-vectors-v1", "cases": cases}


# ---------------------------------------------------------------------------
# 9. wal-linearization-vectors-v1.json
# ---------------------------------------------------------------------------


def build_wal_linearization_vectors() -> dict:
    schedule_a = {
        "name": "schedule-a-delete-before-read",
        "ordering": ["checked_snapshot_read_begin", "forget_accepted_and_committed", "checked_snapshot_read_acquire"],
        "expected_token": "suppressed",
        "assertion": "FORGET commits strictly before the checked-snapshot acquisition point, selector must not be visible",
    }
    schedule_b = {
        "name": "schedule-b-delete-after-read",
        "ordering": ["checked_snapshot_read_acquire", "checked_snapshot_read_returns", "forget_accepted_and_committed"],
        "expected_token": "one_pre_linearized_response_allowed",
        "assertion": "checked-snapshot read acquired strictly before FORGET commit reflects its own atomic as-of point and is never retroactively invalidated",
    }
    return {
        "schema": "wiki-encrypted-lifecycle-wal-linearization-vectors-v1",
        "linearization_point": "atomic_checked_snapshot_read_acquisition",
        "schedules": [schedule_a, schedule_b],
    }


def main() -> None:
    families = {
        "identity-vectors-v1.json": build_identity_vectors,
        "kdf-vectors-v1.json": build_kdf_vectors,
        "nonce-vectors-v1.json": build_nonce_vectors,
        "binding-wire-vectors-v1.json": build_binding_wire_vectors,
        "floor-state-vectors-v1.json": build_floor_state_vectors,
        "bundle-one-pass-vectors-v1.json": build_bundle_vectors,
        "crash-matrix-vectors-v1.json": build_crash_matrix_vectors,
        "new-consent-vectors-v1.json": build_new_consent_vectors,
        "wal-linearization-vectors-v1.json": build_wal_linearization_vectors,
    }
    for filename, builder in families.items():
        write_json(filename, builder())
        print(f"wrote {filename}")


if __name__ == "__main__":
    main()
