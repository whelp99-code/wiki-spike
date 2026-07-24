"""Gate 2 binding registry tests.

Reproduces `tests/fixtures/encrypted_lifecycle/binding-wire-vectors-v1.json`
byte-for-byte via `wiki_spike.infrastructure.binding_registry.BindingRegistry`
using the exact same TEST-ONLY deterministic seeds as
`scripts/generate_encrypted_lifecycle_vectors.py::build_binding_wire_vectors`,
and exercises proof-set verification (positive + every tamper case fails
closed) plus append-only fork/gap/regression rejection.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.binding_registry import (
    DOMAIN_ATTESTATION,
    DOMAIN_CHECKPOINT,
    DOMAIN_HISTORY_LEAF,
    BindingRegistry,
    BindingRegistryError,
)
from wiki_spike.memory_core.contracts import canonical_bytes

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_PATH = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle" / "binding-wire-vectors-v1.json"

WORKSPACE_ID = "ws-test-1"

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


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(scope="module")
def fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _leaf_fields(handle: str, status: str) -> dict:
    return {
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
    }


def _build_registry() -> BindingRegistry:
    """Reproduces the frozen fixture's 3-leaf history + sparse map."""
    registry = BindingRegistry(WORKSPACE_ID)
    for handle, status in [
        ("provider-a", "PREPARED"),
        ("provider-b", "ACTIVE"),
        ("provider-c", "LOSER"),
    ]:
        registry.append_leaf(
            **_leaf_fields(handle, status),
            signing_key=SIGNING_KEY_1,
            key_id=SIGNER_KEY_ID_1,
        )
    return registry


def _build_checkpoint(registry: BindingRegistry) -> tuple[dict, dict]:
    return registry.checkpoint(
        generation_id=sha256_hex(b"generation-1"),
        created_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        key_id=SIGNER_KEY_ID_1,
        registry_sequence="3",
    )


def _build_attestation(registry: BindingRegistry) -> dict:
    return registry.attest(
        request_nonce=sha256_hex(b"test-challenge-nonce-1"),
        challenge_counter="1",
        request_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        signer_key_id=SIGNER_KEY_ID_1,
        issued_at="2026-07-24T00:00:00Z",
        expires_at="2026-07-24T00:05:00Z",
        signing_key=SIGNING_KEY_1,
        checkpoint_id=sha256_hex(b"checkpoint-1"),
        checkpoint_sha256=sha256_hex(b"checkpoint-1"),
        checkpoint_sequence="1",
    )


# ---------------------------------------------------------------------------
# 1. Signer public keys / domains reproduce the fixture exactly.
# ---------------------------------------------------------------------------


def test_signer_public_keys_match_fixture(fixture):
    assert SIGNING_KEY_1.public_key().public_bytes_raw().hex() == fixture["signer_public_keys"][SIGNER_KEY_ID_1]
    assert SIGNING_KEY_2.public_key().public_bytes_raw().hex() == fixture["signer_public_keys"][SIGNER_KEY_ID_2]


def test_domains_match_fixture(fixture):
    assert DOMAIN_ATTESTATION + "\u0000" == fixture["domains"]["attestation"]
    assert DOMAIN_HISTORY_LEAF + "\u0000" == fixture["domains"]["history_leaf"]
    assert DOMAIN_CHECKPOINT + "\u0000" == fixture["domains"]["checkpoint"]


# ---------------------------------------------------------------------------
# 2. Append-only signed history reproduces leaves / leaf hashes / history root.
# ---------------------------------------------------------------------------


def test_leaves_and_leaf_hashes_match_fixture(fixture):
    registry = _build_registry()
    assert registry.leaves == fixture["leaves"]
    assert registry.leaf_hashes_hex == fixture["leaf_hashes_hex"]
    assert registry.signed_leaves == fixture["signed_leaves"]
    assert registry.history_size == 3
    assert registry.history_root_hex == fixture["history_root"]


def test_current_map_root_matches_fixture(fixture):
    registry = _build_registry()
    assert registry.current_map_size == 3
    assert registry.current_map_root_hex == fixture["current_map_root"]


def test_history_inclusion_proof_matches_fixture(fixture):
    registry = _build_registry()
    expected = fixture["history_inclusion_proof"]
    audit_path = [h.hex() for h in crypto.merkle_inclusion_proof(registry._history_entry_hashes, 1)]
    assert audit_path == expected["audit_path"]
    assert str(registry.history_size) == expected["history_size"]


def test_history_consistency_proof_matches_fixture(fixture):
    registry = _build_registry()
    expected = fixture["history_consistency_proof"]
    audit_path = [h.hex() for h in crypto.merkle_consistency_proof(registry._history_entry_hashes, 2, 3)]
    assert audit_path == expected["audit_path"]


def test_membership_and_nonmembership_proofs_match_fixture(fixture):
    registry = _build_registry()
    member_key = fixture["membership_proof"]["map_key"]
    nonmember_key = fixture["nonmembership_proof"]["map_key"]
    assert registry.sparse_proof_for_map_key(member_key) == fixture["membership_proof"]
    assert registry.sparse_proof_for_map_key(nonmember_key) == fixture["nonmembership_proof"]


# ---------------------------------------------------------------------------
# 3. Signed checkpoint reproduces byte-for-byte (deterministic Ed25519).
# ---------------------------------------------------------------------------


def test_checkpoint_and_signature_match_fixture(fixture):
    registry = _build_registry()
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    assert checkpoint == fixture["checkpoint"]
    assert checkpoint_signature == fixture["checkpoint_signature"]


# ---------------------------------------------------------------------------
# 4. Latest-read attestation reproduces payload / canonical bytes / signature.
# ---------------------------------------------------------------------------


def test_attestation_matches_fixture(fixture):
    registry = _build_registry()
    attestation = _build_attestation(registry)
    assert attestation["payload"] == fixture["attestation"]["payload"]
    assert attestation["signature"] == fixture["attestation"]["signature"]
    assert attestation == fixture["attestation"]
    assert canonical_bytes(attestation["payload"]).hex() == fixture["attestation_canonical_bytes_hex"]


# ---------------------------------------------------------------------------
# 5. Proof set reproduces byte-for-byte and verifies clean.
# ---------------------------------------------------------------------------


def test_proof_set_matches_fixture(fixture):
    registry = _build_registry()
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = _build_attestation(registry)
    proof_set = registry.build_proof_set(
        attestation=attestation,
        checkpoint=checkpoint,
        checkpoint_signature=checkpoint_signature,
        namespace="encrypted-lifecycle",
        provider_handle="provider-a",  # fixture proves membership of map_keys[0] (provider-a)
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
        current_leaf_override=registry.signed_leaves[1],  # while current_leaf is the ACTIVE provider-b leaf
    )
    assert proof_set == fixture["proof_set"]


def test_verify_proof_set_accepts_the_valid_fixture_proof_set(fixture):
    registry = _build_registry()
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = _build_attestation(registry)
    proof_set = registry.build_proof_set(
        attestation=attestation,
        checkpoint=checkpoint,
        checkpoint_signature=checkpoint_signature,
        namespace="encrypted-lifecycle",
        provider_handle="provider-b",
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
    )
    registry.verify_proof_set(
        proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
    )


def _fresh_proof_set() -> tuple[BindingRegistry, dict]:
    registry = _build_registry()
    checkpoint, checkpoint_signature = _build_checkpoint(registry)
    attestation = _build_attestation(registry)
    proof_set = registry.build_proof_set(
        attestation=attestation,
        checkpoint=checkpoint,
        checkpoint_signature=checkpoint_signature,
        namespace="encrypted-lifecycle",
        provider_handle="provider-b",
        old_size=2,
        inclusion_indices=[1],
        predecessor_leaf_indices=[],
    )
    return registry, proof_set


def test_verify_proof_set_rejects_replayed_nonce():
    registry, proof_set = _fresh_proof_set()
    floor = sha256_hex(b"floor-checkpoint-genesis")
    registry.verify_proof_set(proof_set, trusted_signer_pub=SIGNING_KEY_1.public_key(), local_floor_checkpoint_id=floor)
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(proof_set, trusted_signer_pub=SIGNING_KEY_1.public_key(), local_floor_checkpoint_id=floor)
    assert excinfo.value.code == "nonce_replay"


def test_verify_proof_set_accepts_expected_identity():
    registry, proof_set = _fresh_proof_set()
    registry.verify_proof_set(
        proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        expected_namespace="encrypted-lifecycle",
        expected_provider_handle="provider-b",
    )


def test_verify_proof_set_rejects_substituted_identity():
    registry, proof_set = _fresh_proof_set()
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            proof_set,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
            expected_namespace="encrypted-lifecycle",
            expected_provider_handle="provider-a",
        )
    assert excinfo.value.code == "membership_proof_identity_mismatch"


def test_verify_proof_set_rejects_floor_mismatch():
    registry, proof_set = _fresh_proof_set()
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            proof_set, trusted_signer_pub=SIGNING_KEY_1.public_key(), local_floor_checkpoint_id=sha256_hex(b"wrong-floor")
        )
    assert excinfo.value.code == "attestation_floor_mismatch"


def test_verify_proof_set_rejects_wrong_signer_key():
    registry, proof_set = _fresh_proof_set()
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            proof_set,
            trusted_signer_pub=SIGNING_KEY_2.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "signature_invalid"


def test_verify_proof_set_rejects_tampered_attestation_signature():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    sig = tampered["attestation"]["signature"]
    tampered["attestation"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "signature_invalid"


def test_verify_proof_set_rejects_tampered_checkpoint_history_root():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    root = tampered["checkpoint"]["history_root"]
    tampered["checkpoint"]["history_root"] = ("0" if root[0] != "0" else "1") + root[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    # canonical bytes changed -> checkpoint_sha256 no longer matches the signature block.
    assert excinfo.value.code == "checkpoint_sha256_mismatch"


def test_verify_proof_set_rejects_tampered_checkpoint_signature():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    sig = tampered["checkpoint_signature"]["signature"]
    tampered["checkpoint_signature"]["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "signature_invalid"


def test_verify_proof_set_rejects_tampered_current_leaf_revision_id():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    rid = tampered["current_leaf"]["leaf"]["revision_id"]
    tampered["current_leaf"]["leaf"]["revision_id"] = ("0" if rid[0] != "0" else "1") + rid[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "leaf_hash_mismatch"


def test_verify_proof_set_rejects_tampered_sparse_sibling():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    sib = tampered["current_sparse_proof"]["siblings"][0]
    tampered["current_sparse_proof"]["siblings"][0] = ("0" if sib[0] != "0" else "1") + sib[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "membership_proof_invalid"


def test_verify_proof_set_rejects_tampered_inclusion_audit_path():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    entry = tampered["history_inclusion_proofs"][0]["audit_path"][0]
    tampered["history_inclusion_proofs"][0]["audit_path"][0] = ("0" if entry[0] != "0" else "1") + entry[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "inclusion_proof_invalid"


def test_verify_proof_set_rejects_tampered_consistency_audit_path():
    registry, proof_set = _fresh_proof_set()
    tampered = json.loads(json.dumps(proof_set))
    entry = tampered["history_consistency_proof"]["audit_path"][0]
    tampered["history_consistency_proof"]["audit_path"][0] = ("0" if entry[0] != "0" else "1") + entry[1:]
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            tampered,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        )
    assert excinfo.value.code == "consistency_proof_invalid"


def test_verify_proof_set_accepts_floor_anchored_consistency():
    registry, proof_set = _fresh_proof_set()
    old_root = crypto.merkle_root(registry._history_entry_hashes[:2])
    registry.verify_proof_set(
        proof_set,
        trusted_signer_pub=SIGNING_KEY_1.public_key(),
        local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
        trusted_old_size=2,
        trusted_old_root_hex=old_root.hex(),
    )


def test_verify_proof_set_rejects_wrong_floor_old_root():
    registry, proof_set = _fresh_proof_set()
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            proof_set,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
            trusted_old_size=2,
            trusted_old_root_hex="00" * 32,
        )
    assert excinfo.value.code == "consistency_proof_invalid"


def test_verify_proof_set_rejects_wrong_floor_old_size():
    registry, proof_set = _fresh_proof_set()
    old_root = crypto.merkle_root(registry._history_entry_hashes[:2])
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.verify_proof_set(
            proof_set,
            trusted_signer_pub=SIGNING_KEY_1.public_key(),
            local_floor_checkpoint_id=sha256_hex(b"floor-checkpoint-genesis"),
            trusted_old_size=1,
            trusted_old_root_hex=old_root.hex(),
        )
    assert excinfo.value.code == "consistency_proof_invalid"


# ---------------------------------------------------------------------------
# 6. Fixture's own frozen tamper_cases / cross_domain_vector / cross_key_vector
#    reject under this module's own signature verification helpers.
# ---------------------------------------------------------------------------


def test_fixture_checkpoint_tamper_cases_are_caught(fixture):
    root_case = next(c for c in fixture["tamper_cases"] if c["case"] == "root_flip")
    assert root_case["mutated"]["history_root"] != root_case["original"]["history_root"]

    size_case = next(c for c in fixture["tamper_cases"] if c["case"] == "size_flip")
    assert size_case["mutated"]["history_size"] != size_case["original"]["history_size"]

    leaf_case = next(c for c in fixture["tamper_cases"] if c["case"] == "leaf_flip")
    original_hash = hashlib.sha256(canonical_bytes(leaf_case["original"])).hexdigest()
    mutated_hash = hashlib.sha256(canonical_bytes(leaf_case["mutated"])).hexdigest()
    assert original_hash != mutated_hash

    signature_case = next(c for c in fixture["tamper_cases"] if c["case"] == "signature_flip")
    pub_key = SIGNING_KEY_1.public_key()
    signing_input = DOMAIN_CHECKPOINT.encode("ascii") + b"\x00" + canonical_bytes(fixture["checkpoint"])
    pub_key.verify(bytes.fromhex(signature_case["original_signature"]), signing_input)
    with pytest.raises(Exception):
        pub_key.verify(bytes.fromhex(signature_case["mutated_signature"]), signing_input)

    domain_case = next(c for c in fixture["tamper_cases"] if c["case"] == "domain_flip")
    wrong_signing_input = domain_case["wrong_domain"].encode("ascii") + b"\x00" + canonical_bytes(fixture["checkpoint"])
    with pytest.raises(Exception):
        pub_key.verify(bytes.fromhex(domain_case["signature"]), wrong_signing_input)


def test_cross_domain_vector_fails_under_wrong_domain(fixture):
    cross = fixture["cross_domain_vector"]
    pub_key = SIGNING_KEY_1.public_key()
    wrong_input = cross["invalid_domain"].encode("ascii") + b"\x00" + canonical_bytes(cross["payload"])
    with pytest.raises(Exception):
        pub_key.verify(bytes.fromhex(cross["signature"]), wrong_input)
    right_input = cross["valid_domain"].encode("ascii") + b"\x00" + canonical_bytes(cross["payload"])
    pub_key.verify(bytes.fromhex(cross["signature"]), right_input)  # sanity: valid under its own domain


def test_cross_key_vector_fails_under_wrong_signer(fixture):
    cross = fixture["cross_key_vector"]
    wrong_pub_key = SIGNING_KEY_1.public_key()
    signing_input = cross["domain"].encode("ascii") + b"\x00" + canonical_bytes(cross["payload"])
    with pytest.raises(Exception):
        wrong_pub_key.verify(bytes.fromhex(cross["signature"]), signing_input)
    right_pub_key = SIGNING_KEY_2.public_key()
    right_pub_key.verify(bytes.fromhex(cross["signature"]), signing_input)  # sanity


# ---------------------------------------------------------------------------
# 7. Append-only chain rejects fork / gap / regression.
# ---------------------------------------------------------------------------


def test_append_leaf_rejects_gap_in_registry_sequence():
    registry = BindingRegistry(WORKSPACE_ID)
    leaf = {
        "schema": "wiki-binding-registry-leaf-v1",
        "workspace_id": WORKSPACE_ID,
        "registry_sequence": "2",  # should be "1"
        "prior_leaf_hash": None,
        **_leaf_fields("provider-a", "PREPARED"),
    }
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.append_signed_leaf(leaf, signing_key=SIGNING_KEY_1, key_id=SIGNER_KEY_ID_1)
    assert excinfo.value.code == "gap_detected"
    assert registry.history_size == 0  # abort before effect


def test_append_leaf_rejects_regression_in_registry_sequence():
    registry = _build_registry()  # history_size == 3
    leaf = {
        "schema": "wiki-binding-registry-leaf-v1",
        "workspace_id": WORKSPACE_ID,
        "registry_sequence": "2",  # already appended
        "prior_leaf_hash": registry.leaf_hashes_hex[-1],
        **_leaf_fields("provider-d", "PREPARED"),
    }
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.append_signed_leaf(leaf, signing_key=SIGNING_KEY_1, key_id=SIGNER_KEY_ID_1)
    assert excinfo.value.code == "regression_detected"
    assert registry.history_size == 3  # unchanged


def test_append_leaf_rejects_fork_wrong_prior_hash():
    registry = _build_registry()  # history_size == 3
    leaf = {
        "schema": "wiki-binding-registry-leaf-v1",
        "workspace_id": WORKSPACE_ID,
        "registry_sequence": "4",
        "prior_leaf_hash": "a" * 64,  # not the real head
        **_leaf_fields("provider-d", "PREPARED"),
    }
    with pytest.raises(BindingRegistryError) as excinfo:
        registry.append_signed_leaf(leaf, signing_key=SIGNING_KEY_1, key_id=SIGNER_KEY_ID_1)
    assert excinfo.value.code == "fork_detected"
    assert registry.history_size == 3  # unchanged


def test_append_leaf_accepts_correct_next_leaf_after_rejections():
    registry = _build_registry()
    signed = registry.append_leaf(
        **_leaf_fields("provider-d", "PREPARED"),
        signing_key=SIGNING_KEY_1,
        key_id=SIGNER_KEY_ID_1,
    )
    assert signed["leaf"]["registry_sequence"] == "4"
    assert signed["leaf"]["prior_leaf_hash"] == registry._leaf_hashes[2].hex()
    assert registry.history_size == 4
