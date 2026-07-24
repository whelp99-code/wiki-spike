"""Conformance suite: the PRODUCT crypto module
(``wiki_spike.infrastructure.crypto``) must reproduce every frozen Gate 1
vector byte-for-byte. This turns the two-oracle Gate 1 vector set
(tests/fixtures/encrypted_lifecycle/*) into an executable conformance oracle
for the real implementation, per ADR-0026.

The TEST-ONLY seed constants below are redefined identically to
``scripts/generate_encrypted_lifecycle_vectors.py`` (the frozen vector
generator) so this suite can recompute the exact same derived keys and
signatures the fixtures were built with. They MUST NEVER be used for
anything but this conformance check.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from wiki_spike.infrastructure import crypto

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "encrypted_lifecycle"

# ---------------------------------------------------------------------------
# TEST-ONLY deterministic key material, identical to
# scripts/generate_encrypted_lifecycle_vectors.py. Never use outside this
# conformance suite.
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

DOMAIN_ATTESTATION = "wiki.binding.latest-read-attestation.v1"
DOMAIN_HISTORY_LEAF = "wiki.binding.history-leaf.v1"
DOMAIN_CHECKPOINT = "wiki.binding.checkpoint.v1"


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURES_DIR / name).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# 1. identity-vectors-v1.json: recompute all five HMAC identity families.
# ---------------------------------------------------------------------------


def test_identity_vectors_reproduce_byte_for_byte():
    data = load_fixture("identity-vectors-v1.json")
    derived_keys = crypto.derive_identity_keys(TEST_ONLY_ROOT_IKM)

    checked = 0
    for case in data["cases"]:
        if "object_id_message" in case:
            assert (
                crypto.identity_hmac_hex(derived_keys, "object_identity_key_v1", case["object_id_message"])
                == case["logical_object_id"]
            )
            checked += 1
        if "command_message" in case:
            assert (
                crypto.identity_hmac_hex(derived_keys, "command_digest_key_v1", case["command_message"])
                == case["command_id"]
            )
            checked += 1
        if "artifact_semantic_message" in case:
            assert (
                crypto.identity_hmac_hex(derived_keys, "artifact_identity_key_v1", case["artifact_semantic_message"])
                == case["artifact_semantic_digest"]
            )
            checked += 1
        if "revision_id_message" in case:
            assert (
                crypto.identity_hmac_hex(derived_keys, "revision_identity_key_v1", case["revision_id_message"])
                == case["revision_id"]
            )
            checked += 1
        if "manifest_message" in case:
            assert (
                crypto.identity_hmac_hex(derived_keys, "manifest_digest_key_v1", case["manifest_message"])
                == case["manifest_digest"]
            )
            checked += 1
        for side in ("command_a", "command_b"):
            if side in case:
                assert (
                    crypto.identity_hmac_hex(derived_keys, "command_digest_key_v1", case[side]["message"])
                    == case[side]["command_id"]
                )
                checked += 1
    assert checked >= 15, "expected to recompute at least 15 identity digests across all five families"


def test_identity_vectors_semantic_convergence_and_idempotency_invariants():
    data = load_fixture("identity-vectors-v1.json")
    cases = {c["name"]: c for c in data["cases"]}

    convergence = cases["semantic-convergence"]
    assert convergence["command_a"]["command_id"] != convergence["command_b"]["command_id"]

    mismatch = cases["idempotency-mismatch"]
    assert mismatch["command_a"]["command_id"] != mismatch["command_b"]["command_id"]

    conflict = cases["expected-active-conflict"]
    assert conflict["expected_active_revision_id"] != conflict["actual_parent_used"]
    assert conflict["expected_conflict"] is True


# ---------------------------------------------------------------------------
# 2. kdf-vectors-v1.json: assert HKDF-SHA-256 outputs for all eight labels.
# ---------------------------------------------------------------------------


def test_kdf_vectors_reproduce_byte_for_byte():
    data = load_fixture("kdf-vectors-v1.json")
    assert data["algorithm"] == "HKDF-SHA-256"
    assert data["ikm_hex_test_only"] == TEST_ONLY_ROOT_IKM.hex()

    labels_seen = set()
    for entry in data["labels"]:
        label = entry["label"]
        labels_seen.add(label)
        assert crypto.hkdf_salt(label).hex() == entry["salt_hex"]
        assert crypto.hkdf_info(label).hex() == entry["info_hex"]
        output = crypto.hkdf_sha256(TEST_ONLY_ROOT_IKM, crypto.hkdf_salt(label), crypto.hkdf_info(label))
        assert output.hex() == entry["output_hex"]

    assert labels_seen == set(crypto.HKDF_LABELS)

    derived = crypto.derive_identity_keys(TEST_ONLY_ROOT_IKM)
    for entry in data["labels"]:
        assert derived[entry["label"]].hex() == entry["output_hex"]


# ---------------------------------------------------------------------------
# 3. nonce-vectors-v1.json: assert width/pattern validators.
# ---------------------------------------------------------------------------


def test_nonce_vectors_validators_match_fixture():
    data = load_fixture("nonce-vectors-v1.json")

    aes = data["aes_gcm_nonce_hex24"]
    for value in aes["valid"]:
        assert crypto.is_aes_gcm_nonce_hex24(value) is True
    for invalid in aes["invalid"]:
        assert crypto.is_aes_gcm_nonce_hex24(invalid["value"]) is False

    challenge = data["challenge_nonce_hex64"]
    for value in challenge["valid"]:
        assert crypto.is_challenge_nonce_hex64(value) is True
    for invalid in challenge["invalid"]:
        assert crypto.is_challenge_nonce_hex64(invalid["value"]) is False

    for cross in data["cross_use_rejection"]:
        if cross["tested_as"] == "challenge_nonce_hex64":
            assert crypto.is_challenge_nonce_hex64(cross["value"]) is False
        elif cross["tested_as"] == "aes_gcm_nonce_hex24":
            assert crypto.is_aes_gcm_nonce_hex24(cross["value"]) is False
        else:  # pragma: no cover - fixture drift guard
            raise AssertionError(f"unexpected tested_as: {cross['tested_as']!r}")


# ---------------------------------------------------------------------------
# 4. binding-wire-vectors-v1.json: leaf hashes, history root, inclusion,
#    consistency, SMT membership/non-membership, attestation/checkpoint
#    Ed25519 verify, cross-domain/cross-key rejection.
# ---------------------------------------------------------------------------


def test_binding_wire_leaf_hashes_and_history_root_reproduce():
    data = load_fixture("binding-wire-vectors-v1.json")
    leaves = data["leaves"]
    signed_leaves = data["signed_leaves"]
    from wiki_spike.memory_core.contracts import canonical_bytes

    recomputed_leaf_hashes = [crypto.leaf_hash(canonical_bytes(sl)).hex() for sl in signed_leaves]
    assert recomputed_leaf_hashes == data["leaf_hashes_hex"]

    leaf_hash_bytes = [bytes.fromhex(h) for h in data["leaf_hashes_hex"]]
    assert crypto.merkle_root(leaf_hash_bytes).hex() == data["history_root"]


def test_binding_wire_history_inclusion_and_consistency_proofs_reproduce():
    data = load_fixture("binding-wire-vectors-v1.json")
    leaf_hash_bytes = [bytes.fromhex(h) for h in data["leaf_hashes_hex"]]

    inclusion = data["history_inclusion_proof"]
    recomputed = crypto.merkle_inclusion_proof(leaf_hash_bytes, int(inclusion["leaf_index"]))
    assert [h.hex() for h in recomputed] == inclusion["audit_path"]

    consistency = data["history_consistency_proof"]
    recomputed_consistency = crypto.merkle_consistency_proof(
        leaf_hash_bytes, int(consistency["old_size"]), int(consistency["new_size"])
    )
    assert [h.hex() for h in recomputed_consistency] == consistency["audit_path"]


def test_binding_wire_smt_membership_and_nonmembership_proofs_reproduce():
    data = load_fixture("binding-wire-vectors-v1.json")
    leaves = data["leaves"]
    signed_leaves = data["signed_leaves"]
    from wiki_spike.memory_core.contracts import canonical_bytes

    def map_key_for(leaf: dict) -> str:
        return hashlib.sha256(canonical_bytes({
            "domain": "wiki.binding-registry.current-key",
            "version": "1",
            "workspace_id": leaf["workspace_id"],
            "namespace": leaf["namespace"],
            "provider_handle": leaf["provider_handle"],
        })).hexdigest()

    smt_items: dict[int, bytes] = {}
    for leaf, signed in zip(leaves, signed_leaves):
        mk_hex = map_key_for(leaf)
        smt_items[crypto.hexkey_to_int(mk_hex)] = hashlib.sha256(canonical_bytes(signed)).digest()

    assert crypto.smt_root(smt_items).hex() == data["current_map_root"]

    membership = data["membership_proof"]
    member_key_int = crypto.hexkey_to_int(membership["map_key"])
    recomputed_member_siblings = crypto.smt_proof(smt_items, member_key_int)
    assert [s.hex() for s in recomputed_member_siblings] == membership["siblings"]

    nonmembership = data["nonmembership_proof"]
    nonmember_key_int = crypto.hexkey_to_int(nonmembership["map_key"])
    recomputed_nonmember_siblings = crypto.smt_proof(smt_items, nonmember_key_int)
    assert [s.hex() for s in recomputed_nonmember_siblings] == nonmembership["siblings"]


def test_binding_wire_attestation_and_checkpoint_signatures_verify():
    data = load_fixture("binding-wire-vectors-v1.json")
    public_key_1 = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(data["signer_public_keys"][SIGNER_KEY_ID_1])
    )

    attestation = data["attestation"]
    crypto.verify(public_key_1, DOMAIN_ATTESTATION, attestation["payload"], attestation["signature"])

    checkpoint = data["checkpoint"]
    checkpoint_signature = data["checkpoint_signature"]
    crypto.verify(public_key_1, DOMAIN_CHECKPOINT, checkpoint, checkpoint_signature["signature"])

    for signed in data["signed_leaves"]:
        crypto.verify(
            public_key_1,
            DOMAIN_HISTORY_LEAF,
            signed["leaf"],
            signed["leaf_signature"]["signature"],
        )


def test_binding_wire_cross_domain_rejection():
    data = load_fixture("binding-wire-vectors-v1.json")
    cross = data["cross_domain_vector"]
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(data["signer_public_keys"][cross["signer_key_id"]])
    )
    # sanity: valid under its own domain
    crypto.verify(public_key, cross["valid_domain"], cross["payload"], cross["signature"])
    with pytest.raises(InvalidSignature):
        crypto.verify(public_key, cross["invalid_domain"], cross["payload"], cross["signature"])


def test_binding_wire_cross_key_rejection():
    data = load_fixture("binding-wire-vectors-v1.json")
    cross = data["cross_key_vector"]
    wrong_public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(data["signer_public_keys"][cross["verify_against_key_id"]])
    )
    with pytest.raises(InvalidSignature):
        crypto.verify(wrong_public_key, cross["domain"], cross["payload"], cross["signature"])

    right_public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(data["signer_public_keys"][cross["signer_key_id_used"]])
    )
    crypto.verify(right_public_key, cross["domain"], cross["payload"], cross["signature"])


def test_binding_wire_tamper_cases_are_rejected():
    data = load_fixture("binding-wire-vectors-v1.json")
    from wiki_spike.memory_core.contracts import canonical_bytes

    tamper_cases = {c["case"]: c for c in data["tamper_cases"]}

    root_flip = tamper_cases["root_flip"]
    assert root_flip["mutated"]["history_root"] != root_flip["original"]["history_root"]

    size_flip = tamper_cases["size_flip"]
    assert size_flip["mutated"]["history_size"] != size_flip["original"]["history_size"]

    leaf_flip = tamper_cases["leaf_flip"]
    original_hash = crypto.leaf_hash(canonical_bytes(leaf_flip["original"])).hex()
    mutated_hash = crypto.leaf_hash(canonical_bytes(leaf_flip["mutated"])).hex()
    assert original_hash != mutated_hash

    signature_flip = tamper_cases["signature_flip"]
    public_key = Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(data["signer_public_keys"][SIGNER_KEY_ID_1])
    )
    crypto.verify(public_key, DOMAIN_CHECKPOINT, data["checkpoint"], signature_flip["original_signature"])
    with pytest.raises(InvalidSignature):
        crypto.verify(public_key, DOMAIN_CHECKPOINT, data["checkpoint"], signature_flip["mutated_signature"])

    domain_flip = tamper_cases["domain_flip"]
    with pytest.raises(InvalidSignature):
        crypto.verify(public_key, domain_flip["wrong_domain"], data["checkpoint"], domain_flip["signature"])


# ---------------------------------------------------------------------------
# 5. bundle-one-pass-vectors-v1.json: recompute canonical manifest bytes,
#    projected/stored envelope bytes, bundle_sha256, artifact_name suffix.
# ---------------------------------------------------------------------------


def test_bundle_one_pass_projection_and_digest_reproduce_byte_for_byte():
    data = load_fixture("bundle-one-pass-vectors-v1.json")
    template = data["template_envelope"]

    projected_bytes, projected_sha256, projected_size = crypto.project_bundle_envelope(template)
    assert projected_bytes.hex() == data["projected_envelope_bytes_hex"]
    assert projected_sha256 == data["projected_envelope_sha256"]
    assert str(projected_size) == data["projected_envelope_size"]

    manifest_bytes, bundle_sha256 = crypto.compute_bundle_digest(data["manifest"])
    assert manifest_bytes.hex() == data["manifest_canonical_bytes_hex"]
    assert bundle_sha256 == data["bundle_sha256"]

    artifact_kind = template["artifact_kind"]
    lower_kind = artifact_kind.lower().replace("_", "-")
    artifact_name = crypto.bundle_artifact_name(
        lower_kind,
        template["workflow_run_id"],
        template["workflow_run_attempt"],
        bundle_sha256,
    )
    assert artifact_name == data["artifact_name"]

    stored_envelope = dict(template)
    stored_envelope["artifact_name"] = artifact_name
    stored_envelope["bundle_sha256"] = bundle_sha256
    from wiki_spike.memory_core.contracts import canonical_bytes

    precount_bytes = canonical_bytes(stored_envelope)
    stored_envelope["stored_size_bytes"] = str(len(precount_bytes))
    stored_envelope_bytes = canonical_bytes(stored_envelope)
    assert stored_envelope_bytes.hex() == data["stored_envelope_bytes_hex"]
    assert stored_envelope == data["stored_envelope"]
    assert stored_envelope["stored_size_bytes"] == data["stored_size_bytes"]


def test_bundle_one_pass_manifest_mutation_cases_are_noncanonical():
    data = load_fixture("bundle-one-pass-vectors-v1.json")
    canonical_bytes_value = bytes.fromhex(data["manifest_canonical_bytes_hex"])

    mutation_cases = {m["case"]: m for m in data["mutation_cases"]}
    assert set(mutation_cases) == {"whitespace", "key_order", "duplicate_key", "self_field"}

    # whitespace, duplicate_key, and self_field are byte-distinguishable
    # from the exact canonical manifest bytes even though whitespace and
    # duplicate_key parse to an equivalent (or, for duplicate_key,
    # ambiguous) JSON value -- this is what a strict byte-for-byte
    # canonical comparison is required to catch.
    for case in ("whitespace", "duplicate_key", "self_field"):
        mutated_bytes = mutation_cases[case]["raw_manifest_text"].encode("utf-8")
        assert mutated_bytes != canonical_bytes_value, f"{case} mutation must differ from canonical bytes"
        assert mutation_cases[case]["expected_error"] in {"noncanonical_bundle_manifest", "self_field_violation"}

    # key_order reorders top-level keys ("entries" then "schema"), which is
    # coincidentally identical to the canonical alphabetical ordering for
    # this particular manifest shape. Assert only the fixture's own
    # well-formedness: the mutation parses to the same JSON value as the
    # canonical manifest (a strict importer comparing exact bytes would
    # accept this particular raw text as already canonical).
    key_order_bytes = mutation_cases["key_order"]["raw_manifest_text"].encode("utf-8")
    assert json.loads(key_order_bytes) == json.loads(canonical_bytes_value)
