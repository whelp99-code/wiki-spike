"""Signed binding-registry authority for the Encrypted Single-Memory
Lifecycle (Gate 2).

This module OWNS the binding registry: an append-only, hash-chained,
Ed25519-signed history of provider-custody leaves (RFC 6962 Merkle tree),
a 256-level Sparse Merkle current-state map, signed checkpoints binding
history/map/veto/transition commitments together, latest-read
attestations bound to a (request_nonce, challenge_counter, local floor)
tuple, and the R9-3/R10-5 ordered proof-set verification pipeline.

Authority: ADR-0026 (authority/identity), ADR-0027 (recovery/deletion),
and the ralplan Stage 08/09/10 revision plans (R9-3, R10-2, R10-4,
R10-5), Revision 10 authoritative wherever it conflicts with Stage 8/9
text.

This module NEVER re-implements canonicalization or cryptographic
primitives: canonical byte encoding comes from
``wiki_spike.memory_core.contracts.canonical_bytes`` and every hash /
signature / Merkle / sparse-Merkle primitive comes from
``wiki_spike.infrastructure.crypto``. It only orchestrates those
primitives into the binding-registry wire objects and their ordered
validation pipeline. All wire numerics are canonical decimal strings,
never JSON numbers (frozen Core ``canonical_bytes`` rejects int/float).

Persistence: SQLite (``wiki_spike.infrastructure.lifecycle_db``) is a
cache only, never the destroy/restore authority (ADR-0026 §1,
ADR-0027). Callers may optionally pass a ``UnitOfWork`` to mirror
appended leaves/checkpoints into the ``binding_leaf`` /
``binding_checkpoint`` cache tables; the in-memory signed history is
always the sole binding authority for classification decisions.
"""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes

if TYPE_CHECKING:  # pragma: no cover
    from wiki_spike.infrastructure.lifecycle_db import UnitOfWork

# ---------------------------------------------------------------------------
# Domains (R10-2 single signature-input-construction rule; ADR-0026 §4).
# ---------------------------------------------------------------------------

DOMAIN_ATTESTATION = "wiki.binding.latest-read-attestation.v1"
DOMAIN_HISTORY_LEAF = "wiki.binding.history-leaf.v1"
DOMAIN_CHECKPOINT = "wiki.binding.checkpoint.v1"

LEAF_SCHEMA = "wiki-binding-registry-leaf-v1"
LEAF_SIGNATURE_SCHEMA = "wiki-binding-registry-leaf-signature-v1"
CHECKPOINT_SCHEMA = "wiki-binding-registry-checkpoint-v1"
CHECKPOINT_SIGNATURE_SCHEMA = "wiki-binding-registry-checkpoint-signature-v1"
ATTESTATION_SCHEMA = "wiki-binding-latest-read-attestation-v1"
MEMBERSHIP_PROOF_SCHEMA = "wiki-binding-current-membership-proof-v1"
NONMEMBERSHIP_PROOF_SCHEMA = "wiki-binding-current-nonmembership-proof-v1"
INCLUSION_PROOF_SCHEMA = "wiki-binding-history-inclusion-proof-v1"
CONSISTENCY_PROOF_SCHEMA = "wiki-binding-history-consistency-proof-v1"
PROOF_SET_SCHEMA = "wiki-binding-registry-proof-set-v1"


class BindingRegistryError(RuntimeError):
    """Raised on any binding-registry invariant violation.

    ``code`` is a short machine-readable failure reason (e.g.
    ``"history_root_mismatch"``, ``"signature_invalid"``,
    ``"attestation_floor_mismatch"``, ``"fork_detected"``) so callers
    and tests can assert on the exact failure mode without string
    matching the human-readable message.
    """

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


def _map_key_hex(workspace_id: str, namespace: str, provider_handle: str) -> str:
    """Current-map key = SHA-256(canonical bytes of the domain-framed key
    object) per the Stage-8 binding current-map wire spec (domain/version/
    workspace_id-scoped, not a bare namespace:handle concatenation)."""
    return hashlib.sha256(
        canonical_bytes(
            {
                "domain": "wiki.binding-registry.current-key",
                "version": "1",
                "workspace_id": workspace_id,
                "namespace": namespace,
                "provider_handle": provider_handle,
            }
        )
    ).hexdigest()


def _leaf_hash_hex(leaf: Mapping) -> str:
    return hashlib.sha256(canonical_bytes(leaf)).hexdigest()


def _sign(key: Ed25519PrivateKey, domain: str, payload: Mapping) -> str:
    return crypto.sign(key, domain, payload)


def _verify_signature(
    pub_key: Ed25519PublicKey,
    domain: str,
    payload: Mapping,
    signature_hex: str,
    error_code: str = "signature_invalid",
) -> None:
    try:
        crypto.verify(pub_key, domain, payload, signature_hex)
    except InvalidSignature as exc:
        raise BindingRegistryError(
            error_code, f"Ed25519 verification failed under domain {domain!r}"
        ) from exc


# ---------------------------------------------------------------------------
# RFC 6962 audit-path verification (mirrors crypto.merkle_inclusion_proof /
# crypto.merkle_consistency_proof's exact recursive split construction so
# that any proof produced by those functions round-trips through these
# verifiers; these are proof-side reconstructions built purely from
# node_hash, never a re-implementation of the hash/canonicalization
# primitives themselves).
# ---------------------------------------------------------------------------


def _verify_inclusion(leaf_h: bytes, index: int, audit_path: Sequence[bytes], tree_size: int, root: bytes) -> bool:
    if tree_size <= 0 or not (0 <= index < tree_size):
        return False
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
            if not proof:
                raise BindingRegistryError("inclusion_proof_invalid", "audit path exhausted early")
            right = proof.pop(0)
            return crypto.node_hash(left, right)
        right = replay(lo + split, hi)
        if not proof:
            raise BindingRegistryError("inclusion_proof_invalid", "audit path exhausted early")
        left = proof.pop(0)
        return crypto.node_hash(left, right)

    computed = replay(0, tree_size)
    return not proof and computed == root


def _verify_consistency(old_size: int, new_size: int, audit_path: Sequence[bytes]) -> tuple[bool, bytes, bytes]:
    """Returns ``(ok, reconstructed_old_root, reconstructed_new_root)``."""
    if old_size <= 0 or old_size >= new_size:
        return False, b"", b""
    proof = list(audit_path)

    def replay(lo: int, hi: int, m: int) -> tuple[bytes, bytes] | None:
        n = hi - lo
        if m == n:
            if not proof:
                return None
            r = proof.pop(0)
            return r, r
        split = 1
        while split * 2 < n:
            split *= 2
        if m <= split:
            inner = replay(lo, lo + split, m)
            if inner is None or not proof:
                return None
            left_new, left_old = inner
            right_new = proof.pop(0)
            return crypto.node_hash(left_new, right_new), left_old
        inner = replay(lo + split, hi, m - split)
        if inner is None or not proof:
            return None
        right_new, right_old = inner
        left_new = proof.pop(0)
        return crypto.node_hash(left_new, right_new), crypto.node_hash(left_new, right_old)

    result = replay(0, new_size, old_size)
    if result is None or proof:
        return False, b"", b""
    new_root, old_root = result
    return True, old_root, new_root


def _reconstruct_smt_root(key_int: int, leaf_value: bytes, siblings: Sequence[bytes]) -> bytes:
    node = leaf_value
    for depth in range(crypto.SMT_DEPTH - 1, -1, -1):
        sibling = siblings[depth]
        if crypto.smt_bit(key_int, depth) == 0:
            node = hashlib.sha256(b"\x02" + node + sibling).digest()
        else:
            node = hashlib.sha256(b"\x02" + sibling + node).digest()
    return node


class BindingRegistry:
    """The signed binding authority: append-only history + sparse current
    map + signed checkpoints + latest-read attestations + proof-set
    build/verify.

    One instance owns one workspace's binding registry state in memory;
    ``UnitOfWork`` mirroring (a SQLite cache, never authoritative) is
    optional per call.
    """

    def __init__(self, workspace_id: str) -> None:
        self.workspace_id = workspace_id
        self._leaves: list[dict] = []
        self._leaf_hashes: list[bytes] = []
        self._history_entry_hashes: list[bytes] = []
        self._signed_leaves: list[dict] = []
        self._smt_items: dict[int, bytes] = {}
        self._current_signed_leaf_by_key: dict[int, dict] = {}
        self._checkpoints: list[tuple[dict, dict]] = []
        self._consumed_nonces: set[tuple[str, str]] = set()

    # -- read-only state ----------------------------------------------- #

    @property
    def history_size(self) -> int:
        return len(self._leaf_hashes)

    @property
    def history_root_hex(self) -> str:
        return crypto.merkle_root(self._history_entry_hashes).hex()

    @property
    def current_map_size(self) -> int:
        return len(self._smt_items)

    @property
    def current_map_root_hex(self) -> str:
        return crypto.smt_root(self._smt_items).hex()

    @property
    def leaves(self) -> list[dict]:
        return list(self._leaves)

    @property
    def signed_leaves(self) -> list[dict]:
        return list(self._signed_leaves)

    @property
    def leaf_hashes_hex(self) -> list[str]:
        return [h.hex() for h in self._history_entry_hashes]

    # -- append-only signed history -------------------------------------- #

    def _validate_chain(self, leaf: Mapping) -> None:
        expected_seq = len(self._leaves) + 1
        try:
            actual_seq = int(leaf["registry_sequence"])
        except (KeyError, ValueError) as exc:
            raise BindingRegistryError(
                "invalid_sequence", "registry_sequence must be a positive decimal string"
            ) from exc
        if actual_seq < expected_seq:
            raise BindingRegistryError(
                "regression_detected",
                f"registry_sequence {actual_seq} regresses behind expected {expected_seq}",
            )
        if actual_seq > expected_seq:
            raise BindingRegistryError(
                "gap_detected", f"registry_sequence {actual_seq} skips ahead of expected {expected_seq}"
            )
        expected_prior = self._leaf_hashes[-1].hex() if self._leaf_hashes else None
        if leaf.get("prior_leaf_hash") != expected_prior:
            raise BindingRegistryError(
                "fork_detected", "prior_leaf_hash does not match the current history head"
            )

    def append_signed_leaf(
        self,
        leaf: Mapping,
        *,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        uow: "UnitOfWork | None" = None,
        created_at: str = "",
    ) -> dict:
        """Low-level append: ``leaf`` must already carry ``registry_sequence``
        and ``prior_leaf_hash``. Validates the append-only chain (rejects
        fork/gap/regression) before any mutation or signing (abort before
        effect)."""
        leaf = dict(leaf)
        self._validate_chain(leaf)
        lh = crypto.leaf_hash(canonical_bytes(leaf))
        signature = _sign(signing_key, DOMAIN_HISTORY_LEAF, leaf)
        signed = {
            "leaf": leaf,
            "leaf_signature": {
                "schema": LEAF_SIGNATURE_SCHEMA,
                "algorithm": "Ed25519",
                "key_id": key_id,
                "leaf_hash": _leaf_hash_hex(leaf),
                "signature": signature,
            },
        }
        self._leaves.append(leaf)
        self._leaf_hashes.append(lh)
        self._history_entry_hashes.append(crypto.leaf_hash(canonical_bytes(signed)))
        self._signed_leaves.append(signed)

        map_key_hex = _map_key_hex(self.workspace_id, leaf["namespace"], leaf["provider_handle"])
        map_key_int = crypto.hexkey_to_int(map_key_hex)
        map_value = hashlib.sha256(canonical_bytes(signed)).digest()
        self._smt_items[map_key_int] = map_value
        self._current_signed_leaf_by_key[map_key_int] = signed

        if uow is not None:
            uow.insert_binding_leaf(
                leaf_id=lh.hex(),
                namespace_id=leaf["namespace"],
                provider_handle=leaf["provider_handle"],
                leaf_state=leaf["status"],
                leaf_digest=lh.hex(),
                created_at=created_at,
            )
        return signed

    def append_leaf(
        self,
        *,
        namespace: str,
        provider_handle: str,
        provider_key_fingerprint: str,
        intent_id: str,
        artifact_id: str,
        revision_id: str,
        semantic_digest: str,
        metadata_digest: str,
        status: str,
        activation_generation_id: str | None,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        uow: "UnitOfWork | None" = None,
        created_at: str = "",
    ) -> dict:
        """High-level append: registry computes ``registry_sequence`` and
        ``prior_leaf_hash`` from its own current head."""
        leaf = {
            "schema": LEAF_SCHEMA,
            "workspace_id": self.workspace_id,
            "registry_sequence": str(len(self._leaves) + 1),
            "namespace": namespace,
            "provider_handle": provider_handle,
            "provider_key_fingerprint": provider_key_fingerprint,
            "intent_id": intent_id,
            "artifact_id": artifact_id,
            "revision_id": revision_id,
            "semantic_digest": semantic_digest,
            "metadata_digest": metadata_digest,
            "status": status,
            "activation_generation_id": activation_generation_id,
            "prior_leaf_hash": self._leaf_hashes[-1].hex() if self._leaf_hashes else None,
        }
        return self.append_signed_leaf(leaf, signing_key=signing_key, key_id=key_id, uow=uow, created_at=created_at)

    # -- signed checkpoint ------------------------------------------------ #

    def checkpoint(
        self,
        *,
        generation_id: str,
        created_at: str,
        signing_key: Ed25519PrivateKey,
        key_id: str,
        veto_set_size: str = "0",
        veto_set_root: str | None = None,
        transition_size: str = "0",
        transition_root: str | None = None,
        prior_checkpoint_hash: str | None = None,
        registry_sequence: str | None = None,
        uow: "UnitOfWork | None" = None,
    ) -> tuple[dict, dict]:
        """Builds and signs ``wiki-binding-registry-checkpoint-v1`` binding
        history_size/root, current_map_root, and veto/transition
        commitments together. Returns ``(checkpoint, checkpoint_signature)``."""
        if veto_set_root is None:
            veto_set_root = crypto.SMT_DEFAULT[crypto.SMT_DEPTH].hex()
        if transition_root is None:
            transition_root = crypto.SMT_DEFAULT[crypto.SMT_DEPTH].hex()
        ck = {
            "schema": CHECKPOINT_SCHEMA,
            "workspace_id": self.workspace_id,
            "generation_id": generation_id,
            "registry_sequence": registry_sequence if registry_sequence is not None else str(len(self._leaves)),
            "history_size": str(len(self._leaf_hashes)),
            "history_root": self.history_root_hex,
            "current_leaf_count": str(len(self._smt_items)),
            "current_map_root": self.current_map_root_hex,
            "veto_set_size": veto_set_size,
            "veto_set_root": veto_set_root,
            "transition_size": transition_size,
            "transition_root": transition_root,
            "created_at": created_at,
            "prior_checkpoint_hash": prior_checkpoint_hash,
            "signer_key_id": key_id,
        }
        checkpoint_sha256 = hashlib.sha256(canonical_bytes(ck)).hexdigest()
        signature = _sign(signing_key, DOMAIN_CHECKPOINT, ck)
        sig_obj = {
            "schema": CHECKPOINT_SIGNATURE_SCHEMA,
            "algorithm": "Ed25519",
            "key_id": key_id,
            "checkpoint_sha256": checkpoint_sha256,
            "signature": signature,
        }
        self._checkpoints.append((ck, sig_obj))
        if uow is not None:
            uow.insert_binding_checkpoint(
                checkpoint_id=checkpoint_sha256,
                checkpoint_sha256=checkpoint_sha256,
                checkpoint_sequence=ck["registry_sequence"],
                history_root_digest=ck["history_root"],
                current_map_root_digest=ck["current_map_root"],
                created_at=created_at,
            )
        return ck, sig_obj

    # -- latest-read attestation ------------------------------------------ #

    def attest(
        self,
        *,
        request_nonce: str,
        challenge_counter: str,
        request_floor_checkpoint_id: str,
        signer_key_id: str,
        issued_at: str,
        expires_at: str,
        signing_key: Ed25519PrivateKey,
        checkpoint: Mapping | None = None,
        checkpoint_id: str | None = None,
        checkpoint_sha256: str | None = None,
        checkpoint_sequence: str | None = None,
    ) -> dict:
        """Builds and signs a ``BindingLatestReadAttestationPayloadV1`` wire
        object (R9-3/R10-4/R10-5). ``history_size``/``history_root`` and
        ``current_map_size``/``current_map_root`` are always the registry's
        own live state (directly-signed roots/sizes, R10-4).

        Either pass ``checkpoint=`` (the checkpoint object being attested
        to) so that ``checkpoint_id == checkpoint_sha256 ==
        sha256(canonical checkpoint bytes)`` per R10-4, or pass the three
        ``checkpoint_*`` values explicitly.
        """
        if checkpoint is not None:
            cid = csha = hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()
            cseq = checkpoint["registry_sequence"]
        else:
            if checkpoint_id is None or checkpoint_sha256 is None or checkpoint_sequence is None:
                raise ValueError(
                    "attest() requires either checkpoint= or all of "
                    "checkpoint_id/checkpoint_sha256/checkpoint_sequence"
                )
            cid, csha, cseq = checkpoint_id, checkpoint_sha256, checkpoint_sequence

        payload = {
            "schema": ATTESTATION_SCHEMA,
            "workspace_id": self.workspace_id,
            "request_nonce": request_nonce,
            "challenge_counter": challenge_counter,
            "request_floor_checkpoint_id": request_floor_checkpoint_id,
            "checkpoint_id": cid,
            "checkpoint_sha256": csha,
            "checkpoint_sequence": cseq,
            "history_size": str(len(self._leaf_hashes)),
            "history_root": self.history_root_hex,
            "current_map_size": str(len(self._smt_items)),
            "current_map_root": self.current_map_root_hex,
            "signer_key_id": signer_key_id,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        signature = _sign(signing_key, DOMAIN_ATTESTATION, payload)
        return {"payload": payload, "signature_algorithm": "Ed25519", "signature": signature}

    def sparse_proof_for_map_key(self, map_key_hex: str) -> dict:
        """Builds a membership or non-membership proof for an arbitrary
        raw 256-bit ``map_key_hex`` (not necessarily derived from a
        ``(namespace, provider_handle)`` pair — e.g. an unregistered
        probe key used to demonstrate non-membership)."""
        map_key_int = crypto.hexkey_to_int(map_key_hex)
        siblings = crypto.smt_proof(self._smt_items, map_key_int)
        if map_key_int in self._smt_items:
            return {
                "schema": MEMBERSHIP_PROOF_SCHEMA,
                "map_key": map_key_hex,
                "signed_leaf": self._current_signed_leaf_by_key[map_key_int],
                "siblings": [s.hex() for s in siblings],
            }
        return {
            "schema": NONMEMBERSHIP_PROOF_SCHEMA,
            "map_key": map_key_hex,
            "signed_leaf": None,
            "siblings": [s.hex() for s in siblings],
        }

    # -- proof-set construction -------------------------------------------- #

    def build_proof_set(
        self,
        *,
        attestation: Mapping,
        checkpoint: Mapping,
        checkpoint_signature: Mapping,
        namespace: str,
        provider_handle: str,
        old_size: int,
        inclusion_indices: Sequence[int] = (),
        predecessor_leaf_indices: Sequence[int] = (),
        current_leaf_override: Mapping | None = None,
    ) -> dict:
        """Builds a ``BindingRegistryProofSetV1`` proving the current
        (or absent) binding for ``(namespace, provider_handle)`` together
        with history inclusion/consistency evidence from ``old_size``
        through the registry's current history size.

        ``current_leaf_override``, when given, is emitted as the
        top-level ``current_leaf`` slot verbatim instead of the sparse
        proof's own ``signed_leaf`` (needed to reproduce wire vectors
        that demonstrate the ``current_leaf``/``current_sparse_proof``
        fields independently)."""
        sparse_proof = self.sparse_proof_for_map_key(_map_key_hex(self.workspace_id, namespace, provider_handle))
        current_signed_leaf = current_leaf_override if current_leaf_override is not None else sparse_proof["signed_leaf"]

        new_size = len(self._leaf_hashes)
        inclusion_proofs = [
            {
                "schema": INCLUSION_PROOF_SCHEMA,
                "history_size": str(new_size),
                "leaf_index": str(i),
                "audit_path": [h.hex() for h in crypto.merkle_inclusion_proof(self._history_entry_hashes, i)],
            }
            for i in inclusion_indices
        ]
        consistency_proof = {
            "schema": CONSISTENCY_PROOF_SCHEMA,
            "old_size": str(old_size),
            "new_size": str(new_size),
            "audit_path": [h.hex() for h in crypto.merkle_consistency_proof(self._history_entry_hashes, old_size, new_size)],
        }
        predecessor = [self._signed_leaves[i] for i in predecessor_leaf_indices]

        return {
            "schema": PROOF_SET_SCHEMA,
            "attestation": attestation,
            "checkpoint": checkpoint,
            "checkpoint_signature": checkpoint_signature,
            "current_leaf": current_signed_leaf,
            "current_sparse_proof": sparse_proof,
            "predecessor_transition_leaves": predecessor,
            "history_inclusion_proofs": inclusion_proofs,
            "history_consistency_proof": consistency_proof,
        }

    # -- proof-set verification (R9-3, amended by R10-5, ordered) --------- #

    def verify_proof_set(
        self,
        proof_set: Mapping,
        *,
        trusted_signer_pub: Ed25519PublicKey,
        local_floor_checkpoint_id: str,
        expected_namespace: str | None = None,
        expected_provider_handle: str | None = None,
        trusted_old_size: int | None = None,
        trusted_old_root_hex: str | None = None,
    ) -> None:
        """Ordered validation pipeline (ADR-0027 R9-3/R10-5): strict
        decode/raw canonical-byte equality; attestation signature/nonce/
        counter/signer chain and ``request_floor_checkpoint_id`` equality;
        checkpoint ID/signature and equality with signed roots/sizes;
        history consistency (optionally anchored to the trusted floor's
        signed old_size/old_root); every inclusion/predecessor leaf; sparse
        membership/non-membership; abort-before-effect (nonce is only
        consumed after every prior check succeeds) on any mismatch.

        Raises :class:`BindingRegistryError` on the first failure.
        """
        required = (
            "schema",
            "attestation",
            "checkpoint",
            "checkpoint_signature",
            "current_leaf",
            "current_sparse_proof",
            "predecessor_transition_leaves",
            "history_inclusion_proofs",
            "history_consistency_proof",
        )
        for key in required:
            if key not in proof_set:
                raise BindingRegistryError("proof_set_malformed", f"missing field {key!r}")
        if proof_set["schema"] != PROOF_SET_SCHEMA:
            raise BindingRegistryError("proof_set_malformed", "unexpected proof_set schema")

        attestation = proof_set["attestation"]
        checkpoint = proof_set["checkpoint"]
        checkpoint_signature = proof_set["checkpoint_signature"]

        # 1. attestation signature / nonce / counter / signer chain.
        payload = attestation["payload"]
        if attestation.get("signature_algorithm") != "Ed25519":
            raise BindingRegistryError("signature_invalid", "unsupported attestation signature algorithm")
        if not crypto.is_challenge_nonce_hex64(str(payload.get("request_nonce", ""))):
            raise BindingRegistryError("nonce_invalid", "request_nonce is not a well-formed challenge nonce")
        _verify_signature(trusted_signer_pub, DOMAIN_ATTESTATION, payload, attestation["signature"])
        nonce_key = (payload["request_nonce"], payload["challenge_counter"])
        if nonce_key in self._consumed_nonces:
            raise BindingRegistryError("nonce_replay", "request_nonce/challenge_counter already consumed")

        # 2. request_floor_checkpoint_id must equal the local floor (R10-5).
        if payload["request_floor_checkpoint_id"] != local_floor_checkpoint_id:
            raise BindingRegistryError(
                "attestation_floor_mismatch",
                "request_floor_checkpoint_id does not match the local floor checkpoint",
            )

        # 3. checkpoint ID/signature and equality with signed roots/sizes.
        recomputed_checkpoint_sha256 = hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()
        if checkpoint_signature.get("checkpoint_sha256") != recomputed_checkpoint_sha256:
            raise BindingRegistryError(
                "checkpoint_sha256_mismatch",
                "checkpoint_signature.checkpoint_sha256 does not match the recomputed checkpoint digest",
            )
        if checkpoint_signature.get("algorithm") != "Ed25519":
            raise BindingRegistryError("signature_invalid", "unsupported checkpoint signature algorithm")
        _verify_signature(trusted_signer_pub, DOMAIN_CHECKPOINT, checkpoint, checkpoint_signature["signature"])

        if payload["history_root"] != checkpoint["history_root"]:
            raise BindingRegistryError("history_root_mismatch", "attestation/checkpoint history_root disagree")
        if payload["history_size"] != checkpoint["history_size"]:
            raise BindingRegistryError("history_size_mismatch", "attestation/checkpoint history_size disagree")
        if payload["current_map_root"] != checkpoint["current_map_root"]:
            raise BindingRegistryError(
                "current_map_root_mismatch", "attestation/checkpoint current_map_root disagree"
            )
        if payload["current_map_size"] != checkpoint["current_leaf_count"]:
            raise BindingRegistryError(
                "current_map_size_mismatch", "attestation current_map_size vs checkpoint current_leaf_count disagree"
            )

        history_root = bytes.fromhex(checkpoint["history_root"])
        history_size = int(checkpoint["history_size"])

        # 4. history consistency from the locally trusted floor.
        consistency = proof_set["history_consistency_proof"]
        old_size = int(consistency["old_size"])
        new_size = int(consistency["new_size"])
        if new_size != history_size:
            raise BindingRegistryError(
                "consistency_proof_invalid", "consistency proof new_size does not match checkpoint history_size"
            )
        if trusted_old_size is not None and old_size != trusted_old_size:
            raise BindingRegistryError(
                "consistency_proof_invalid",
                "consistency proof old_size does not match the trusted floor old_size",
            )
        if old_size == 0:
            pass  # nothing to prove against an empty prior history
        elif old_size == new_size:
            if consistency["audit_path"]:
                raise BindingRegistryError(
                    "consistency_proof_invalid", "non-empty audit path for old_size == new_size"
                )
        else:
            audit_path = [bytes.fromhex(h) for h in consistency["audit_path"]]
            ok, reconstructed_old_root, computed_new_root = _verify_consistency(old_size, new_size, audit_path)
            if not ok or computed_new_root != history_root:
                raise BindingRegistryError(
                    "consistency_proof_invalid", "consistency proof does not reconstruct the checkpoint history_root"
                )
            if trusted_old_root_hex is not None and reconstructed_old_root.hex() != trusted_old_root_hex:
                raise BindingRegistryError(
                    "consistency_proof_invalid",
                    "consistency proof reconstructed old_root does not match the trusted floor old_root",
                )

        # 5. every inclusion / predecessor + terminal current leaf, ordered.
        combined_leaves = list(proof_set["predecessor_transition_leaves"])
        if proof_set["current_leaf"] is not None:
            combined_leaves.append(proof_set["current_leaf"])
        inclusion_proofs = proof_set["history_inclusion_proofs"]
        if len(combined_leaves) != len(inclusion_proofs):
            raise BindingRegistryError(
                "inclusion_proof_invalid",
                "history_inclusion_proofs cardinality does not match predecessor+current leaf set",
            )
        for signed_leaf, inc in zip(combined_leaves, inclusion_proofs):
            leaf = signed_leaf["leaf"]
            leaf_hash_hex = _leaf_hash_hex(leaf)
            if leaf_hash_hex != signed_leaf["leaf_signature"]["leaf_hash"]:
                raise BindingRegistryError(
                    "leaf_hash_mismatch", "leaf does not hash to its declared leaf_signature.leaf_hash"
                )
            _verify_signature(
                trusted_signer_pub, DOMAIN_HISTORY_LEAF, leaf, signed_leaf["leaf_signature"]["signature"]
            )
            expected_index = int(leaf["registry_sequence"]) - 1
            if int(inc["leaf_index"]) != expected_index:
                raise BindingRegistryError(
                    "inclusion_proof_invalid", "inclusion proof leaf_index does not match leaf registry_sequence"
                )
            if int(inc["history_size"]) != history_size:
                raise BindingRegistryError(
                    "inclusion_proof_invalid", "inclusion proof history_size does not match checkpoint history_size"
                )
            audit_path = [bytes.fromhex(h) for h in inc["audit_path"]]
            leaf_h = crypto.leaf_hash(canonical_bytes(signed_leaf))
            if not _verify_inclusion(leaf_h, expected_index, audit_path, history_size, history_root):
                raise BindingRegistryError(
                    "inclusion_proof_invalid", "inclusion proof does not reconstruct the checkpoint history_root"
                )

        # 6. sparse membership / non-membership against checkpoint.current_map_root.
        sparse = proof_set["current_sparse_proof"]
        map_key_hex = sparse["map_key"]
        map_key_int = crypto.hexkey_to_int(map_key_hex)
        siblings = [bytes.fromhex(s) for s in sparse["siblings"]]
        if len(siblings) != crypto.SMT_DEPTH:
            raise BindingRegistryError("membership_proof_invalid", "sparse proof must carry exactly 256 siblings")

        # 6a. Bind the sparse proof to the caller's queried identity (both
        # membership and non-membership) so a valid proof for a different
        # (namespace, provider_handle) cannot be substituted (P2-3).
        if expected_namespace is not None and expected_provider_handle is not None:
            expected_query_key = _map_key_hex(self.workspace_id, expected_namespace, expected_provider_handle)
            if map_key_hex != expected_query_key:
                raise BindingRegistryError(
                    "membership_proof_identity_mismatch",
                    "sparse proof map_key does not match the queried (namespace, provider_handle)",
                )

        if proof_set["current_leaf"] is not None:
            cl_leaf = proof_set["current_leaf"]["leaf"]
            expected_map_key = _map_key_hex(cl_leaf["workspace_id"], cl_leaf["namespace"], cl_leaf["provider_handle"])
            if map_key_hex != expected_map_key:
                raise BindingRegistryError(
                    "membership_proof_invalid",
                    "sparse proof map_key does not match current_leaf namespace/provider_handle",
                )

        if sparse["schema"] == MEMBERSHIP_PROOF_SCHEMA:
            signed_leaf = sparse["signed_leaf"]
            if signed_leaf is None:
                raise BindingRegistryError("membership_proof_invalid", "membership proof is missing signed_leaf")
            leaf = signed_leaf["leaf"]
            leaf_hash_hex = _leaf_hash_hex(leaf)
            if leaf_hash_hex != signed_leaf["leaf_signature"]["leaf_hash"]:
                raise BindingRegistryError(
                    "leaf_hash_mismatch", "membership proof leaf does not hash to its own leaf_signature.leaf_hash"
                )
            _verify_signature(
                trusted_signer_pub, DOMAIN_HISTORY_LEAF, leaf, signed_leaf["leaf_signature"]["signature"]
            )
            leaf_value = crypto.smt_leaf(map_key_int, hashlib.sha256(canonical_bytes(signed_leaf)).digest())
        elif sparse["schema"] == NONMEMBERSHIP_PROOF_SCHEMA:
            if sparse["signed_leaf"] is not None:
                raise BindingRegistryError(
                    "membership_proof_invalid", "non-membership proof must not carry a signed_leaf"
                )
            leaf_value = crypto.SMT_DEFAULT[0]
        else:
            raise BindingRegistryError("proof_set_malformed", "unknown current_sparse_proof schema")

        computed_map_root = _reconstruct_smt_root(map_key_int, leaf_value, siblings)
        if computed_map_root.hex() != checkpoint["current_map_root"]:
            raise BindingRegistryError(
                "membership_proof_invalid", "sparse proof does not reconstruct checkpoint current_map_root"
            )

        # 7. abort-before-effect: only now, after every check has passed,
        # advance verifier-local replay-protection state.
        self._consumed_nonces.add(nonce_key)
