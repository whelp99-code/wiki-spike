"""Encrypted lifecycle deterministic vertical pipeline (Gate 3).

Orchestrates the full REMEMBER → APPROVE/REJECT → change set → signed
generation / binding checkpoint → activation via readback/CAS → opaque
projection pipeline per the Stage 8 Gate 3 specification.

Architecture-boundary contract: application layer; may import
``wiki_spike.memory_core`` and ``wiki_spike.infrastructure`` only.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from wiki_spike.infrastructure import crypto, floor_protocol, identities
from wiki_spike.infrastructure.changeset import (
    build_encrypted_accepted_changeset,
    build_state_delta,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore, EncryptedCASError
from wiki_spike.infrastructure.ingestion import (
    input_content_digest,
    normalize_lifecycle_input_v1,
    remember_options,
)
from wiki_spike.infrastructure.keystore import CreateOnlyKeyStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, UnitOfWork
from wiki_spike.memory_core.contracts import canonical_bytes

GENERATION_DOMAIN = "wiki.generation.v1"


class PipelineError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class RememberResult:
    command_id: str
    manifest_digest: str
    artifact_semantic_digest: str
    logical_object_id: str
    revision_id: str
    blob_id: str
    envelope: dict


@dataclass
class EncryptedLifecyclePipeline:
    """Gate 3 deterministic vertical pipeline.

    Coordinates identity derivation, input normalization, envelope
    sealing, CAS persistence, DB unit-of-work, and change-set
    construction for the encrypted single-memory lifecycle.
    """

    workspace_id: str
    derived_keys: dict[str, bytes]
    db: LifecycleDatabase
    cas: EncryptedContentStore
    dek: bytes  # AES-256-GCM data encryption key (32 bytes)

    def remember(
        self,
        *,
        raw_body: bytes,
        project_id: str,
        source_kind: str = "INLINE_TEXT",
        input_format: str = "PLAIN_TEXT",
        source_instance_id: str = "inline",
        subject_ordinal: str = "0",
        sensitivity: str = "INTERNAL",
        consent_epoch: str = "1",
        extractor_profile: str = "LOCAL_RULES_V1",
        policy_context_digest: str | None = None,
    ) -> RememberResult:
        """REMEMBER ingestion: normalize → identities → seal → persist."""
        normalized = normalize_lifecycle_input_v1(raw_body)
        content_digest = input_content_digest(normalized)

        if policy_context_digest is None:
            policy_context_digest = hashlib.sha256(b"default-policy-context").hexdigest()

        opts = remember_options(
            project_id=project_id,
            source_kind=source_kind,
            input_format=input_format,
            source_instance_id=source_instance_id,
            subject_ordinal=subject_ordinal,
            sensitivity=sensitivity,
            consent_epoch=consent_epoch,
            extractor_profile=extractor_profile,
        )

        _, command_id = identities.command_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            command_kind="REMEMBER",
            normalized_options=opts,
            input_content_digest=content_digest,
            policy_context_digest=policy_context_digest,
        )

        stable_subject_msg, stable_subject_digest = identities.stable_subject_ref(
            self.derived_keys,
            workspace_id=self.workspace_id,
            project_id=project_id,
            source_instance_id=source_instance_id,
            subject_ordinal=subject_ordinal,
        )

        semantic_plaintext = {
            "schema": "wiki-memory-revision-semantic-v1",
            "project_id": project_id,
            "subject_key_digest": stable_subject_digest,
            "consent_epoch": consent_epoch,
            "sensitivity": sensitivity,
            "normalized_text": normalized.decode("utf-8"),
            "language": "und",
            "parent_revision_id": None,
        }
        _, artifact_semantic_digest_hex = identities.artifact_semantic_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            artifact_kind="MEMORY_REVISION",
            consent_epoch=consent_epoch,
            semantic_schema="wiki-memory-revision-semantic-v1",
            semantic_plaintext=semantic_plaintext,
        )

        _, logical_object_id_hex = identities.logical_object_id(
            self.derived_keys,
            workspace_id=self.workspace_id,
            object_kind="MEMORY",
            consent_epoch=consent_epoch,
            subject_key_digest=stable_subject_digest,
        )

        _, revision_id_hex = identities.revision_id(
            self.derived_keys,
            workspace_id=self.workspace_id,
            object_kind="MEMORY",
            logical_object_id_hex=logical_object_id_hex,
            consent_epoch=consent_epoch,
            revision_number="1",
            parent_revision_id=None,
            artifact_semantic_digest_hex=artifact_semantic_digest_hex,
        )

        nonce_hex = os.urandom(12).hex()
        aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(artifact_semantic_digest_hex)
        ciphertext_hex, tag_hex = crypto.aes_gcm_seal(self.dek, nonce_hex, normalized, aad)
        now = _utcnow()
        envelope = {
            "schema": "wiki-envelope-v1",
            "version": "1",
            "algorithm": "AES-256-GCM",
            "workspace_id": self.workspace_id,
            "logical_object_id": logical_object_id_hex,
            "revision_id": revision_id_hex,
            "semantic_schema_id": "wiki-memory-revision-semantic-v1",
            "nonce": nonce_hex,
            "aad_digest": hashlib.sha256(aad).hexdigest(),
            "ciphertext": ciphertext_hex,
            "tag": tag_hex,
            "metadata": {
                "consent_epoch": consent_epoch,
                "key_version": "1",
                "content_length_bytes": str(len(normalized)),
                "created_at": now,
            },
        }
        envelope_bytes = canonical_bytes(envelope)
        blob_id = self.cas.put(envelope_bytes)

        entry = identities.manifest_entry(
            artifact_role="PRIMARY_MEMORY",
            ordinal="0",
            artifact_kind="MEMORY_REVISION",
            revision_id=revision_id_hex,
            artifact_semantic_digest=artifact_semantic_digest_hex,
        )
        _, manifest_digest_hex = identities.manifest_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            command_digest_hex=command_id,
            entries=[entry],
        )

        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.insert_command(
                command_id=command_id,
                workspace_id=self.workspace_id,
                command_kind="REMEMBER",
                input_digest=content_digest,
                command_state="ACCEPTED",
                created_at=now,
            )
            uow.insert_canonical_artifact(
                artifact_id=artifact_semantic_digest_hex,
                workspace_id=self.workspace_id,
                artifact_kind="MEMORY_REVISION",
                revision_id=revision_id_hex,
                artifact_state="PREPARED",
                created_at=now,
            )
            uow.insert_command_artifact(
                command_id=command_id,
                artifact_id=artifact_semantic_digest_hex,
                artifact_role="PRIMARY_MEMORY",
                ordinal="0",
            )
            uow.upsert_key_state(
                artifact_id=artifact_semantic_digest_hex,
                custody_state="PREPARED",
                updated_at=now,
            )

        prev = self.db.event_chain_head()
        self.db.append_event(
            prev_digest=prev,
            kind="REMEMBER_ACCEPTED",
            ref_digest=command_id,
        )

        return RememberResult(
            command_id=command_id,
            manifest_digest=manifest_digest_hex,
            artifact_semantic_digest=artifact_semantic_digest_hex,
            logical_object_id=logical_object_id_hex,
            revision_id=revision_id_hex,
            blob_id=blob_id,
            envelope=envelope,
        )

    def build_changeset(
        self,
        *,
        command_ids: Sequence[str],
        parent_generation_id: str | None = None,
        deltas: Sequence[Mapping] | None = None,
    ) -> dict:
        """Construct an EncryptedAcceptedChangeSetV1 from command IDs.

        If ``deltas`` is not supplied, a default ADD/MEMORY_REVISION delta
        is built for each command's primary artifact.
        """
        if deltas is None:
            deltas = []
            with self.db.unit_of_work() as uow:
                for cmd_id in command_ids:
                    cmd = uow.get_command(cmd_id)
                    if cmd is None:
                        raise PipelineError("command_not_found", f"command {cmd_id} not found")
                    artifacts = uow.list_command_artifacts(cmd_id)
                    for art_row in artifacts:
                        art = uow.get_canonical_artifact(art_row["artifact_id"])
                        if art is None:
                            continue
                        deltas.append(build_state_delta(
                            operation="ADD",
                            object_kind=art["artifact_kind"],
                            object_id=art["artifact_id"],
                            revision_id=art["revision_id"],
                            envelope_ref=art["artifact_id"],
                        ))

        return build_encrypted_accepted_changeset(
            workspace_id=self.workspace_id,
            parent_generation_id=parent_generation_id,
            command_ids=list(command_ids),
            deltas=deltas,
        )

    def persist_changeset(self, changeset: Mapping) -> None:
        """Persist a constructed changeset and its deltas to the DB cache."""
        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.insert_accepted_changeset(
                changeset_id=changeset["changeset_id"],
                workspace_id=changeset["workspace_id"],
                parent_generation_id=changeset["parent_generation_id"],
                changes_root_digest=changeset["changes_root"],
                changeset_state="ACCEPTED",
                created_at=now,
            )
            for delta in changeset["deltas"]:
                uow.insert_state_delta(
                    delta_id=delta["delta_id"],
                    changeset_id=changeset["changeset_id"],
                    operation_kind=delta["operation"],
                    object_kind=delta["object_kind"],
                    object_id=delta["object_id"],
                    revision_id=delta.get("revision_id"),
                    expected_active_revision_id=delta.get("expected_active_revision_id"),
                    envelope_ref_id=delta.get("envelope_ref"),
                    assertion_id=delta.get("assertion_id"),
                    evidence_edge_id=delta.get("evidence_edge_id"),
                    evidence_fragment_ref_id=delta.get("evidence_fragment_ref"),
                    deletion_command_id=delta.get("deletion_command_id"),
                    scope_digest=delta.get("scope_digest"),
                    reason_state=delta.get("reason_code"),
                )

        prev = self.db.event_chain_head()
        self.db.append_event(
            prev_digest=prev,
            kind="CHANGESET_ACCEPTED",
            ref_digest=changeset["changeset_id"],
        )

    # ------------------------------------------------------------------
    # APPROVE / REJECT candidate review
    # ------------------------------------------------------------------

    def review_candidate(
        self,
        *,
        artifact_id: str,
        reviewer_handle: str,
        review_state: str,
    ) -> str:
        """Record an APPROVE or REJECT review for a candidate artifact.

        ``review_state`` must be ``"APPROVED"`` or ``"REJECTED"``.
        Returns the review_id.
        """
        if review_state not in ("APPROVED", "REJECTED"):
            raise PipelineError("invalid_review_state", f"review_state must be APPROVED or REJECTED, got {review_state!r}")
        review_id = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.candidate-review.v1",
                "workspace_id": self.workspace_id,
                "artifact_id": artifact_id,
                "reviewer_handle": reviewer_handle,
                "review_state": review_state,
            })
        ).hexdigest()
        now = _utcnow()
        with self.db.unit_of_work() as uow:
            art = uow.get_canonical_artifact(artifact_id)
            if art is None:
                raise PipelineError("artifact_not_found", f"artifact {artifact_id} not found")
            uow.insert_candidate_review(
                review_id=review_id,
                artifact_id=artifact_id,
                reviewer_handle=reviewer_handle,
                review_state=review_state,
                created_at=now,
            )
            if review_state == "APPROVED":
                uow.upsert_key_state(artifact_id=artifact_id, custody_state="APPROVED", updated_at=now)

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind=f"CANDIDATE_{review_state}", ref_digest=artifact_id)
        return review_id

    # ------------------------------------------------------------------
    # Signed generation + binding checkpoint
    # ------------------------------------------------------------------

    def create_generation(
        self,
        *,
        changeset_id: str,
        signing_key: "Ed25519PrivateKey",
        signer_key_id: str,
        binding_registry: "BindingRegistry | None" = None,
        namespace: str = "encrypted-lifecycle",
        provider_handle: str = "default",
    ) -> dict:
        """Create a signed generation for an accepted changeset.

        Signs the generation payload under ``wiki.generation.v1`` (R10-2)
        and optionally appends a binding registry leaf + checkpoint.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        with self.db.unit_of_work() as uow:
            cs_row = uow.get_accepted_changeset(changeset_id)
            if cs_row is None:
                raise PipelineError("changeset_not_found", f"changeset {changeset_id} not found")

        generation_id = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.generation-id.v1",
                "workspace_id": self.workspace_id,
                "changeset_id": changeset_id,
                "changes_root": cs_row["changes_root_digest"],
            })
        ).hexdigest()

        generation_payload = {
            "domain": GENERATION_DOMAIN,
            "workspace_id": self.workspace_id,
            "generation_id": generation_id,
            "changeset_id": changeset_id,
            "changes_root": cs_row["changes_root_digest"],
        }
        signature = crypto.sign(signing_key, GENERATION_DOMAIN, generation_payload)

        binding_checkpoint_id = None
        if binding_registry is not None:
            deltas = []
            with self.db.unit_of_work() as uow:
                delta_rows = uow.list_state_deltas(changeset_id)
                for dr in delta_rows:
                    deltas.append(dict(dr))

            for dr in deltas:
                binding_registry.append_leaf(
                    namespace=namespace,
                    provider_handle=provider_handle,
                    provider_key_fingerprint=hashlib.sha256(signer_key_id.encode()).hexdigest(),
                    intent_id=dr.get("object_id", generation_id),
                    artifact_id=dr.get("object_id", generation_id),
                    revision_id=dr.get("revision_id") or generation_id,
                    semantic_digest=dr.get("scope_digest") or cs_row["changes_root_digest"],
                    metadata_digest=cs_row["changes_root_digest"],
                    status="PREPARED",
                    activation_generation_id=None,
                    signing_key=signing_key,
                    key_id=signer_key_id,
                )

            checkpoint, checkpoint_sig = binding_registry.checkpoint(
                generation_id=generation_id,
                created_at=_utcnow(),
                signing_key=signing_key,
                key_id=signer_key_id,
            )
            binding_checkpoint_id = hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()

        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.insert_generation(
                generation_id=generation_id,
                workspace_id=self.workspace_id,
                changeset_id=changeset_id,
                generation_state="SIGNED",
                binding_checkpoint_id=binding_checkpoint_id,
                created_at=now,
            )

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind="GENERATION_SIGNED", ref_digest=generation_id)

        return {
            "generation_id": generation_id,
            "signature": signature,
            "binding_checkpoint_id": binding_checkpoint_id,
            "payload": generation_payload,
        }
    # ------------------------------------------------------------------
    # Forward-only floor protocol + freshness serve gate (Gate 3 wiring)
    # ------------------------------------------------------------------

    def bootstrap_workspace(self) -> None:
        """Idempotently initialize the workspace floor to a stable genesis
        state (``FLOOR_STABLE``, generation "1") with a ``CLEAR``/``NONE``
        freshness serve gate. Safe to call more than once."""
        genesis_checkpoint_id = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.floor-genesis.v1",
                "workspace_id": self.workspace_id,
            })
        ).hexdigest()
        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.upsert_floor_state(
                workspace_id=self.workspace_id,
                stable_floor_generation="1",
                stable_checkpoint_id=genesis_checkpoint_id,
                attempt_state=floor_protocol.FloorState.FLOOR_STABLE.value,
                updated_at=now,
            )
            gate = floor_protocol.build_freshness_serve_gate(
                workspace_id=self.workspace_id,
                state="CLEAR",
                stable_floor_generation="1",
                stable_checkpoint_id=genesis_checkpoint_id,
                source_candidate_digest=genesis_checkpoint_id,
                reason="NONE",
                updated_at=now,
            )
            uow.upsert_freshness_serve_gate(
                workspace_id=self.workspace_id,
                gate_state=gate["state"],
                stable_floor_generation=gate["stable_floor_generation"],
                stable_checkpoint_id=gate["stable_checkpoint_id"],
                source_candidate_digest=gate["source_candidate_digest"],
                reason_state=gate["reason"],
                updated_at=now,
            )

    def advance_floor(
        self,
        *,
        candidate_floor: Mapping,
        counter: str,
        nonce_digest: str,
        simulate_readback: Mapping | None = None,
    ) -> str:
        """Drive one forward-only floor update through the FloorStateV1
        machine (R9-1 exact-A CAS readback, R10-1 no adoption/supersession).

        Transitions FLOOR_STABLE -> CHALLENGE_RESERVED ->
        FLOOR_UPDATE_PREPARED, persists the candidate, then verifies the
        committed keychain bytes (``simulate_readback`` if given, else
        ``candidate_floor`` for the exact-A happy path). On success
        transitions -> KEYCHAIN_COMMITTED -> FLOOR_STABLE and returns the
        new stable checkpoint id. On readback mismatch, quarantines the
        floor, withholds serving, and raises ``PipelineError``.
        """
        with self.db.unit_of_work() as uow:
            floor_row = uow.get_floor_state(self.workspace_id)
        if floor_row is None:
            raise PipelineError(
                "floor_not_bootstrapped",
                f"workspace {self.workspace_id} floor is not bootstrapped",
            )
        current_state = floor_protocol.FloorState(floor_row["attempt_state"])
        if current_state != floor_protocol.FloorState.FLOOR_STABLE:
            raise PipelineError(
                "floor_not_stable",
                f"cannot advance floor from state {current_state.value}",
            )

        old_generation = floor_row["stable_floor_generation"]
        old_checkpoint_id = floor_row["stable_checkpoint_id"]

        state = floor_protocol.advance(current_state, floor_protocol.FloorState.CHALLENGE_RESERVED)
        state = floor_protocol.advance(state, floor_protocol.FloorState.FLOOR_UPDATE_PREPARED)

        attempt_id = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.floor-attempt-id.v1",
                "workspace_id": self.workspace_id,
                "counter": counter,
                "nonce_digest": nonce_digest,
            })
        ).hexdigest()

        candidate = floor_protocol.build_floor_candidate(
            candidate_kind=floor_protocol.CandidateKind.VALIDATED_ADVANCE,
            expected_old_floor_hash=old_checkpoint_id,
            expected_keychain_generation=old_generation,
            candidate_floor=candidate_floor,
            attempt_id=attempt_id,
            counter=counter,
            nonce_digest=nonce_digest,
            disposition=floor_protocol.CandidateDisposition.ACCEPTED_PREPARED,
        )

        prepared_now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.upsert_floor_state(
                workspace_id=self.workspace_id,
                stable_floor_generation=old_generation,
                stable_checkpoint_id=old_checkpoint_id,
                attempt_state=state.value,
                updated_at=prepared_now,
            )
            uow.insert_floor_candidate(
                attempt_id=attempt_id,
                workspace_id=self.workspace_id,
                candidate_kind=candidate["candidate_kind"],
                expected_old_floor_digest=candidate["expected_old_floor_hash"],
                expected_keychain_generation=candidate["expected_keychain_generation"],
                candidate_floor_hex=canonical_bytes(candidate_floor).hex(),
                candidate_floor_digest=candidate["candidate_floor_hash"],
                challenge_sequence=counter,
                nonce_digest=nonce_digest,
                disposition_state=candidate["disposition"],
                created_at=prepared_now,
            )

        keychain_bytes = simulate_readback if simulate_readback is not None else candidate_floor

        try:
            floor_protocol.verify_cas_readback(candidate, keychain_bytes)
        except floor_protocol.FloorProtocolError as exc:
            quarantine_now = _utcnow()
            with self.db.unit_of_work() as uow:
                uow.upsert_floor_state(
                    workspace_id=self.workspace_id,
                    stable_floor_generation=old_generation,
                    stable_checkpoint_id=old_checkpoint_id,
                    attempt_state=floor_protocol.FloorState.QUARANTINED_FLOOR_CONFLICT.value,
                    updated_at=quarantine_now,
                )
                gate = floor_protocol.build_freshness_serve_gate(
                    workspace_id=self.workspace_id,
                    state="FRESH_CHALLENGE_REQUIRED",
                    stable_floor_generation=old_generation,
                    stable_checkpoint_id=old_checkpoint_id,
                    source_candidate_digest=candidate["candidate_floor_hash"],
                    reason="ATTESTATION_EXPIRED_BEFORE_STABILIZE",
                    updated_at=quarantine_now,
                )
                uow.upsert_freshness_serve_gate(
                    workspace_id=self.workspace_id,
                    gate_state=gate["state"],
                    stable_floor_generation=gate["stable_floor_generation"],
                    stable_checkpoint_id=gate["stable_checkpoint_id"],
                    source_candidate_digest=gate["source_candidate_digest"],
                    reason_state=gate["reason"],
                    updated_at=quarantine_now,
                )
            prev = self.db.event_chain_head()
            self.db.append_event(prev_digest=prev, kind="FLOOR_QUARANTINED", ref_digest=attempt_id)
            raise PipelineError("quarantined_floor_conflict", str(exc)) from exc

        committed_now = _utcnow()
        state = floor_protocol.advance(state, floor_protocol.FloorState.KEYCHAIN_COMMITTED)
        state = floor_protocol.advance(state, floor_protocol.FloorState.FLOOR_STABLE)
        new_generation = str(int(old_generation) + 1)
        new_checkpoint_id = candidate["candidate_floor_hash"]

        with self.db.unit_of_work() as uow:
            uow.upsert_floor_state(
                workspace_id=self.workspace_id,
                stable_floor_generation=new_generation,
                stable_checkpoint_id=new_checkpoint_id,
                attempt_state=state.value,
                updated_at=committed_now,
            )
            gate = floor_protocol.build_freshness_serve_gate(
                workspace_id=self.workspace_id,
                state="CLEAR",
                stable_floor_generation=new_generation,
                stable_checkpoint_id=new_checkpoint_id,
                source_candidate_digest=candidate["candidate_floor_hash"],
                reason="NONE",
                updated_at=committed_now,
            )
            uow.upsert_freshness_serve_gate(
                workspace_id=self.workspace_id,
                gate_state=gate["state"],
                stable_floor_generation=gate["stable_floor_generation"],
                stable_checkpoint_id=gate["stable_checkpoint_id"],
                source_candidate_digest=gate["source_candidate_digest"],
                reason_state=gate["reason"],
                updated_at=committed_now,
            )

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind="FLOOR_STABILIZED", ref_digest=new_checkpoint_id)
        return new_checkpoint_id

    def can_serve(self) -> bool:
        """True only if the freshness serve gate is CLEAR/NONE (R9-2/R10-3)."""
        with self.db.unit_of_work() as uow:
            gate_row = uow.get_freshness_serve_gate(self.workspace_id)
        if gate_row is None:
            return False
        return floor_protocol.serve_gate_allows_serving({
            "state": gate_row["gate_state"],
            "reason": gate_row["reason_state"],
        })

    # ------------------------------------------------------------------
    # Crash recovery (ADR-0027 §4)
    # ------------------------------------------------------------------

    def recover(
        self,
        *,
        mode: "RecoveryMode",
        registry: "BindingRegistry",
        proof_set: Mapping,
        trusted_signer_pub: "Ed25519PublicKey",
        local_floor_checkpoint_id: str,
        expected_namespace: str,
        expected_provider_handle: str,
        local_history_size: int | None = None,
        local_history_root_hex: str | None = None,
    ) -> "RecoveryDecision":
        """Gate 3 crash-recovery entry point (ADR-0027 §4). Runs the
        fail-closed DELTA_CONTINUITY / AUTHORITATIVE_SNAPSHOT recovery-proof
        mode against the local trusted binding registry and records the
        decision on the append-only event chain. A QUARANTINE_UNKNOWN
        decision never releases the floor, creates a survivor key, or serves
        plaintext; only a RECOVERED decision authorizes the caller to release
        visibility."""
        from wiki_spike.infrastructure import recovery

        decision = recovery.recover(
            mode=mode,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=trusted_signer_pub,
            local_floor_checkpoint_id=local_floor_checkpoint_id,
            expected_namespace=expected_namespace,
            expected_provider_handle=expected_provider_handle,
            local_history_size=local_history_size,
            local_history_root_hex=local_history_root_hex,
        )
        ref = "0" * 64
        checkpoint_sig = proof_set.get("checkpoint_signature") if isinstance(proof_set, Mapping) else None
        if isinstance(checkpoint_sig, Mapping) and checkpoint_sig.get("checkpoint_sha256"):
            ref = checkpoint_sig["checkpoint_sha256"]
        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind=f"RECOVERY_{decision.value}", ref_digest=ref)
        return decision


    # ------------------------------------------------------------------
    # Activation via readback / CAS
    # ------------------------------------------------------------------

    def activate_artifact(
        self,
        *,
        artifact_id: str,
        blob_id: str,
    ) -> None:
        """Activate a PREPARED/APPROVED artifact via an authenticated CAS
        readback: read the blob back (integrity-verified against blob_id by
        the CAS), confirm the readback envelope's workspace+revision identity
        binds to this exact artifact, then transition custody to ACTIVE. A
        missing blob, corrupt blob, unreadable envelope, or artifact<->blob
        identity mismatch fails closed (no ACTIVE election)."""
        with self.db.unit_of_work() as uow:
            gate_row = uow.get_freshness_serve_gate(self.workspace_id)
        if gate_row is None:
            # Lazy bootstrap: pre-existing callers that never bootstrapped
            # the floor still get a stable genesis + CLEAR gate.
            self.bootstrap_workspace()
        elif not floor_protocol.serve_gate_allows_serving({
            "state": gate_row["gate_state"],
            "reason": gate_row["reason_state"],
        }):
            raise PipelineError(
                "serve_withheld",
                f"freshness serve gate withholds serving for workspace {self.workspace_id}",
            )
        try:
            envelope_bytes = self.cas.get(blob_id)
        except EncryptedCASError as exc:
            raise PipelineError("blob_readback_failed", f"CAS readback of {blob_id} failed: {exc}") from exc
        try:
            envelope = json.loads(envelope_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PipelineError("envelope_unreadable", f"CAS blob {blob_id} is not a readable envelope") from exc

        now = _utcnow()
        with self.db.unit_of_work() as uow:
            art = uow.get_canonical_artifact(artifact_id)
            if art is None:
                raise PipelineError("artifact_not_found", f"artifact {artifact_id} not found")
            if (
                envelope.get("workspace_id") != self.workspace_id
                or envelope.get("revision_id") != art["revision_id"]
            ):
                raise PipelineError(
                    "activation_identity_mismatch",
                    f"CAS blob {blob_id} envelope identity does not bind artifact {artifact_id}",
                )
            ks = uow.get_key_state(artifact_id)
            if ks is None:
                raise PipelineError("key_state_not_found", f"no key_state for artifact {artifact_id}")
            if ks["custody_state"] not in ("PREPARED", "APPROVED"):
                raise PipelineError(
                    "invalid_activation_state",
                    f"cannot activate from custody_state={ks['custody_state']!r}",
                )
            uow.upsert_key_state(artifact_id=artifact_id, custody_state="ACTIVE", updated_at=now)

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind="ARTIFACT_ACTIVATED", ref_digest=artifact_id)

    # ------------------------------------------------------------------
    # Opaque projection
    # ------------------------------------------------------------------

    def project_expected_active(self, changeset_id: str) -> list[dict]:
        """Return the ExpectedActiveRevisionV1 sorted-unique projection
        for a persisted changeset."""
        with self.db.unit_of_work() as uow:
            cs = uow.get_accepted_changeset(changeset_id)
            if cs is None:
                raise PipelineError("changeset_not_found", f"changeset {changeset_id} not found")
            delta_rows = uow.list_state_deltas(changeset_id)

        deltas = [dict(dr) for dr in delta_rows]
        mapped = []
        for dr in deltas:
            mapped.append({
                "delta_version": "1",
                "delta_id": dr["delta_id"],
                "operation": dr["operation_kind"],
                "object_kind": dr["object_kind"],
                "object_id": dr["object_id"],
                "revision_id": dr.get("revision_id"),
                "expected_active_revision_id": dr.get("expected_active_revision_id"),
                "envelope_ref": dr.get("envelope_ref_id"),
                "assertion_id": dr.get("assertion_id"),
                "evidence_edge_id": dr.get("evidence_edge_id"),
                "evidence_fragment_ref": dr.get("evidence_fragment_ref_id"),
                "deletion_command_id": dr.get("deletion_command_id"),
                "scope_digest": dr.get("scope_digest"),
                "reason_code": dr.get("reason_state"),
            })

        from wiki_spike.infrastructure.changeset import project_expected_active_revisions
        return project_expected_active_revisions(mapped)
