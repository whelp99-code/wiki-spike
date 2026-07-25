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
import re
from pathlib import Path
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from wiki_spike.infrastructure import crypto, deletion, floor_protocol, identities, locators
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
from wiki_spike.infrastructure.keystore import CreateOnlyKeyStore, KeyStoreError
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, UnitOfWork
from wiki_spike.memory_core.contracts import canonical_bytes

GENERATION_DOMAIN = "wiki.generation.v1"


class PipelineError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_STATE_DELTA_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "schemas" / "encrypted-lifecycle" / "state-delta-v1.schema.json"
)
_STATE_DELTA_SCHEMA = json.loads(_STATE_DELTA_SCHEMA_PATH.read_text(encoding="utf-8"))

try:
    import jsonschema as _jsonschema  # type: ignore

    _HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover - exercised only when jsonschema absent
    _jsonschema = None  # type: ignore
    _HAVE_JSONSCHEMA = False

_OBJECT_KINDS = ("MEMORY_REVISION", "EVIDENCE_FRAGMENT", "ASSERTION", "EVIDENCE_EDGE")
_REASON_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _validate_state_delta(delta: Mapping) -> None:
    """Fail-closed guard: every persisted state delta MUST conform to the
    frozen StateDeltaV1 schema. When jsonschema is available (the normal path)
    the full schema is enforced (object_kind enum, reason_code pattern, hex64
    fields, delta_version/operation const/enum, all 14 keys, additionalProperties
    false); the jsonschema-absent fallback enforces at least the object_kind enum
    and reason_code pattern (the P1 defect class). A violation raises
    PipelineError before any durable delta write."""
    if _HAVE_JSONSCHEMA:
        try:
            _jsonschema.validate(instance=dict(delta), schema=_STATE_DELTA_SCHEMA)
        except _jsonschema.ValidationError as exc:  # type: ignore[attr-defined]
            raise PipelineError(
                "state_delta_schema_violation",
                f"state delta violates StateDeltaV1: {exc.message}",
            ) from exc
        return
    if delta.get("object_kind") not in _OBJECT_KINDS:
        raise PipelineError("state_delta_schema_violation", f"invalid object_kind {delta.get('object_kind')!r}")
    rc = delta.get("reason_code")
    if rc is not None and not _REASON_CODE_RE.fullmatch(str(rc)):
        raise PipelineError("state_delta_schema_violation", f"invalid reason_code {rc!r}")

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
    platform_keystore: "CreateOnlyKeyStore | None" = None
    recovery_keystore: "CreateOnlyKeyStore | None" = None

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
        art_dek = (
            os.urandom(32)
            if self.platform_keystore is not None and self.recovery_keystore is not None
            else self.dek
        )
        ciphertext_hex, tag_hex = crypto.aes_gcm_seal(art_dek, nonce_hex, normalized, aad)
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

        self._register_artifact_ark(artifact_semantic_digest_hex, art_dek)
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
        for delta in changeset["deltas"]:
            _validate_state_delta(delta)
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
        now: str | None = None,
        freshness_seconds: int = 300,
        skew_seconds: int = 60,
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
            now=now,
            freshness_seconds=freshness_seconds,
            skew_seconds=skew_seconds,
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
        if self.is_object_vetoed(artifact_id):
            raise PipelineError(
                "artifact_vetoed",
                f"artifact {artifact_id} is under an active deletion veto and cannot be activated/served",
            )
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
    # ------------------------------------------------------------------
    # Gate 4: Correction
    # ------------------------------------------------------------------
    #
    # NOTE on simplifying assumptions (Gate 4 minimal vertical slice):
    # The body-free ``lifecycle_db`` cache intentionally never persists
    # plaintext project/subject/consent-epoch metadata (see lifecycle_db.py
    # module docstring), so ``correct()`` cannot recover the *original*
    # ``project_id``/``source_instance_id``/``subject_ordinal``/
    # ``consent_epoch`` used by the initiating ``remember()`` call from the
    # prior artifact row alone. Rather than inventing/guessing those values,
    # this method:
    #   * fixes ``consent_epoch="1"`` for the corrected revision (a
    #     correction never changes consent epoch; only ``remember_new_consent``
    #     does that, deliberately, via an explicit epoch bump),
    #   * anchors the logical object identity to the prior artifact's own
    #     ``artifact_semantic_digest`` (deterministic, stable across a single
    #     correction) rather than the real stable-subject digest, and
    #   * hardcodes ``revision_number="2"`` (this Gate 4 slice supports ONE
    #     correction step from the original revision; a correction-of-a-
    #     correction would reuse "2"), and uses its own body-free
    #     ``wiki-memory-revision-correction-semantic-v1`` semantic schema
    #     (parallel to remember()'s own non-frozen schema naming) rather than
    #     reusing remember()'s schema (which needs project/subject fields this
    #     method never has).
    #
    # HONESTY/FIDELITY (tracked follow-up G4-CORRECTION-CONTINUITY): this does
    # NOT reproduce the frozen ``correction-r1-to-r2`` identity-vector digests
    # — only the literal ``revision_number="2"`` field coincides; the computed
    # logical_object_id/artifact_semantic_digest/revision_id differ because the
    # correction is anchored to the prior artifact digest, not the original
    # stable-subject/logical object, so the corrected revision lands under a
    # different logical_object_id than the frozen "same object, new revision"
    # contract. Full logical-object continuity + chained revision numbers
    # require persisting a body-free subject/object binding and are deferred to
    # the cross-revision "history of a memory" reconciliation (Gate 5). The
    # frozen identity vectors are validated only for their own HMAC
    # self-consistency; correct() is never driven against them, so this is a
    # design-fidelity gap, not a vector-conformance break. The RETRACT+ADD
    # atomicity and expected-active conflict guard below are exact.

    def correct(
        self,
        *,
        artifact_id: str,
        reviewer_handle: str,
        corrected_raw_body: bytes,
        note: str = "correction",
        expected_active_revision_id: str | None = None,
    ) -> dict:
        """CORRECT: retract the prior MEMORY_REVISION and add a new one whose
        ``parent_revision_id`` is the prior active revision. Atomic
        RETRACT+ADD via a single change set. Raises
        ``PipelineError("correction_conflict")`` if ``expected_active_revision_id``
        is supplied and does not match the prior active revision."""
        normalized = normalize_lifecycle_input_v1(corrected_raw_body)
        content_digest = input_content_digest(normalized)

        with self.db.unit_of_work() as uow:
            prior = uow.get_canonical_artifact(artifact_id)
            if prior is None:
                raise PipelineError("artifact_not_found", f"artifact {artifact_id} not found")
            if prior["artifact_kind"] != "MEMORY_REVISION":
                raise PipelineError(
                    "invalid_artifact_kind",
                    f"artifact {artifact_id} is not a MEMORY_REVISION (got {prior['artifact_kind']!r})",
                )
            prior_revision_id = prior["revision_id"]

        if expected_active_revision_id is not None and expected_active_revision_id != prior_revision_id:
            raise PipelineError(
                "correction_conflict",
                f"expected_active_revision_id {expected_active_revision_id!r} does not match "
                f"prior active revision {prior_revision_id!r}",
            )

        consent_epoch = "1"
        policy_context_digest = hashlib.sha256(b"default-policy-context").hexdigest()

        _, command_id = identities.command_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            command_kind="CORRECT",
            normalized_options={"note": note},
            input_content_digest=content_digest,
            policy_context_digest=policy_context_digest,
        )

        _, logical_object_id_hex = identities.logical_object_id(
            self.derived_keys,
            workspace_id=self.workspace_id,
            object_kind="MEMORY",
            consent_epoch=consent_epoch,
            subject_key_digest=artifact_id,
        )

        semantic_plaintext = {
            "schema": "wiki-memory-revision-correction-semantic-v1",
            "prior_artifact_id": artifact_id,
            "prior_revision_id": prior_revision_id,
            "consent_epoch": consent_epoch,
            "normalized_text": normalized.decode("utf-8"),
            "language": "und",
            "parent_revision_id": prior_revision_id,
        }
        _, artifact_semantic_digest_hex = identities.artifact_semantic_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            artifact_kind="MEMORY_REVISION",
            consent_epoch=consent_epoch,
            semantic_schema="wiki-memory-revision-correction-semantic-v1",
            semantic_plaintext=semantic_plaintext,
        )

        _, new_revision_id_hex = identities.revision_id(
            self.derived_keys,
            workspace_id=self.workspace_id,
            object_kind="MEMORY",
            logical_object_id_hex=logical_object_id_hex,
            consent_epoch=consent_epoch,
            revision_number="2",
            parent_revision_id=prior_revision_id,
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
            "revision_id": new_revision_id_hex,
            "semantic_schema_id": "wiki-memory-revision-correction-semantic-v1",
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

        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.insert_command(
                command_id=command_id,
                workspace_id=self.workspace_id,
                command_kind="CORRECT",
                input_digest=content_digest,
                command_state="ACCEPTED",
                created_at=now,
            )
            uow.insert_canonical_artifact(
                artifact_id=artifact_semantic_digest_hex,
                workspace_id=self.workspace_id,
                artifact_kind="MEMORY_REVISION",
                revision_id=new_revision_id_hex,
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

        retract_delta = build_state_delta(
            operation="RETRACT",
            object_kind="MEMORY_REVISION",
            object_id=artifact_id,
            revision_id=prior_revision_id,
            expected_active_revision_id=prior_revision_id,
        )
        add_delta = build_state_delta(
            operation="ADD",
            object_kind="MEMORY_REVISION",
            object_id=artifact_semantic_digest_hex,
            revision_id=new_revision_id_hex,
            expected_active_revision_id=new_revision_id_hex,
            envelope_ref=artifact_semantic_digest_hex,
        )
        changeset = build_encrypted_accepted_changeset(
            workspace_id=self.workspace_id,
            parent_generation_id=None,
            command_ids=[command_id],
            deltas=[retract_delta, add_delta],
        )
        self.persist_changeset(changeset)

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind="CORRECT_ACCEPTED", ref_digest=command_id)

        return {
            "command_id": command_id,
            "revision_id": new_revision_id_hex,
            "artifact_semantic_digest": artifact_semantic_digest_hex,
            "changeset_id": changeset["changeset_id"],
            "blob_id": blob_id,
        }

    # ------------------------------------------------------------------
    # Gate 4: Evidence fragments / edges
    # ------------------------------------------------------------------

    def add_evidence_fragment(
        self,
        *,
        project_id: str,
        source_content_digest: str,
        normalized_source_body: bytes,
        locator: Mapping,
        consent_epoch: str = "1",
    ) -> dict:
        """Validate ``locator``, extract its excerpt, seal a body-free
        EvidenceFragmentSemanticV1 identity + envelope, and persist a
        canonical EVIDENCE_FRAGMENT artifact."""
        locators.validate_locator(locator)
        excerpt = locators.extract_excerpt(locator, normalized_source_body)

        locator_kind = locator["locator_kind"]
        locator_start = locator.get("locator_start")
        locator_end = locator.get("locator_end")
        locator_text = locator.get("locator_text")

        fragment_semantic_plaintext = {
            "schema": "wiki-evidence-fragment-semantic-v1",
            "project_id": project_id,
            "source_content_digest": source_content_digest,
            "locator_kind": locator_kind,
            "locator_start": locator_start,
            "locator_end": locator_end,
            "locator_text": locator_text,
            "normalized_excerpt": excerpt,
            "consent_epoch": consent_epoch,
        }
        _, fragment_semantic_digest_hex = identities.artifact_semantic_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            artifact_kind="EVIDENCE_FRAGMENT",
            consent_epoch=consent_epoch,
            semantic_schema="wiki-evidence-fragment-semantic-v1",
            semantic_plaintext=fragment_semantic_plaintext,
        )
        _, locator_digest_hex = identities.locator_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            project_id=project_id,
            source_content_digest=source_content_digest,
            locator_kind=locator_kind,
            locator_start=locator_start,
            locator_end=locator_end,
            locator_text=locator_text,
        )

        nonce_hex = os.urandom(12).hex()
        aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(fragment_semantic_digest_hex)
        plaintext_bytes = excerpt.encode("utf-8")
        ciphertext_hex, tag_hex = crypto.aes_gcm_seal(self.dek, nonce_hex, plaintext_bytes, aad)
        now = _utcnow()
        envelope = {
            "schema": "wiki-envelope-v1",
            "version": "1",
            "algorithm": "AES-256-GCM",
            "workspace_id": self.workspace_id,
            "logical_object_id": fragment_semantic_digest_hex,
            "revision_id": fragment_semantic_digest_hex,
            "semantic_schema_id": "wiki-evidence-fragment-semantic-v1",
            "nonce": nonce_hex,
            "aad_digest": hashlib.sha256(aad).hexdigest(),
            "ciphertext": ciphertext_hex,
            "tag": tag_hex,
            "metadata": {
                "consent_epoch": consent_epoch,
                "key_version": "1",
                "content_length_bytes": str(len(plaintext_bytes)),
                "created_at": now,
            },
        }
        envelope_bytes = canonical_bytes(envelope)
        blob_id = self.cas.put(envelope_bytes)

        with self.db.unit_of_work() as uow:
            uow.insert_canonical_artifact(
                artifact_id=fragment_semantic_digest_hex,
                workspace_id=self.workspace_id,
                artifact_kind="EVIDENCE_FRAGMENT",
                revision_id=fragment_semantic_digest_hex,
                artifact_state="PREPARED",
                created_at=now,
            )
            uow.upsert_key_state(
                artifact_id=fragment_semantic_digest_hex,
                custody_state="PREPARED",
                updated_at=now,
            )

        prev = self.db.event_chain_head()
        self.db.append_event(
            prev_digest=prev, kind="EVIDENCE_FRAGMENT_ADDED", ref_digest=fragment_semantic_digest_hex
        )

        return {
            "fragment_semantic_digest": fragment_semantic_digest_hex,
            "locator_digest": locator_digest_hex,
            "blob_id": blob_id,
            "normalized_excerpt": excerpt,
        }

    def add_evidence_edge(
        self,
        *,
        project_id: str,
        assertion_semantic_digest: str,
        fragment_semantic_digest: str,
        locator_digest: str,
        support_kind: str,
        consent_epoch: str = "1",
    ) -> dict:
        """Persist an EvidenceEdgeSemanticV1 EVIDENCE_EDGE artifact linking
        an assertion to a supporting/contradicting evidence fragment."""
        if support_kind not in ("SUPPORTS", "CONTRADICTS"):
            raise PipelineError(
                "invalid_support_kind",
                f"support_kind must be SUPPORTS or CONTRADICTS, got {support_kind!r}",
            )

        edge_semantic_plaintext = {
            "schema": "wiki-evidence-edge-semantic-v1",
            "project_id": project_id,
            "assertion_semantic_digest": assertion_semantic_digest,
            "fragment_semantic_digest": fragment_semantic_digest,
            "locator_digest": locator_digest,
            "support_kind": support_kind,
            "consent_epoch": consent_epoch,
        }
        _, edge_semantic_digest_hex = identities.artifact_semantic_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            artifact_kind="EVIDENCE_EDGE",
            consent_epoch=consent_epoch,
            semantic_schema="wiki-evidence-edge-semantic-v1",
            semantic_plaintext=edge_semantic_plaintext,
        )

        now = _utcnow()
        with self.db.unit_of_work() as uow:
            uow.insert_canonical_artifact(
                artifact_id=edge_semantic_digest_hex,
                workspace_id=self.workspace_id,
                artifact_kind="EVIDENCE_EDGE",
                revision_id=edge_semantic_digest_hex,
                artifact_state="PREPARED",
                created_at=now,
            )
            uow.upsert_key_state(
                artifact_id=edge_semantic_digest_hex,
                custody_state="PREPARED",
                updated_at=now,
            )

        prev = self.db.event_chain_head()
        self.db.append_event(
            prev_digest=prev, kind="EVIDENCE_EDGE_ADDED", ref_digest=edge_semantic_digest_hex
        )

        return {"edge_semantic_digest": edge_semantic_digest_hex}

    # ------------------------------------------------------------------
    # Gate 4: Tombstone / FORGET
    # ------------------------------------------------------------------

    def tombstone_object(
        self,
        *,
        object_id: str,
        deletion_command_id: str,
        reason_code: str = "forget",
    ) -> dict:
        """Persist a single-delta TOMBSTONE change set for ``object_id``."""
        scope_digest = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.tombstone-scope.v1",
                "workspace_id": self.workspace_id,
                "object_id": object_id,
                "deletion_command_id": deletion_command_id,
            })
        ).hexdigest()
        delta = build_state_delta(
            operation="TOMBSTONE",
            object_kind="MEMORY_REVISION",
            object_id=object_id,
            deletion_command_id=deletion_command_id,
            scope_digest=scope_digest,
            reason_code=reason_code,
        )
        changeset = build_encrypted_accepted_changeset(
            workspace_id=self.workspace_id,
            parent_generation_id=None,
            command_ids=[deletion_command_id],
            deltas=[delta],
        )
        self.persist_changeset(changeset)

        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind="OBJECT_TOMBSTONED", ref_digest=object_id)

        ears = self.project_expected_active(changeset["changeset_id"])
        matching = [
            ear for ear in ears
            if ear["object_kind"] == "MEMORY_REVISION" and ear["object_id"] == object_id
        ]
        if len(matching) != 1 or matching[0]["expected_active_revision_id"] is not None:
            raise PipelineError(
                "tombstone_projection_mismatch",
                f"projection for tombstoned object {object_id} does not reflect the "
                f"TOMBSTONE discriminator (no active revision expected)",
            )

        return {"changeset_id": changeset["changeset_id"], "delta_id": delta["delta_id"]}

    # ------------------------------------------------------------------
    # Gate 4: New consent (post-FORGET re-remember)
    # ------------------------------------------------------------------

    def remember_new_consent(
        self,
        *,
        prior_object_id: str,
        prior_consent_epoch: str,
        consent_epoch: str,
        raw_body: bytes,
        project_id: str,
        source_instance_id: str = "inline",
        subject_ordinal: str = "0",
        platform_absence_receipt: "object | None" = None,
        recovery_absence_receipt: "object | None" = None,
        sensitivity: str = "INTERNAL",
        source_kind: str = "INLINE_TEXT",
        input_format: str = "PLAIN_TEXT",
        extractor_profile: str = "LOCAL_RULES_V1",
        policy_context_digest: str | None = None,
    ) -> RememberResult:
        """Fail-closed re-REMEMBER under a strictly greater consent epoch
        after a prior object's FORGET has fully completed. Every precondition
        below is verified BEFORE any new command/artifact/key_state row is
        written; a failure leaves no new state. Never reads/unwraps the
        prior object's ciphertext -- only body-free tombstone/identity
        metadata (the deletion_state phase and the two custody absence
        receipts) and the caller-supplied fresh ``raw_body``.

        DEFERRED (tracked follow-up G4-NEW-CONSENT-SUBJECT-BINDING, to Gate 5
        dual-ARK-destroy where custody/subject binding hardens): two plan
        line-138 preconditions are intentionally under-enforced here because the
        body-free cache persists no subject/custody binding to check against —
        (a) the "same project/stable-subject as the prior object" precondition
        is NOT verified (project/subject params are caller-supplied and a fresh
        stable_subject_ref is derived without comparing to the deleted object's
        subject); (b) the two absence receipts are validated for PRESENCE only,
        not for distinct custody roles, ark_handle binding to prior_object_id,
        or receipt_digest validity. The safety-critical guarantees below are
        fully enforced: prior deletion COMPLETE, strictly-greater consent epoch,
        non-empty body, zero-state-on-any-failure, and no prior-ciphertext read.
        """
        row = self.db.con.execute(
            "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
            "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
            (prior_object_id,),
        ).fetchone()
        if row is None or row[0] != "COMPLETE":
            raise PipelineError(
                "new_consent_prior_deletion_incomplete",
                f"prior object {prior_object_id} has no COMPLETE deletion_state "
                f"(fail-closed: refusing to mint new consent)",
            )

        if platform_absence_receipt is None or recovery_absence_receipt is None:
            raise PipelineError(
                "new_consent_missing_absence_receipts",
                "both platform and recovery custody absence receipts are required "
                "for new consent (fail-closed)",
            )

        if int(consent_epoch) <= int(prior_consent_epoch):
            raise PipelineError(
                "new_consent_epoch_not_greater",
                f"consent_epoch {consent_epoch!r} must be strictly greater than "
                f"prior_consent_epoch {prior_consent_epoch!r}",
            )

        if not raw_body:
            raise PipelineError("new_consent_body_required", "raw_body must be non-empty")

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
            new_consent="YES",
            consent_reason="NEW_EXPLICIT_CONSENT",
            prior_object_id=prior_object_id,
            prior_consent_epoch=prior_consent_epoch,
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
            kind="NEW_CONSENT_ACCEPTED",
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

    # ------------------------------------------------------------------
    # Gate 5: dual-custody ARK + FORGET deletion workflow
    # ------------------------------------------------------------------

    def _register_artifact_ark(self, artifact_digest_hex: str, dek: bytes) -> None:
        """Owner decisions 4/5: an independent per-artifact-revision ARK held in
        create-only DUAL custody (platform + recovery keystores). FORGET later
        destroys BOTH copies (crypto-shred) so the artifact's random DEK becomes
        unrecoverable. No-op for Gate 3/4 single-DEK callers (no keystores)."""
        if self.platform_keystore is None or self.recovery_keystore is None:
            return
        self.platform_keystore.create_only(self.workspace_id, artifact_digest_hex, dek.hex(), artifact_digest_hex)
        self.recovery_keystore.create_only(self.workspace_id, artifact_digest_hex, dek.hex(), artifact_digest_hex)

    def _set_deletion_phase(self, deletion_id: str, phase: "deletion.DeletionPhase", now: str) -> None:
        with self.db.unit_of_work() as uow:
            uow.update_deletion_phase(deletion_id=deletion_id, phase_state=phase.value, updated_at=now)

    def _append_deletion_event(self, kind: str, ref: str) -> None:
        prev = self.db.event_chain_head()
        self.db.append_event(prev_digest=prev, kind=kind, ref_digest=ref)

    def is_object_vetoed(self, artifact_id: str) -> bool:
        """True once a deletion_state row exists for the artifact in ANY phase:
        current deletion truth vetoes history, cache, restore, and in-flight
        reads (deletion.is_vetoed)."""
        row = self.db.con.execute(
            "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
            "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
            (artifact_id,),
        ).fetchone()
        return row is not None and deletion.is_vetoed(row[0])

    def forget(
        self,
        *,
        artifact_id: str,
        blob_id: str,
        selector_kind: str = "MEMORY",
        selector_value: str | None = None,
        revision_id: str | None = None,
        reason_code: str = "forget",
        wait_seconds: str = "0",
    ) -> dict:
        """FORGET: immediate live-API veto through dual-custody crypto-shred.

        Drives the forward-only deletion phase machine REQUESTED ->
        API_VETO_ACTIVE -> TOMBSTONE_ACTIVE -> CHECKPOINT_COMMITTED ->
        REVOCATION_KEYS_DESTROYED -> CRYPTO_SHRED_COMPLETE -> PURGE_PENDING ->
        COMPLETE. The veto is live from REQUESTED; cryptographic undecryptability
        is claimed only once BOTH custody copies of the artifact's ARK are
        destroyed. Fail-closed: if either ARK destroy fails the deletion stops
        before CRYPTO_SHRED_COMPLETE (API denial holds, no false shred claim)."""
        if self.platform_keystore is None or self.recovery_keystore is None:
            raise PipelineError(
                "forget_requires_dual_custody",
                "FORGET requires platform + recovery keystores for dual ARK destroy",
            )
        if not (0 <= int(wait_seconds) <= 300):
            raise PipelineError("forget_wait_out_of_range", "wait_seconds must be 0..300")

        if selector_value is None:
            selector_value = artifact_id
        if self.is_object_vetoed(artifact_id):
            raise PipelineError(
                "already_under_deletion",
                f"artifact {artifact_id} already has an active deletion_state (idempotent FORGET rejected)",
            )
        empty_digest = hashlib.sha256(b"").hexdigest()
        forget_opts = {
            "schema": "wiki-forget-options-v1",
            "command_kind": "FORGET",
            "selector_kind": selector_kind,
            "selector_value": selector_value,
            "revision_id": revision_id,
            "reason_code": reason_code,
            "wait_seconds": wait_seconds,
        }
        policy_context_digest = hashlib.sha256(b"default-policy-context").hexdigest()
        _, command_id = identities.command_digest(
            self.derived_keys,
            workspace_id=self.workspace_id,
            command_kind="FORGET",
            normalized_options=forget_opts,
            input_content_digest=empty_digest,
            policy_context_digest=policy_context_digest,
        )
        now = _utcnow()
        phase = deletion.DeletionPhase.REQUESTED
        with self.db.unit_of_work() as uow:
            uow.insert_command(
                command_id=command_id,
                workspace_id=self.workspace_id,
                command_kind="FORGET",
                input_digest=empty_digest,
                command_state="ACCEPTED",
                created_at=now,
            )
            uow.insert_deletion_state(
                deletion_id=command_id,
                artifact_id=artifact_id,
                phase_state=phase.value,
                updated_at=now,
            )
        self._append_deletion_event("FORGET_REQUESTED", command_id)

        # Immediate live-API veto.
        phase = deletion.advance(phase, deletion.DeletionPhase.API_VETO_ACTIVE)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_API_VETO_ACTIVE", artifact_id)

        # Tombstone the CAS blob (retained bytes, not servable).
        phase = deletion.advance(phase, deletion.DeletionPhase.TOMBSTONE_ACTIVE)
        self.cas.tombstone(blob_id, reason=reason_code)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_TOMBSTONED", artifact_id)

        # Body-free deletion checkpoint.
        deletion_checkpoint_id = hashlib.sha256(
            canonical_bytes({
                "domain": "wiki.deletion-checkpoint.v1",
                "workspace_id": self.workspace_id,
                "deletion_command_id": command_id,
                "artifact_id": artifact_id,
                "blob_id": blob_id,
            })
        ).hexdigest()
        phase = deletion.advance(phase, deletion.DeletionPhase.CHECKPOINT_COMMITTED)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_CHECKPOINT_COMMITTED", deletion_checkpoint_id)

        # Dual ARK destroy (platform + recovery), fail-closed.
        try:
            platform_receipt = self.platform_keystore.destroy(self.workspace_id, artifact_id)
            recovery_receipt = self.recovery_keystore.destroy(self.workspace_id, artifact_id)
        except KeyStoreError as exc:
            raise PipelineError(
                "forget_ark_destroy_failed",
                f"dual ARK destroy failed for {artifact_id}; deletion held at CHECKPOINT_COMMITTED: {exc}",
            ) from exc
        phase = deletion.advance(phase, deletion.DeletionPhase.REVOCATION_KEYS_DESTROYED)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_ARK_DESTROYED", artifact_id)

        # Both wraps gone -> cryptographic undecryptability.
        phase = deletion.advance(phase, deletion.DeletionPhase.CRYPTO_SHRED_COMPLETE)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_CRYPTO_SHRED_COMPLETE", artifact_id)

        phase = deletion.advance(phase, deletion.DeletionPhase.PURGE_PENDING)
        self._set_deletion_phase(command_id, phase, now)
        phase = deletion.advance(phase, deletion.DeletionPhase.COMPLETE)
        self._set_deletion_phase(command_id, phase, now)
        self._append_deletion_event("DELETION_COMPLETE", command_id)

        return {
            "deletion_command_id": command_id,
            "phase": phase.value,
            "deletion_checkpoint_id": deletion_checkpoint_id,
            "platform_absence_receipt": platform_receipt.to_mapping(),
            "recovery_absence_receipt": recovery_receipt.to_mapping(),
        }

    def restore(
        self,
        *,
        artifact_id: str,
        mode: "RecoveryMode",
        registry: "BindingRegistry",
        proof_set: Mapping,
        trusted_signer_pub: "Ed25519PublicKey",
        local_floor_checkpoint_id: str,
        expected_namespace: str,
        expected_provider_handle: str,
        now: str,
        local_history_size: int | None = None,
        local_history_root_hex: str | None = None,
    ) -> dict:
        """Selective restore (ADR-0027): re-enable visibility of an artifact ONLY
        after a valid recovery proof AND an immutable/stable floor + binding
        proofs, and ONLY if the artifact is not under a current deletion veto.

        Fail-closed gates run BEFORE any serve/key work: (1) a forgotten
        (deletion_state) artifact is never restorable — the veto dominates
        rollback; (2) the recovery proof set must RECOVER (both modes;
        replay/expiry/fork/omission/stale-floor/invalid-signer/outage/incomplete-
        binding all fail closed to QUARANTINE_UNKNOWN via ``recover``, injecting
        the trusted clock ``now``); (3) the freshness serve gate must be CLEAR
        (floor stable) before visibility. This never recreates a destroyed ARK,
        lowers the floor/counter, or serves plaintext under an incomplete proof."""
        from wiki_spike.infrastructure.recovery import RecoveryDecision

        # 1. Current-veto gate: a forgotten artifact is never restorable.
        if self.is_object_vetoed(artifact_id):
            raise PipelineError(
                "restore_vetoed",
                f"artifact {artifact_id} is under an active deletion veto and is not restorable",
            )

        # 2. Recovery-proof gate (both modes; fail-closed to QUARANTINE_UNKNOWN).
        decision = self.recover(
            mode=mode,
            registry=registry,
            proof_set=proof_set,
            trusted_signer_pub=trusted_signer_pub,
            local_floor_checkpoint_id=local_floor_checkpoint_id,
            expected_namespace=expected_namespace,
            expected_provider_handle=expected_provider_handle,
            now=now,
            local_history_size=local_history_size,
            local_history_root_hex=local_history_root_hex,
        )
        if decision is not RecoveryDecision.RECOVERED:
            raise PipelineError(
                "restore_quarantined",
                f"recovery proof did not RECOVER ({decision.value}); no restore before visibility",
            )

        # 3. Immutable/stable floor + CLEAR freshness serve gate before visibility.
        if not self.can_serve():
            raise PipelineError(
                "restore_serve_withheld",
                "floor/freshness serve gate is not CLEAR; restore withheld until the floor stabilizes",
            )

        # 4. Release visibility (never recreates a destroyed ARK).
        now_ts = _utcnow()
        with self.db.unit_of_work() as uow:
            art = uow.get_canonical_artifact(artifact_id)
            if art is None:
                raise PipelineError("restore_artifact_not_found", f"artifact {artifact_id} not found")
            uow.upsert_key_state(artifact_id=artifact_id, custody_state="ACTIVE", updated_at=now_ts)
        self._append_deletion_event("ARTIFACT_RESTORED", artifact_id)
        return {"artifact_id": artifact_id, "decision": decision.value, "restored": True}
