"""Encrypted lifecycle deterministic vertical pipeline (Gate 3).

Orchestrates the full REMEMBER → APPROVE/REJECT → change set → signed
generation / binding checkpoint → activation via readback/CAS → opaque
projection pipeline per the Stage 8 Gate 3 specification.

Architecture-boundary contract: application layer; may import
``wiki_spike.memory_core`` and ``wiki_spike.infrastructure`` only.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Mapping, Sequence

from wiki_spike.infrastructure import crypto, identities
from wiki_spike.infrastructure.changeset import (
    build_encrypted_accepted_changeset,
    build_state_delta,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
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
            canonical_bytes({"artifact_id": artifact_id, "reviewer_handle": reviewer_handle, "review_state": review_state, "ts": _utcnow()})
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
            canonical_bytes({"changeset_id": changeset_id, "workspace_id": self.workspace_id, "ts": _utcnow()})
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
                )

            checkpoint, checkpoint_sig = binding_registry.checkpoint(
                signing_key=signing_key,
                signer_key_id=signer_key_id,
                generation_id=generation_id,
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
    # Activation via readback / CAS
    # ------------------------------------------------------------------

    def activate_artifact(
        self,
        *,
        artifact_id: str,
        blob_id: str,
    ) -> None:
        """Activate a PREPARED artifact: verify CAS blob exists, transition
        key state to ACTIVE, and append an activation event."""
        if not self.cas.exists(blob_id):
            raise PipelineError("blob_not_found", f"CAS blob {blob_id} not found")

        now = _utcnow()
        with self.db.unit_of_work() as uow:
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
