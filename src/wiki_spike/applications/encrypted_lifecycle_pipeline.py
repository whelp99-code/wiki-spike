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
