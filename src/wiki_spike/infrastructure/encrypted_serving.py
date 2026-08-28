"""Shared fail-closed read path for encrypted lifecycle artifacts.

The desktop façade and read-only MCP must make the same visibility decision.
This module therefore owns the single checked-snapshot gate, CAS integrity read,
per-artifact key resolution, AES-GCM authentication, and optional response bound.
It creates no alternate memory state and persists nothing.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from wiki_spike.infrastructure import crypto, deletion, floor_protocol
from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedContentStore,
    IntegrityError as CasIntegrityError,
    NotFound as CasNotFound,
    Tombstoned as CasTombstoned,
)
from wiki_spike.infrastructure.keystore import CreateOnlyKeyStore, KeyStoreError
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, ServeSnapshotResult


class EncryptedServingError(RuntimeError):
    """A checked encrypted read was denied or could not be authenticated."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class DecryptedArtifact:
    artifact_id: str
    content: str
    metadata: dict[str, Any]
    truncated: bool


class EncryptedArtifactReader:
    """Read ACTIVE encrypted artifacts through one fail-closed authority path."""

    def __init__(
        self,
        *,
        workspace_id: str,
        db: LifecycleDatabase,
        cas: EncryptedContentStore,
        fallback_dek: bytes,
        platform_keystore: CreateOnlyKeyStore | None = None,
    ) -> None:
        self._workspace_id = workspace_id
        self._db = db
        self._cas = cas
        self._fallback_dek = fallback_dek
        self._platform_keystore = platform_keystore

    def read(
        self,
        *,
        artifact_id: str,
        blob_id: str,
        max_chars: int | None = None,
        snapshot: ServeSnapshotResult | None = None,
    ) -> DecryptedArtifact:
        if snapshot is None:
            snapshot = self._db.checked_serve_snapshot_read(
                artifact_id,
                self._workspace_id,
            )
        if snapshot.artifact_state is None:
            raise EncryptedServingError(
                "artifact_not_found",
                f"artifact {artifact_id} not found",
            )
        if snapshot.custody_state != "ACTIVE":
            raise EncryptedServingError(
                "artifact_not_active",
                f"artifact {artifact_id} is not the active revision",
            )
        if snapshot.deletion_phase_state is not None and deletion.is_vetoed(
            snapshot.deletion_phase_state
        ):
            raise EncryptedServingError(
                "artifact_vetoed",
                f"artifact {artifact_id} is under deletion veto",
            )
        if snapshot.serve_gate_state is None or not floor_protocol.serve_gate_allows_serving(
            {
                "state": snapshot.serve_gate_state,
                "reason": snapshot.serve_gate_reason,
            }
        ):
            raise EncryptedServingError(
                "serve_withheld",
                f"freshness serve gate withholds serving for workspace {self._workspace_id}",
            )

        try:
            envelope_bytes = self._cas.get(blob_id)
        except CasNotFound as exc:
            raise EncryptedServingError(
                "blob_not_found",
                f"CAS blob {blob_id} not found",
            ) from exc
        except CasTombstoned as exc:
            raise EncryptedServingError(
                "blob_tombstoned",
                f"CAS blob {blob_id} is tombstoned",
            ) from exc
        except CasIntegrityError as exc:
            raise EncryptedServingError(
                "integrity_violation",
                f"CAS integrity verification failed for {blob_id}",
            ) from exc

        try:
            envelope = json.loads(envelope_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EncryptedServingError(
                "envelope_unreadable",
                f"CAS blob {blob_id} is not valid JSON",
            ) from exc
        if not isinstance(envelope, dict):
            raise EncryptedServingError(
                "envelope_unreadable",
                f"CAS blob {blob_id} is not a JSON object",
            )
        if envelope.get("workspace_id") != self._workspace_id:
            raise EncryptedServingError(
                "workspace_mismatch",
                f"CAS blob {blob_id} belongs to another workspace",
            )

        nonce = envelope.get("nonce", "")
        ciphertext = envelope.get("ciphertext", "")
        tag = envelope.get("tag", "")
        metadata = envelope.get("metadata", {})
        if not isinstance(metadata, dict):
            raise EncryptedServingError(
                "envelope_unreadable",
                f"CAS blob {blob_id} metadata is not an object",
            )

        aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(artifact_id)
        if envelope.get("aad_digest") != hashlib.sha256(aad).hexdigest():
            raise EncryptedServingError(
                "envelope_identity_mismatch",
                f"CAS blob {blob_id} does not bind artifact {artifact_id}",
            )

        if self._platform_keystore is not None:
            try:
                dek = self._platform_keystore.get_ark_dek(
                    self._workspace_id,
                    artifact_id,
                )
            except KeyStoreError as exc:
                raise EncryptedServingError(
                    "dek_unavailable",
                    f"artifact key is unavailable for {artifact_id}: {exc}",
                ) from exc
        else:
            dek = self._fallback_dek

        try:
            plaintext = crypto.aes_gcm_open(
                dek,
                str(nonce),
                str(ciphertext),
                str(tag),
                aad,
            ).decode("utf-8")
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise EncryptedServingError(
                "decryption_failed",
                f"authenticated decryption failed for artifact {artifact_id}",
            ) from exc

        truncated = False
        if max_chars is not None and len(plaintext) > max_chars:
            plaintext = plaintext[:max_chars]
            truncated = True
        return DecryptedArtifact(
            artifact_id=artifact_id,
            content=plaintext,
            metadata=dict(metadata),
            truncated=truncated,
        )
