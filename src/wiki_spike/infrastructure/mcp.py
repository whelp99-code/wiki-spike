"""Scoped authenticated MCP tools for the Encrypted Single-Memory Lifecycle.

Gate 7: two read-only tools (`memory_recall`, `memory_source`), 64 KiB
response bound, shared checked-snapshot primitive, no write path, no
caller trust beyond authentication.

Architecture-boundary contract: infrastructure layer; may import only
``wiki_spike.memory_core`` and stdlib/crypto/``wiki_spike.infrastructure.*``.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any, Mapping

from wiki_spike.infrastructure import crypto, deletion, floor_protocol
from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedContentStore,
    NotFound as CasNotFound,
    Tombstoned as CasTombstoned,
    IntegrityError as CasIntegrityError,
)
from wiki_spike.infrastructure.keystore import CreateOnlyKeyStore, KeyStoreError
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.contracts import canonical_bytes

MCP_DOMAIN = "wiki.mcp.v1"
MAX_RESPONSE_SIZE = 65536  # 64 KiB


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class McpError(Exception):
    """Base MCP error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class McpAuthError(McpError):
    """Authentication/authorisation error."""


class McpToolError(McpError):
    """Tool execution error."""


class McpResponseTooLarge(McpError):
    """Response exceeds maximum allowed size."""


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class McpRequest:
    tool: str
    params: dict
    nonce: str
    workspace_id: str


@dataclass(frozen=True)
class McpResponse:
    tool: str
    result: dict
    error: str | None


# ---------------------------------------------------------------------------
# In-memory nonce replay guard
# ---------------------------------------------------------------------------


class McpNonceGuard:
    """In-memory nonce replay protection."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def consume(self, nonce: str) -> None:
        """Mark *nonce* as consumed, raising ``McpAuthError`` on replay."""
        if nonce in self._consumed:
            raise McpAuthError(
                "nonce_replay",
                f"nonce {nonce!r} has already been consumed",
            )
        self._consumed.add(nonce)


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------


class McpServer:
    """Scoped MCP server for encrypted-memory read tools.

    Two authentication modes:

    * **Direct-key mode** (testing): *public_key* is ``None``; authentication
      is bypassed.
    * **Authenticated mode**: every request carries an Ed25519 signature over
      ``domain_prefix(MCP_DOMAIN) + canonical_bytes(request)``.
    """

    def __init__(
        self,
        *,
        workspace_id: str,
        derived_keys: dict[str, bytes],
        db: LifecycleDatabase,
        cas: EncryptedContentStore,
        dek: bytes,
        platform_keystore: CreateOnlyKeyStore | None = None,
        recovery_keystore: CreateOnlyKeyStore | None = None,
        nonce_guard: McpNonceGuard | None = None,
    ) -> None:
        self._workspace_id = workspace_id
        self._derived_keys = derived_keys
        self._db = db
        self._cas = cas
        self._dek = dek
        self._platform_keystore = platform_keystore
        self._recovery_keystore = recovery_keystore
        self._nonce_guard = nonce_guard or McpNonceGuard()

    # -- public API ------------------------------------------------------- #

    def handle_request(
        self,
        request_json: str,
        signature_hex: str | None = None,
        public_key=None,
    ) -> str:
        """Handle one MCP request and return the JSON response string.

        Parameters
        ----------
        request_json:
            JSON-encoded ``McpRequest``.
        signature_hex:
            Hex-encoded Ed25519 signature (``None`` for unauthenticated).
        public_key:
            ``Ed25519PublicKey`` instance (``None`` for unauthenticated).
        """
        try:
            return self._handle(request_json, signature_hex, public_key)
        except McpError as exc:
            return self._serialize_response(
                McpResponse(tool="", result={}, error=exc.code)
            )
        except Exception as exc:
            return self._serialize_response(
                McpResponse(tool="", result={}, error=f"internal_error: {exc}")
            )

    def get_nonce_guard(self) -> McpNonceGuard:
        """Expose the nonce guard for test introspection."""
        return self._nonce_guard

    # -- internal --------------------------------------------------------- #

    def _handle(
        self,
        request_json: str,
        signature_hex: str | None,
        public_key,
    ) -> str:
        parsed_raw: Any = json.loads(request_json)
        if not isinstance(parsed_raw, dict):
            raise McpAuthError("bad_request", "request must be a JSON object")

        # Authenticate when a public key is supplied.
        if public_key is not None:
            if not signature_hex:
                raise McpAuthError(
                    "signature_missing",
                    "authenticated mode requires a signature",
                )
            self._verify_signature(request_json, signature_hex, public_key)

        request = McpRequest(
            tool=parsed_raw.get("tool", ""),
            params=parsed_raw.get("params", {}),
            nonce=parsed_raw.get("nonce", ""),
            workspace_id=parsed_raw.get("workspace_id", ""),
        )

        # Nonce replay guard (always applied when nonce is non-empty).
        if request.nonce:
            self._nonce_guard.consume(request.nonce)

        if request.workspace_id != self._workspace_id:
            raise McpToolError(
                "workspace_mismatch",
                f"request workspace {request.workspace_id!r} != server workspace {self._workspace_id!r}",
            )

        if request.tool == "memory_recall":
            result = self._memory_recall(request.params)
        elif request.tool == "memory_source":
            result = self._memory_source(request.params)
        else:
            raise McpToolError("unknown_tool", f"unknown tool: {request.tool!r}")

        return self._serialize_response(
            McpResponse(tool=request.tool, result=result, error=None)
        )

    def _verify_signature(
        self, request_json: str, signature_hex: str, public_key
    ) -> None:
        """Verify Ed25519 signature over the canonicalised request payload."""
        try:
            parsed: Any = json.loads(request_json)
            if not isinstance(parsed, dict):
                raise McpAuthError("bad_request", "request must be a JSON object")
            crypto.verify(public_key, MCP_DOMAIN, parsed, signature_hex)
        except McpAuthError:
            raise
        except Exception as exc:
            raise McpAuthError(
                "signature_invalid",
                f"Ed25519 signature verification failed: {exc}",
            ) from exc

    # -- tools ------------------------------------------------------------ #

    def _memory_recall(self, params: dict) -> dict:
        artifact_id = params.get("artifact_id", "")
        blob_id = params.get("blob_id", "")

        if not artifact_id or not blob_id:
            raise McpToolError("missing_params", "artifact_id and blob_id are required")

        # 1. Checked snapshot read.
        snapshot = self._db.checked_snapshot_read(artifact_id)
        if snapshot is None or snapshot.artifact_state is None:
            raise McpToolError(
                "artifact_not_found",
                f"artifact {artifact_id} not found",
            )

        # 2. Deletion veto check — direct SQL (no UnitOfWork method on LifecycleDatabase).
        cursor = self._db.con.execute(
            "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
            "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
            (artifact_id,),
        )
        deletion_row = cursor.fetchone()
        if deletion_row is not None:
            if deletion.is_vetoed(deletion_row[0]):
                raise McpToolError(
                    "artifact_vetoed",
                    f"artifact {artifact_id} is under deletion veto",
                )

        # 3. Serve gate check.
        # 3. Serve gate check — direct SQL.
        cursor = self._db.con.execute(
            "SELECT gate_state, reason_state FROM freshness_serve_gate WHERE workspace_id=?",
            (self._workspace_id,),
        )
        gate_row = cursor.fetchone()
        if gate_row is not None and not floor_protocol.serve_gate_allows_serving({
            "state": gate_row[0],
            "reason": gate_row[1],
        }):
            raise McpToolError(
                "serve_withheld",
                f"freshness serve gate withholds serving for workspace {self._workspace_id}",
            )

        # 4. Decrypt and return.
        content, metadata, truncated = self._decrypt_cas_blob(artifact_id, blob_id)
        result: dict[str, Any] = {
            "artifact_id": artifact_id,
            "content": content,
            "truncated": truncated,
            "metadata": metadata,
        }
        return result

    def _memory_source(self, params: dict) -> dict:
        source_content_digest = params.get("source_content_digest", "")
        blob_id = params.get("blob_id", "")
        if not source_content_digest:
            raise McpToolError(
                "missing_params",
                "source_content_digest is required",
            )

        # 1. Deletion veto check.
        cursor = self._db.con.execute(
            "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
            "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
            (source_content_digest,),
        )
        deletion_row = cursor.fetchone()
        if deletion_row is not None:
            if deletion.is_vetoed(deletion_row[0]):
                raise McpToolError(
                    "artifact_vetoed",
                    f"source {source_content_digest} is under deletion veto",
                )

        # 2. Serve gate check.
        cursor = self._db.con.execute(
            "SELECT gate_state, reason_state FROM freshness_serve_gate WHERE workspace_id=?",
            (self._workspace_id,),
        )
        gate_row = cursor.fetchone()
        if gate_row is not None and not floor_protocol.serve_gate_allows_serving({
            "state": gate_row[0],
            "reason": gate_row[1],
        }):
            raise McpToolError(
                "serve_withheld",
                f"freshness serve gate withholds serving for workspace {self._workspace_id}",
            )

        # 3. Verify the source artifact exists.
        cursor = self._db.con.execute(
            "SELECT artifact_state FROM canonical_artifact WHERE artifact_id=?",
            (source_content_digest,),
        )
        row = cursor.fetchone()
        if row is None:
            raise McpToolError(
                "source_not_found",
                f"source artifact {source_content_digest} not found",
            )

        # Look up the blob_id: check params first, then fall back to state_delta.
        if not blob_id:
            delta_cursor = self._db.con.execute(
                "SELECT envelope_ref_id FROM state_delta WHERE object_id=? AND envelope_ref_id IS NOT NULL "
                "ORDER BY delta_id DESC LIMIT 1",
                (source_content_digest,),
            )
            delta_row = delta_cursor.fetchone()
            if delta_row is not None and delta_row[0]:
                blob_id = delta_row[0]

        if not blob_id:
            raise McpToolError(
                "blob_not_found",
                f"no content blob found for source artifact {source_content_digest}",
            )

        content, _metadata, truncated = self._decrypt_cas_blob(
            source_content_digest, blob_id
        )
        result: dict[str, Any] = {
            "source_content_digest": source_content_digest,
            "content": content,
            "truncated": truncated,
        }
        return result

    # -- helpers ---------------------------------------------------------- #

    def _decrypt_cas_blob(self, artifact_id: str, blob_id: str) -> tuple[str, dict, bool]:
        """Read, decrypt, and bound-check a CAS blob.

        Returns ``(content_str, metadata_dict, truncated_bool)``.
        """
        try:
            envelope_bytes = self._cas.get(blob_id)
        except CasNotFound as exc:
            raise McpToolError(
                "blob_not_found",
                f"CAS blob {blob_id} not found",
            ) from exc
        except CasTombstoned as exc:
            raise McpToolError(
                "blob_tombstoned",
                f"CAS blob {blob_id} is tombstoned",
            ) from exc

        try:
            envelope_str = envelope_bytes.decode("utf-8")
            envelope = json.loads(envelope_str)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise McpToolError(
                "envelope_unreadable",
                f"CAS blob {blob_id} is not valid JSON",
            ) from exc

        if not isinstance(envelope, dict):
            raise McpToolError(
                "envelope_unreadable",
                f"CAS blob {blob_id} is not a JSON object",
            )

        nonce = envelope.get("nonce", "")
        ciphertext = envelope.get("ciphertext", "")
        tag = envelope.get("tag", "")
        metadata = envelope.get("metadata", {})

        # Resolve the DEK.
        if self._platform_keystore is not None:
            try:
                dek = self._platform_keystore.get_ark_dek(self._workspace_id, artifact_id)
            except KeyStoreError as exc:
                raise McpToolError(
                    "dek_unavailable",
                    f"platform keystore DEK unavailable for artifact {artifact_id}: {exc}",
                ) from exc
        else:
            dek = self._dek

        aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(artifact_id)

        try:
            plaintext_bytes = crypto.aes_gcm_open(dek, nonce, ciphertext, tag, aad)
        except Exception as exc:
            raise McpToolError(
                "decryption_failed",
                f"AES-GCM decryption failed for artifact {artifact_id}: {exc}",
            ) from exc

        try:
            plaintext_str = plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise McpToolError(
                "decryption_failed",
                f"plaintext is not valid UTF-8 for artifact {artifact_id}",
            ) from exc

        # Apply 64 KiB bound.
        truncated = False
        if len(plaintext_str) > MAX_RESPONSE_SIZE:
            plaintext_str = plaintext_str[:MAX_RESPONSE_SIZE]
            truncated = True

        return plaintext_str, metadata, truncated

    def _serialize_response(self, response: McpResponse) -> str:
        raw = asdict(response)
        serialized = canonical_bytes(raw).decode("utf-8")
        if len(serialized) > MAX_RESPONSE_SIZE:
            # Truncate the "result" dict content field to fit.
            payload = raw.copy()
            content = payload.get("result", {}).get("content", "")
            if isinstance(content, str) and len(content) > 0:
                overhead = len(canonical_bytes(payload))
                max_content = MAX_RESPONSE_SIZE - (overhead - len(content))
                if max_content < 0:
                    max_content = 0
                payload["result"]["content"] = content[:max_content]
                payload["result"]["truncated"] = True
                serialized = canonical_bytes(payload).decode("utf-8")
                if len(serialized) > MAX_RESPONSE_SIZE:
                    # Last resort: minimal response.
                    payload = {"tool": raw["tool"], "result": {"truncated": True}, "error": "response_too_large"}
                    serialized = canonical_bytes(payload).decode("utf-8")
        return serialized
