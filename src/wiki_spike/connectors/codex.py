"""Codex fixture connector plus an inert, typed live-source adapter."""
from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from threading import RLock
from typing import Any

from . import FixtureConnectorReader
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    SOURCE_CHECKPOINT_VERSION,
    SourceCheckpointV1,
    SourceItemDispositionV1,
    SourcePageV1,
)
from wiki_spike.memory_core.second_brain_ports import (
    CredentialProviderPort,
    FilesystemSourceClientPort,
    SourceApiClientPort,
    SourceCheckpointPort,
    SourceReaderPort,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
    require_security_context_authority,
)


class CodexFixtureConnector(FixtureConnectorReader):
    source_profile = "Codex"
    source_domain = "codex"


class _ReadOnlySourceAdapter(SourceReaderPort, SourceCheckpointPort):
    """Application-only adapter with an in-memory CAS checkpoint for a test run.

    The injected client is deliberately a low-level read transport.  The adapter
    does not persist credentials, raw content, or an authorization grant.
    """

    source_profile = ""
    uses_filesystem = False
    live_operation_authorized = False

    def __init__(
        self, *, api_client: SourceApiClientPort | None = None,
        filesystem_client: FilesystemSourceClientPort | None = None,
        credential_provider: CredentialProviderPort,
        security_authority: SecurityContextAuthority | None = None,
    ) -> None:
        if credential_provider is None or not isinstance(credential_provider, CredentialProviderPort):
            raise ValueError("a typed read-only credential provider is required")
        if self.uses_filesystem:
            if api_client is not None or filesystem_client is None:
                raise ValueError("this source requires only an injected filesystem client")
            client: SourceApiClientPort | FilesystemSourceClientPort = filesystem_client
        else:
            if filesystem_client is not None or api_client is None:
                raise ValueError("this source requires only an injected API client")
            client = api_client
        if not isinstance(client, (SourceApiClientPort, FilesystemSourceClientPort)):
            raise ValueError("client must implement the low-level source client port")
        if getattr(client, "read_only", None) is not True or any(
            callable(getattr(client, name, None))
            for name in ("write", "append", "patch", "unlink", "rename", "delete", "create", "update", "mutate", "post", "put", "request")
        ):
            raise ValueError("write-capable source clients are forbidden")
        self._client = client
        self._credential_provider = credential_provider
        self._security_authority = security_authority
        self._checkpoints: dict[str, SourceCheckpointV1] = {}
        self._validated_pages: dict[str, SourcePageV1] = {}
        # Process-local only: this is not a durable or cross-process checkpoint authority.
        self._checkpoint_lock = RLock()

    def read_page(self, *, source_scope: str, cursor: str | None, watermark: str | None, limit: int) -> SourcePageV1:
        if not isinstance(source_scope, str) or not source_scope or not 1 <= limit <= 1000 or (cursor is None) != (watermark is None):
            raise ValueError("source scope and bounded limit are required")
        try:
            require_security_context_authority(
                self._security_authority, scope_kind="source_profile", scope_name=self.source_profile,
            )
        except Exception as exc:
            raise ValueError("a resolved trusted security context for this source profile is required") from exc
        credential = self._credential_provider.read_only_credential(source_scope=source_scope)
        try:
            raw = self._client.read_page(
                source_scope=source_scope, cursor=cursor, watermark=watermark,
                limit=limit, credential=credential,
            )
        finally:
            # The capability is intentionally not retained on this adapter.
            credential = None
        if not isinstance(raw, Mapping):
            raise ValueError("low-level source client must return a closed source page mapping")
        page = SourcePageV1.from_mapping(raw)
        if (page.source_profile, page.source_scope, page.cursor, page.watermark) != (self.source_profile, source_scope, cursor, watermark):
            raise ValueError("source page must pin the adapter profile, requested scope, cursor, and watermark")
        if len(page.items) > limit:
            raise ValueError("source page exceeded the requested bound")
        with self._checkpoint_lock:
            self._validated_pages[page.digest] = page
        return page

    def load(self, *, source_scope: str) -> SourceCheckpointV1 | None:
        if not isinstance(source_scope, str) or not source_scope:
            raise ValueError("source scope is required")
        with self._checkpoint_lock:
            return self._checkpoints.get(source_scope)

    def commit(
        self, *, source_scope: str, prior_checkpoint: SourceCheckpointV1 | None,
        observed_page_digest: str, next_cursor: str | None, next_watermark: str | None,
        dispositions: tuple[SourceItemDispositionV1, ...],
        tombstones: tuple[tuple[str, str], ...],
    ) -> SourceCheckpointV1:
        if not isinstance(source_scope, str) or not source_scope or (next_cursor is None) != (next_watermark is None):
            raise ValueError("source scope and paired next cursor/watermark are required")
        with self._checkpoint_lock:
            try:
                require_security_context_authority(
                    self._security_authority, scope_kind="source_profile", scope_name=self.source_profile,
                )
            except Exception as exc:
                raise ValueError("a resolved trusted security context for this source profile is required") from exc
            current = self._checkpoints.get(source_scope)
            if prior_checkpoint is not None and (prior_checkpoint.source_scope != source_scope or prior_checkpoint.source_profile != self.source_profile):
                raise ValueError("prior checkpoint scope mismatch")
            ordered = tuple(dispositions)
            if any(not isinstance(item, SourceItemDispositionV1) for item in ordered):
                raise ValueError("closed source item dispositions are required")
            identities = tuple((item.native_id, item.revision) for item in ordered)
            if identities != tuple(sorted(identities)) or len(set(identities)) != len(identities):
                raise ValueError("dispositions must be sorted and unique")
            normalized_tombstones = tuple(tombstones)
            if normalized_tombstones != tuple(sorted(normalized_tombstones)) or len(set(normalized_tombstones)) != len(normalized_tombstones):
                raise ValueError("tombstones must be sorted and unique")
            expected_tombstones = tuple((item.native_id, item.revision) for item in ordered if item.disposition == "TOMBSTONE")
            if normalized_tombstones != expected_tombstones:
                raise ValueError("tombstones must exactly match persisted dispositions")
            if not isinstance(observed_page_digest, str) or len(observed_page_digest) != 64:
                raise ValueError("a canonical observed page digest is required")
            page = self._validated_pages.get(observed_page_digest)
            if page is None or page.digest != observed_page_digest:
                raise ValueError("checkpoint commit requires a validated observed page")
            if (page.source_profile, page.source_scope) != (self.source_profile, source_scope):
                raise ValueError("observed page source binding does not match checkpoint scope")
            expected_prior_position = (None, None) if prior_checkpoint is None else (prior_checkpoint.cursor, prior_checkpoint.watermark)
            if (page.cursor, page.watermark) != expected_prior_position or (page.next_cursor, page.next_watermark) != (next_cursor, next_watermark):
                raise ValueError("observed page cursor and watermark binding does not match checkpoint advance")
            if ordered != tuple(item.disposition for item in page.items) or normalized_tombstones != tuple((item.native_id, item.revision) for item in page.items if item.tombstone):
                raise ValueError("checkpoint dispositions and tombstones must exactly bind the observed page")
            if any(item.disposition == "TRANSIENT_FAILURE" for item in ordered):
                if prior_checkpoint is None:
                    if (next_cursor, next_watermark) != (None, None):
                        raise ValueError("initial transient failure must not advance a checkpoint")
                elif (next_cursor, next_watermark) != (prior_checkpoint.cursor, prior_checkpoint.watermark):
                    raise ValueError("transient failure must never advance a checkpoint")
            body: dict[str, Any] = {
            "checkpoint_version": SOURCE_CHECKPOINT_VERSION, "source_profile": self.source_profile,
            "source_scope": source_scope,
            "observed_page_digest": observed_page_digest,
            "prior_checkpoint_digest": None if prior_checkpoint is None else prior_checkpoint.checkpoint_digest,
            "cursor": next_cursor, "watermark": next_watermark,
            "dispositions": [item.to_mapping() for item in ordered],
            "tombstones": [{"native_id": native_id, "revision": revision} for native_id, revision in normalized_tombstones],
            "live_operation_authorized": False,
            }
            digest = sha256(canonical_bytes(body)).hexdigest()
            value = SourceCheckpointV1.from_mapping({**body, "checkpoint_digest": digest})
            # Retrying an already-published candidate is safe even when the caller
            # still holds the pre-CAS (including None) checkpoint.
            if current == value:
                return current
            if current != prior_checkpoint:
                raise ValueError("checkpoint compare-and-swap conflict")
            self._checkpoints[source_scope] = value
            return value


class CodexLiveSourceAdapter(_ReadOnlySourceAdapter):
    """The only typed Codex source adapter; execution remains non-authorizing."""

    source_profile = "Codex"


CodexSourceReader = CodexLiveSourceAdapter


__all__ = ["CodexFixtureConnector", "CodexLiveSourceAdapter", "CodexSourceReader"]
