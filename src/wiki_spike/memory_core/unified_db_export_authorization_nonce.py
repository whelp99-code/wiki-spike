"""Process-local nonce reservation seam for one-shot export authorization.

Nonce identity is global: the same nonce cannot be reserved under two
authorization_ids. This in-memory fake is fixture-only. A durable production
store is still required before any live adapter.
"""
from __future__ import annotations

from threading import Lock
from typing import Protocol, runtime_checkable

from .unified_db_snapshot_export import UnifiedDbExportError


@runtime_checkable
class ExportAuthorizationNonceStore(Protocol):
    def reserve(self, authorization_id: str, nonce: str) -> None:
        """Reserve nonce exclusively, ignoring authorization_id for uniqueness."""

    def consume(self, authorization_id: str, nonce: str) -> None:
        """Mark a reserved nonce consumed. Attempts are not retryable."""


class InMemoryExportAuthorizationNonceStore:
    """Fixture-only fake. Does not persist a nonce store."""

    _states: dict[str, str]
    _lock: Lock

    def __init__(self) -> None:
        self._states = {}
        self._lock = Lock()

    def reserve(self, authorization_id: str, nonce: str) -> None:
        _ = authorization_id
        with self._lock:
            if nonce in self._states:
                raise UnifiedDbExportError("authorization nonce was already consumed")
            self._states[nonce] = "reserved"

    def consume(self, authorization_id: str, nonce: str) -> None:
        _ = authorization_id
        with self._lock:
            if self._states.get(nonce) != "reserved":
                raise UnifiedDbExportError("authorization nonce was already consumed")
            self._states[nonce] = "consumed"
