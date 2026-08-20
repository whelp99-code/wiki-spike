"""Process-local one-shot metadata-capture authorization nonce protocol."""
from __future__ import annotations

from hashlib import sha256
from threading import Lock
from typing import Final, Protocol, runtime_checkable

from .unified_db_snapshot_export import UnifiedDbExportError

NONCE_DIGEST_DOMAIN: Final = (
    b"wiki-spike.second-brain.postgres-metadata-capture-nonce-store.v1\x00"
)


def metadata_capture_nonce_digest(nonce: str) -> str:
    if not nonce.isascii():
        raise UnifiedDbExportError("authorization nonce must be ASCII")
    return sha256(NONCE_DIGEST_DOMAIN + nonce.encode("ascii")).hexdigest()


@runtime_checkable
class MetadataCaptureNonceStore(Protocol):
    def reserve_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        authorization_digest: str,
        authorization_issued_at: str,
    ) -> None:
        """Insert the nonce as CONSUMED or refuse a replay."""


class InMemoryMetadataCaptureNonceStore:
    """Process-local fake. One locked final-state insertion. Not durable."""

    _states: dict[str, str]
    _lock: Lock

    def __init__(self) -> None:
        self._states = {}
        self._lock = Lock()

    def reserve_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        authorization_digest: str,
        authorization_issued_at: str,
    ) -> None:
        _ = authorization_id, authorization_digest, authorization_issued_at
        digest = metadata_capture_nonce_digest(nonce)
        with self._lock:
            if digest in self._states:
                raise UnifiedDbExportError("authorization nonce was already consumed")
            self._states[digest] = "CONSUMED"
