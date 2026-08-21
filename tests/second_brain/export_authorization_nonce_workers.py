"""Spawn workers for durable nonce-store race and crash tests."""
from __future__ import annotations

import os
from multiprocessing.connection import Connection
from multiprocessing.queues import Queue
from pathlib import Path

from wiki_spike.infrastructure.export_authorization_nonce_capture import (
    SqliteMetadataCaptureNonceStore,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def race_reserve_and_consume(
    db_path: str,
    authorization_id: str,
    nonce: str,
    authorization_digest: str,
    authorization_issued_at: str,
    ready: Queue[str],
    go: Queue[str],
    result: Queue[str],
) -> None:
    ready.put("READY")
    command = go.get()
    if command != "GO":
        result.put("LOSE")
        return
    try:
        store = SqliteExportAuthorizationNonceStore(Path(db_path))
        store.reserve_and_consume(
            authorization_id=authorization_id,
            nonce=nonce,
            authorization_digest=authorization_digest,
            authorization_issued_at=authorization_issued_at,
        )
        store.close()
        result.put("WIN")
    except UnifiedDbExportError:
        result.put("LOSE")


def commit_then_hard_exit(
    db_path: str,
    authorization_id: str,
    nonce: str,
    authorization_digest: str,
    authorization_issued_at: str,
    ready: Queue[str],
    go: Queue[str],
    done: Connection,
) -> None:
    ready.put("READY")
    command = go.get()
    if command != "GO":
        done.send("SKIP")
        done.close()
        return
    store = SqliteExportAuthorizationNonceStore(Path(db_path))
    store.reserve_and_consume(
        authorization_id=authorization_id,
        nonce=nonce,
        authorization_digest=authorization_digest,
        authorization_issued_at=authorization_issued_at,
    )
    done.send("COMMITTED")
    done.close()
    os._exit(0)


def capture_commit_then_hard_exit(
    db_path: str,
    authorization_id: str,
    nonce: str,
    authorization_digest: str,
    authorization_issued_at: str,
    ready: Queue[str],
    go: Queue[str],
    done: Connection,
) -> None:
    ready.put("READY")
    command = go.get()
    if command != "GO":
        done.send("SKIP")
        done.close()
        return
    store = SqliteMetadataCaptureNonceStore(Path(db_path))
    store.reserve_and_consume(
        authorization_id=authorization_id,
        nonce=nonce,
        authorization_digest=authorization_digest,
        authorization_issued_at=authorization_issued_at,
    )
    done.send("COMMITTED")
    done.close()
    os._exit(0)
