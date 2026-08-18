"""Spawned-process race and hard-exit durability for the nonce store."""
from __future__ import annotations

import multiprocessing
from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    DIGEST,
    ISSUED,
    NONCE,
    attempt,
    private_store_path,
)
from tests.second_brain.export_authorization_nonce_workers import (
    commit_then_hard_exit,
    race_reserve_and_consume,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_WAIT = 10


def test_spawned_processes_admit_exactly_one_winner(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    created = SqliteExportAuthorizationNonceStore(path)
    created.close()
    ctx = multiprocessing.get_context("spawn")
    ready: multiprocessing.Queue[str] = ctx.Queue(2)
    go: multiprocessing.Queue[str] = ctx.Queue(2)
    result: multiprocessing.Queue[str] = ctx.Queue(2)
    workers = [
        ctx.Process(
            target=race_reserve_and_consume,
            args=(
                str(path),
                "export-auth-001",
                NONCE,
                DIGEST,
                ISSUED,
                ready,
                go,
                result,
            ),
        )
        for _ in range(2)
    ]
    for worker in workers:
        worker.start()
    assert ready.get(timeout=_WAIT) == "READY"
    assert ready.get(timeout=_WAIT) == "READY"
    go.put("GO")
    go.put("GO")
    outcomes = [result.get(timeout=_WAIT), result.get(timeout=_WAIT)]
    for worker in workers:
        worker.join(timeout=_WAIT)
        assert worker.exitcode == 0
        assert not worker.is_alive()
    assert outcomes.count("WIN") == 1
    assert outcomes.count("LOSE") == 1
    store = SqliteExportAuthorizationNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt())
    store.close()


def test_hard_exit_after_commit_preserves_consumed_state(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    created = SqliteExportAuthorizationNonceStore(path)
    created.close()
    ctx = multiprocessing.get_context("spawn")
    ready: multiprocessing.Queue[str] = ctx.Queue(1)
    go: multiprocessing.Queue[str] = ctx.Queue(1)
    recv, send = ctx.Pipe(duplex=False)
    worker = ctx.Process(
        target=commit_then_hard_exit,
        args=(str(path), "export-auth-001", NONCE, DIGEST, ISSUED, ready, go, send),
    )
    worker.start()
    send.close()
    assert ready.get(timeout=_WAIT) == "READY"
    go.put("GO")
    assert recv.poll(timeout=_WAIT)
    assert recv.recv() == "COMMITTED"
    worker.join(timeout=_WAIT)
    assert not worker.is_alive()
    store = SqliteExportAuthorizationNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt())
    store.close()
