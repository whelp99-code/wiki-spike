"""Capture-domain adapter over the shared physical export nonce SQLite store."""
from __future__ import annotations

import multiprocessing
import os
from collections.abc import Callable
from dataclasses import dataclass
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
    capture_commit_then_hard_exit,
)
from wiki_spike.composition.unified_db_postgres_capture import (
    open_production_metadata_capture_nonce_store,
)
from wiki_spike.infrastructure.export_authorization_nonce_capture import (
    SqliteMetadataCaptureNonceStore,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    metadata_capture_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_WAIT = 10


@dataclass(frozen=True, slots=True)
class _PasswdRecord:
    pw_dir: str


def _initialized_store(directory: Path) -> Path:
    path = private_store_path(directory)
    store = SqliteExportAuthorizationNonceStore(path)
    store.close()
    return path


def _production_store(home: Path) -> Path:
    support = home / "Library" / "Application Support"
    support.mkdir(parents=True)
    wiki = support / "wiki-spike"
    os.mkdir(wiki, 0o700)
    os.chmod(wiki, 0o700)
    return _initialized_store(wiki)


def _passwd_lookup(home: Path) -> Callable[[int], _PasswdRecord]:
    def lookup(uid: int) -> _PasswdRecord:
        _ = uid
        return _PasswdRecord(pw_dir=str(home))

    return lookup


def test_production_opener_ignores_home_env_and_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    env_home = tmp_path / "env-home"
    cwd = tmp_path / "cwd"
    passwd_home.mkdir()
    env_home.mkdir()
    cwd.mkdir()
    passwd_path = _production_store(passwd_home)
    env_path = _production_store(env_home)
    monkeypatch.setenv("HOME", str(env_home))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    store = open_production_metadata_capture_nonce_store()
    store.reserve_and_consume(**attempt())
    store.close()
    replay = SqliteMetadataCaptureNonceStore(passwd_path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        replay.reserve_and_consume(**attempt())
    replay.close()
    env_store = SqliteMetadataCaptureNonceStore(env_path)
    env_store.reserve_and_consume(**attempt())
    env_store.close()
    assert not (cwd / "Library").exists()


def test_missing_store_is_refused_and_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = private_store_path(tmp_path / "adapter")
    assert not path.exists()
    with pytest.raises(UnifiedDbExportError):
        _ = SqliteMetadataCaptureNonceStore(path)
    assert not path.exists()
    passwd_home = tmp_path / "passwd"
    passwd_home.mkdir()
    monkeypatch.setenv("HOME", str(tmp_path / "env-home"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    with pytest.raises(UnifiedDbExportError):
        _ = open_production_metadata_capture_nonce_store()
    assert not (passwd_home / "Library").exists()
    assert not (tmp_path / "env-home").exists()


def test_corrupt_store_is_refused_and_not_recreated(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    planted = b"not-a-sqlite-database"
    _ = path.write_bytes(planted)
    os.chmod(path, 0o600)
    with pytest.raises(UnifiedDbExportError):
        _ = SqliteMetadataCaptureNonceStore(path)
    assert path.read_bytes() == planted


def test_capture_replay_is_domain_separated_from_export(tmp_path: Path) -> None:
    path = _initialized_store(tmp_path)
    capture = SqliteMetadataCaptureNonceStore(path)
    capture.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        capture.reserve_and_consume(**attempt())
    capture.close()
    payload = path.read_bytes()
    assert NONCE.encode("ascii") not in payload
    capture_digest = metadata_capture_nonce_digest(NONCE).encode("ascii")
    export_digest = export_authorization_nonce_digest(NONCE).encode("ascii")
    assert capture_digest != export_digest
    assert capture_digest in payload
    assert export_digest not in payload


def test_capture_and_export_consume_same_nonce_independently(tmp_path: Path) -> None:
    path = _initialized_store(tmp_path)
    exported = SqliteExportAuthorizationNonceStore(path)
    exported.reserve_and_consume(**attempt())
    capture = SqliteMetadataCaptureNonceStore(path)
    capture.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        exported.reserve_and_consume(**attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        capture.reserve_and_consume(**attempt())
    exported.close()
    capture.close()
    payload = path.read_bytes()
    assert metadata_capture_nonce_digest(NONCE).encode("ascii") in payload
    assert export_authorization_nonce_digest(NONCE).encode("ascii") in payload


def test_close_reopen_replay_is_refused(tmp_path: Path) -> None:
    path = _initialized_store(tmp_path)
    store = SqliteMetadataCaptureNonceStore(path)
    store.reserve_and_consume(**attempt())
    store.close()
    reopened = SqliteMetadataCaptureNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        reopened.reserve_and_consume(**attempt())
    reopened.close()


def test_hard_exit_after_commit_preserves_consumed_state(tmp_path: Path) -> None:
    path = _initialized_store(tmp_path)
    ctx = multiprocessing.get_context("spawn")
    ready: multiprocessing.Queue[str] = ctx.Queue(1)
    go: multiprocessing.Queue[str] = ctx.Queue(1)
    recv, send = ctx.Pipe(duplex=False)
    worker = ctx.Process(
        target=capture_commit_then_hard_exit,
        args=(str(path), "capture-auth-001", NONCE, DIGEST, ISSUED, ready, go, send),
    )
    worker.start()
    send.close()
    assert ready.get(timeout=_WAIT) == "READY"
    go.put("GO")
    assert recv.poll(timeout=_WAIT)
    assert recv.recv() == "COMMITTED"
    worker.join(timeout=_WAIT)
    assert not worker.is_alive()
    store = SqliteMetadataCaptureNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt())
    store.close()
