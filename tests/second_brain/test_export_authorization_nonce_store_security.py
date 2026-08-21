"""Fail-closed path, permission, schema, and corruption probes."""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    attempt,
    private_store_path,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def _open(path: Path) -> None:
    store = SqliteExportAuthorizationNonceStore(path)
    store.close()


def test_unknown_schema_is_refused_and_unchanged(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    connection = sqlite3.connect(path)
    _ = connection.execute("CREATE TABLE unexpected (value TEXT)")
    connection.commit()
    connection.close()
    os.chmod(path, 0o600)
    before = path.read_bytes()
    with pytest.raises(UnifiedDbExportError, match="schema"):
        _open(path)
    assert path.read_bytes() == before


def test_corrupt_bytes_are_refused_and_unchanged(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(path)
    store.reserve_and_consume(**attempt())
    store.close()
    planted = b"not-a-sqlite-database" + os.urandom(64)
    _ = path.write_bytes(planted)
    with pytest.raises(UnifiedDbExportError, match="corrupt"):
        _open(path)
    assert path.read_bytes() == planted


def test_world_readable_permissions_are_refused(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    _open(path)
    os.chmod(path, 0o644)
    with pytest.raises(UnifiedDbExportError, match="permission"):
        _open(path)


def test_symlink_path_is_refused(tmp_path: Path) -> None:
    real = private_store_path(tmp_path)
    _open(real)
    alias_dir = tmp_path / "alias-authority"
    os.mkdir(alias_dir, 0o700)
    os.chmod(alias_dir, 0o700)
    alias = alias_dir / "nonces.sqlite3"
    alias.symlink_to(real)
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _open(alias)
    assert real.is_file()
    assert not real.is_symlink()


def test_hardlink_is_refused(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    _open(path)
    extra = tmp_path / "hardlink.sqlite3"
    os.link(path, extra)
    with pytest.raises(UnifiedDbExportError, match="hardlink|nlink|link"):
        _open(path)


def test_symlink_ancestor_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    os.mkdir(real, 0o700)
    os.chmod(real, 0o700)
    store_dir = real / "export-authority-v1"
    os.mkdir(store_dir, 0o700)
    os.chmod(store_dir, 0o700)
    path = store_dir / "nonces.sqlite3"
    _open(path)
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _open(alias / "export-authority-v1" / "nonces.sqlite3")
