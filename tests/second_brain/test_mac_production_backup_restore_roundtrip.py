"""Backup then restore must keep the live source immutable and SERVING_READY."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.second_brain.mac_production_backup_support import (
    CAS_OBJECT_BYTES,
    CAS_OBJECT_NAME,
    arm_bombs,
    identity_snapshot,
    run_backup,
    write_backup_source,
)
from tests.second_brain.mac_production_status_serving_support import PINNED_WORKSPACE
from tests.second_brain.mac_production_status_support import tree_snapshot
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)


def _run_restore(backup: Path, dest: Path) -> int:
    from scripts.second_brain_mac_restore import main

    return main(
        [
            "--backup",
            str(backup),
            "--workspace-ref",
            PINNED_WORKSPACE,
            "--dest",
            str(dest),
        ]
    )


def test_backup_then_restore_keeps_live_source_immutable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = tmp_path / "decoy-home"
    decoy.mkdir()
    monkeypatch.setenv("HOME", str(decoy))
    home = tmp_path / "passwd-home"
    write_backup_source(home)
    live_root = home / "Library" / "Application Support" / "wiki-spike" / "second-brain-v1"
    backup_dest = tmp_path / "backup-v1"
    restore_dest = tmp_path / "restore-v1"
    arm_bombs(monkeypatch)
    before = identity_snapshot(live_root)
    before_tree = tree_snapshot(live_root)
    live_sqlite = live_root / "lifecycle.sqlite3"
    live_blob = live_root / "cas" / "objects" / CAS_OBJECT_NAME
    live_sqlite_ino = os.lstat(live_sqlite).st_ino

    assert run_backup(home, backup_dest) == 0
    assert _run_restore(backup_dest, restore_dest) == 0

    assert identity_snapshot(live_root) == before
    assert tree_snapshot(live_root) == before_tree
    assert not (decoy / "Library").exists()
    restored = restore_dest / "lifecycle.sqlite3"
    assert restored.is_file() and not restored.is_symlink()
    assert restored.read_bytes() == live_sqlite.read_bytes()
    assert os.lstat(restored).st_ino != live_sqlite_ino
    blob = restore_dest / "cas" / "objects" / CAS_OBJECT_NAME
    assert blob.read_bytes() == CAS_OBJECT_BYTES == live_blob.read_bytes()
    database = open_existing_lifecycle_database(restored)
    try:
        status = inspect_existing_serving_ready(database, PINNED_WORKSPACE)
    finally:
        database.close()
    assert status.ready is True
    assert not (restore_dest / "keychain").exists()
