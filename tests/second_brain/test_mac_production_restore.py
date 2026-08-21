"""Fail-closed Mac production restore copies sqlite+CAS only after SERVING_READY."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.second_brain.mac_production_backup_support import (
    CAS_OBJECT_BYTES,
    CAS_OBJECT_NAME,
    arm_bombs,
    identity_snapshot,
)
from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    write_lifecycle_database,
)
from tests.second_brain.mac_production_status_support import tree_snapshot
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)

_CLI = Path("scripts/second_brain_mac_restore.py")


def _decoy_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    decoy = tmp_path / "decoy-home"
    decoy.mkdir()
    monkeypatch.setenv("HOME", str(decoy))
    return decoy


def _assert_no_real_home_writes(decoy: Path) -> None:
    assert not (decoy / "Library").exists()


def run_restore(backup: Path, dest: Path) -> int:
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


def _write_cas(backup: Path) -> None:
    cas = backup / "cas"
    cas.mkdir(mode=0o700)
    (cas / "objects").mkdir(mode=0o700)
    (cas / "tombstones").mkdir(mode=0o700)
    for path in (cas, cas / "objects", cas / "tombstones"):
        path.chmod(0o700)
    blob = cas / "objects" / CAS_OBJECT_NAME
    _ = blob.write_bytes(CAS_OBJECT_BYTES)
    blob.chmod(0o444)


def _write_backup(backup: Path, *, migration_state: str = "SERVING_READY") -> None:
    write_lifecycle_database(
        backup / "lifecycle.sqlite3",
        migration_state=migration_state,
    )
    _write_cas(backup)
    keychain = backup / "keychain"
    keychain.mkdir()
    _ = (keychain / "secret").write_bytes(b"secret")


def _assert_serving_ready(sqlite: Path) -> None:
    database = open_existing_lifecycle_database(sqlite)
    try:
        status = inspect_existing_serving_ready(database, PINNED_WORKSPACE)
    finally:
        database.close()
    assert status.ready
    assert status.workspace_ref == PINNED_WORKSPACE
    assert status.migration_state == "SERVING_READY"


@pytest.mark.parametrize("kind", ("missing_sqlite", "missing_cas", "not_serving"))
def test_missing_backup_sqlite_cas_or_serving_refuses_without_dest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    dest = tmp_path / "restore"
    if kind == "missing_sqlite":
        backup.mkdir()
        _write_cas(backup)
    elif kind == "missing_cas":
        write_lifecycle_database(backup / "lifecycle.sqlite3")
    else:
        _write_backup(backup, migration_state="READY_NON_SERVING")
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)
    before_tree = tree_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(backup) == before
    assert tree_snapshot(backup) == before_tree
    _assert_no_real_home_writes(decoy)


def test_dest_exists_refuses_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    _write_backup(backup)
    dest = tmp_path / "restore"
    _ = dest.write_text("keep-me", encoding="utf-8")
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert dest.read_text(encoding="utf-8") == "keep-me"
    assert identity_snapshot(backup) == before
    _assert_no_real_home_writes(decoy)


def test_symlink_dest_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    _write_backup(backup)
    victim = tmp_path / "victim"
    _ = victim.write_text("keep-me", encoding="utf-8")
    dest = tmp_path / "restore"
    dest.symlink_to(victim)
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert dest.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep-me"
    assert identity_snapshot(backup) == before
    _assert_no_real_home_writes(decoy)


def test_symlink_dest_ancestor_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    _write_backup(backup)
    real = tmp_path / "real-out"
    real.mkdir()
    linked = tmp_path / "link-out"
    linked.symlink_to(real, target_is_directory=True)
    dest = linked / "restore"
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert list(real.iterdir()) == []
    assert identity_snapshot(backup) == before
    _assert_no_real_home_writes(decoy)


def test_happy_path_backup_immutable_restored_serving_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    _write_backup(backup)
    dest = tmp_path / "restore"
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)
    before_tree = tree_snapshot(backup)
    source_sqlite = backup / "lifecycle.sqlite3"
    source_blob = backup / "cas" / "objects" / CAS_OBJECT_NAME
    source_sqlite_ino = os.lstat(source_sqlite).st_ino
    source_cas_ino = os.lstat(backup / "cas").st_ino

    code = run_restore(backup, dest)

    assert code == 0
    assert identity_snapshot(backup) == before
    assert tree_snapshot(backup) == before_tree
    copied = dest / "lifecycle.sqlite3"
    assert copied.is_file() and not copied.is_symlink()
    assert copied.read_bytes() == source_sqlite.read_bytes()
    assert os.lstat(copied).st_ino != source_sqlite_ino
    blob = dest / "cas" / "objects" / CAS_OBJECT_NAME
    assert blob.is_file() and not blob.is_symlink()
    assert blob.read_bytes() == CAS_OBJECT_BYTES == source_blob.read_bytes()
    assert os.lstat(dest / "cas").st_ino != source_cas_ino
    assert not (dest / "keychain").exists()
    for path in dest.rglob("*"):
        assert "keychain" not in path.name.casefold()
        assert not path.is_symlink()
    _assert_serving_ready(copied)
    _assert_no_real_home_writes(decoy)
    source = _CLI.read_text(encoding="utf-8")
    assert "/usr/bin/security" not in source
    assert "add-generic-password" not in source
    assert "find-generic-password" not in source
    assert "delete-generic-password" not in source
    assert "--private-key" not in source
    assert "BEGIN" not in source
    assert "initialize" not in source
