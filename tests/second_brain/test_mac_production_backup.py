"""Fail-closed Mac production backup copies sqlite+CAS only after SERVING_READY."""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
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
from tests.second_brain.mac_production_status_compose_support import (
    cas_root,
    v1_dir,
    write_cas_layout,
)
from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    sqlite_path,
    write_lifecycle_database,
)
from tests.second_brain.mac_production_status_support import tree_snapshot

_CLI = Path("scripts/second_brain_mac_backup.py")


def _decoy_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    decoy = tmp_path / "decoy-home"
    decoy.mkdir()
    monkeypatch.setenv("HOME", str(decoy))
    return decoy


def _assert_no_real_home_writes(decoy: Path) -> None:
    assert not (decoy / "Library").exists()


def _assert_no_raw_numbers(value: object) -> None:
    assert not isinstance(value, bool | int | float)
    if isinstance(value, Mapping):
        for item in value.values():
            _assert_no_raw_numbers(item)
    elif isinstance(value, list):
        for item in value:
            _assert_no_raw_numbers(item)


@pytest.mark.parametrize(
    "kind",
    ("missing_sqlite", "wal", "missing_cas", "not_serving"),
)
def test_missing_sqlite_wal_cas_or_serving_refuses_without_dest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    dest = tmp_path / "backup"
    if kind == "missing_sqlite":
        v1_dir(home).mkdir(parents=True)
    elif kind == "missing_cas":
        write_lifecycle_database(sqlite_path(home))
    elif kind == "not_serving":
        write_lifecycle_database(sqlite_path(home), migration_state="READY_NON_SERVING")
        write_cas_layout(home)
    else:
        write_backup_source(home)
        _ = Path(f"{sqlite_path(home)}-wal").write_bytes(b"wal")
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)
    before_tree = tree_snapshot(home)

    code = run_backup(home, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(home) == before
    assert tree_snapshot(home) == before_tree
    _assert_no_real_home_writes(decoy)


def test_dest_exists_refuses_without_overwrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_backup_source(home)
    dest = tmp_path / "backup"
    _ = dest.write_text("keep-me", encoding="utf-8")
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)

    code = run_backup(home, dest)

    assert code != 0
    assert dest.read_text(encoding="utf-8") == "keep-me"
    assert identity_snapshot(home) == before
    _assert_no_real_home_writes(decoy)


def test_symlink_dest_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_backup_source(home)
    victim = tmp_path / "victim"
    _ = victim.write_text("keep-me", encoding="utf-8")
    dest = tmp_path / "backup"
    dest.symlink_to(victim)
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)

    code = run_backup(home, dest)

    assert code != 0
    assert dest.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep-me"
    assert identity_snapshot(home) == before
    _assert_no_real_home_writes(decoy)


def test_symlink_dest_ancestor_refuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_backup_source(home)
    real = tmp_path / "real-out"
    real.mkdir()
    linked = tmp_path / "link-out"
    linked.symlink_to(real, target_is_directory=True)
    dest = linked / "backup"
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)

    code = run_backup(home, dest)

    assert code != 0
    assert not dest.exists()
    assert list(real.iterdir()) == []
    assert identity_snapshot(home) == before
    _assert_no_real_home_writes(decoy)


def test_happy_path_copies_sqlite_and_cas_source_immutable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_backup_source(home)
    dest = tmp_path / "backup"
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)
    before_tree = tree_snapshot(home)
    source_sqlite = sqlite_path(home)
    source_blob = cas_root(home) / "objects" / CAS_OBJECT_NAME
    source_sqlite_ino = os.lstat(source_sqlite).st_ino
    source_cas_ino = os.lstat(cas_root(home)).st_ino

    code = run_backup(home, dest)

    assert code == 0
    assert identity_snapshot(home) == before
    assert tree_snapshot(home) == before_tree
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
    receipt = dest / "backup-receipt.json"
    assert receipt.is_file() and not receipt.is_symlink()
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    assert payload["sqlite_sha256"] == hashlib.sha256(
        source_sqlite.read_bytes()
    ).hexdigest()
    assert payload["cas_file_count"].isdigit()
    assert isinstance(payload["cas_file_count"], str)
    assert payload["serving_ready"] == "true"
    assert payload["workspace_ref"] == PINNED_WORKSPACE
    assert "signatures" not in payload
    _assert_no_raw_numbers(payload)
    _assert_no_real_home_writes(decoy)
    source = _CLI.read_text(encoding="utf-8")
    assert "/usr/bin/security" not in source
    assert "add-generic-password" not in source
    assert "find-generic-password" not in source
    assert "delete-generic-password" not in source
    assert "--private-key" not in source
    assert "BEGIN" not in source


def test_dest_inside_source_tree_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_backup_source(home)
    dest = v1_dir(home) / "nested-backup"
    arm_bombs(monkeypatch)
    before = identity_snapshot(home)
    before_tree = tree_snapshot(home)

    code = run_backup(home, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(home) == before
    assert tree_snapshot(home) == before_tree
    _assert_no_real_home_writes(decoy)
