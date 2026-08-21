"""Restore must verify a create-only backup receipt before copying."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.second_brain.mac_production_backup_support import (
    arm_bombs,
    identity_snapshot,
)
from tests.second_brain.mac_production_status_serving_support import PINNED_WORKSPACE
from tests.second_brain.mac_production_status_support import tree_snapshot
from tests.second_brain.test_mac_production_restore import (
    _assert_no_real_home_writes,
    _decoy_home,
    _write_backup,
    run_restore,
)
from wiki_spike.infrastructure.mac_backup_receipt import (
    MacBackupReceiptError,
    verify_restore_receipt,
)


def test_restore_refuses_backup_without_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    dest = tmp_path / "restore"
    _write_backup(backup)
    receipt = backup / "backup-receipt.json"
    if receipt.exists():
        receipt.unlink()
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)
    before_tree = tree_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(backup) == before
    assert tree_snapshot(backup) == before_tree
    _assert_no_real_home_writes(decoy)


def test_restore_refuses_mismatched_sqlite_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    dest = tmp_path / "restore"
    _write_backup(backup)
    receipt = backup / "backup-receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["sqlite_sha256"] = "0" * 64
    receipt.unlink()
    receipt.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(backup) == before
    _assert_no_real_home_writes(decoy)


def test_restore_receipt_matches_dest_and_refuses_tamper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    dest = tmp_path / "restore"
    _write_backup(backup)
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)

    assert run_restore(backup, dest) == 0
    verify_restore_receipt(dest, PINNED_WORKSPACE)

    receipt = dest / "restore-receipt.json"
    payload = json.loads(receipt.read_text(encoding="utf-8"))
    payload["sqlite_sha256"] = "0" * 64
    receipt.unlink()
    receipt.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    with pytest.raises(MacBackupReceiptError):
        verify_restore_receipt(dest, PINNED_WORKSPACE)
    assert identity_snapshot(backup) == before
    _assert_no_real_home_writes(decoy)


def test_restore_dest_inside_backup_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    backup = tmp_path / "backup"
    dest = backup / "nested-restore"
    _write_backup(backup)
    arm_bombs(monkeypatch)
    before = identity_snapshot(backup)
    before_tree = tree_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(backup) == before
    assert tree_snapshot(backup) == before_tree
    _assert_no_real_home_writes(decoy)


def test_restore_dest_inside_existing_lifecycle_tree_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    decoy = _decoy_home(tmp_path, monkeypatch)
    live = tmp_path / "live-v1"
    backup = tmp_path / "backup"
    dest = live / "nested-restore"
    _write_backup(live)
    _write_backup(backup)
    arm_bombs(monkeypatch)
    live_before = identity_snapshot(live)
    backup_before = identity_snapshot(backup)

    code = run_restore(backup, dest)

    assert code != 0
    assert not dest.exists()
    assert identity_snapshot(live) == live_before
    assert identity_snapshot(backup) == backup_before
    _assert_no_real_home_writes(decoy)
