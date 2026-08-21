"""Authorized import refuses unless resolver_outcome is RESOLVED."""
from __future__ import annotations

import json
import os
from pathlib import Path

from tests.second_brain.mac_production_status_support import tree_snapshot

CLI = Path("scripts/second_brain_authorized_import.py")


def _run(argv: list[str]) -> int:
    from scripts.second_brain_authorized_import import main

    return main(argv)


def _write_receipt(path: Path, outcome: str) -> None:
    payload = {
        "live_operation_authorized": "false",
        "resolver_outcome": outcome,
        "stage0_contract_usable": "false",
    }
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")


def test_missing_resolution_receipt_refuses_without_writes(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.md").write_text("keep\n", encoding="utf-8")
    dest = tmp_path / "dest"
    receipt = tmp_path / "missing-receipt.json"
    before = tree_snapshot(source)

    code = _run(
        [
            "--resolution-receipt",
            str(receipt),
            "--source-root",
            str(source),
            "--dest",
            str(dest),
        ]
    )

    assert code != 0
    assert not dest.exists()
    assert tree_snapshot(source) == before


def test_unresolved_receipt_refuses_without_source_mutation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    marker = source / "note.md"
    marker.write_text("keep\n", encoding="utf-8")
    dest = tmp_path / "dest"
    receipt = tmp_path / "receipt.json"
    _write_receipt(receipt, "FAIL_CLOSED")
    before = tree_snapshot(source)
    before_ino = os.lstat(marker).st_ino
    before_mtime = os.lstat(marker).st_mtime_ns

    code = _run(
        [
            "--resolution-receipt",
            str(receipt),
            "--source-root",
            str(source),
            "--dest",
            str(dest),
        ]
    )

    assert code != 0
    assert not dest.exists()
    assert tree_snapshot(source) == before
    assert os.lstat(marker).st_ino == before_ino
    assert os.lstat(marker).st_mtime_ns == before_mtime


def test_resolved_receipt_does_not_write_dest_in_this_increment(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "note.md").write_text("keep\n", encoding="utf-8")
    dest = tmp_path / "dest"
    receipt = tmp_path / "receipt.json"
    _write_receipt(receipt, "RESOLVED")
    before = tree_snapshot(source)

    code = _run(
        [
            "--resolution-receipt",
            str(receipt),
            "--source-root",
            str(source),
            "--dest",
            str(dest),
        ]
    )

    assert code != 0
    assert not dest.exists()
    assert tree_snapshot(source) == before
