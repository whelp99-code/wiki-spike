"""Create-only atomic publication probes for public CLI writes."""
from __future__ import annotations

import os
from pathlib import Path
from threading import Thread

import pytest

from wiki_spike.applications.unified_db_export_authorization_publish import (
    publish_exclusive_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_publish_creates_new_file_and_refuses_existing(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    publish_exclusive_bytes(dest, b"alpha")
    assert dest.read_bytes() == b"alpha"
    with pytest.raises(UnifiedDbExportError, match="exists|overwrite"):
        publish_exclusive_bytes(dest, b"beta")
    assert dest.read_bytes() == b"alpha"


def test_publish_rejects_symlink_ancestor_and_leaves_real_path(tmp_path: Path) -> None:
    real = tmp_path / "real"
    _ = (real / "sub").mkdir(parents=True)
    victim = real / "sub" / "out.bin"
    _ = victim.write_bytes(b"keep")
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    planted = alias / "sub" / "out.bin"
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        publish_exclusive_bytes(planted, b"pwn")
    assert victim.read_bytes() == b"keep"
    assert not any(path.name.startswith(".") for path in (real / "sub").iterdir())


def test_publish_refuses_planted_symlink_and_leaves_victim(tmp_path: Path) -> None:
    victim = tmp_path / "victim.bin"
    _ = victim.write_bytes(b"keep-me")
    planted = tmp_path / "out.bin"
    planted.symlink_to(victim)
    with pytest.raises(UnifiedDbExportError, match="exists|symlink|overwrite"):
        publish_exclusive_bytes(planted, b"pwn")
    assert victim.read_bytes() == b"keep-me"
    assert planted.is_symlink()


def test_publish_link_fault_leaves_no_dest_or_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = tmp_path / "out.bin"

    def boom(source: str, target: str) -> None:
        _ = source
        _ = target
        raise OSError("link failed")

    monkeypatch.setattr("os.link", boom)
    with pytest.raises(UnifiedDbExportError):
        publish_exclusive_bytes(dest, b"data")
    assert not dest.exists()
    leftovers = [path for path in tmp_path.iterdir() if path.name.startswith(".")]
    assert leftovers == []


def test_publish_fsync_fault_leaves_no_valid_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    dest = tmp_path / "out.bin"
    real_fsync = os.fsync
    calls = {"n": 0}

    def flaky(fd: int) -> None:
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("fsync failed")
        real_fsync(fd)

    monkeypatch.setattr("os.fsync", flaky)
    with pytest.raises(UnifiedDbExportError):
        publish_exclusive_bytes(dest, b"data")
    assert not dest.exists()
    leftovers = [path for path in tmp_path.iterdir() if path.name.startswith(".")]
    assert leftovers == []


def test_publish_race_creates_exactly_one_file(tmp_path: Path) -> None:
    dest = tmp_path / "out.bin"
    errors: list[str] = []

    def attempt(payload: bytes) -> None:
        try:
            publish_exclusive_bytes(dest, payload)
        except UnifiedDbExportError:
            errors.append("exists")

    workers = [
        Thread(target=attempt, args=(b"one",)),
        Thread(target=attempt, args=(b"two",)),
    ]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()
    assert dest.is_file()
    assert dest.read_bytes() in {b"one", b"two"}
    assert len(errors) == 1
