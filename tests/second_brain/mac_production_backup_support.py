"""Helpers for fail-closed Mac production backup CLI tests."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_compose_support import (
    write_cas_layout,
    write_keychain_layout,
)
from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    sqlite_path,
    write_lifecycle_database,
)
from tests.second_brain.mac_production_status_support import bomb
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.macos_keychain_backend import SecurityCliKeychainBackend

CAS_OBJECT_NAME = "ab" * 32
CAS_OBJECT_BYTES = b"opaque-cas-object"


def identity_snapshot(root: Path) -> dict[str, tuple[int, int, int]]:
    """Capture relative paths with inode, mtime, and size. Never follows links."""
    snapshot: dict[str, tuple[int, int, int]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        for name in sorted(set(dirnames + filenames)):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            meta = os.lstat(path)
            snapshot[relative] = (meta.st_ino, meta.st_mtime_ns, meta.st_size)
    return snapshot


def write_backup_source(home: Path) -> Path:
    write_lifecycle_database(sqlite_path(home))
    cas = write_cas_layout(home)
    blob = cas / "objects" / CAS_OBJECT_NAME
    _ = blob.write_bytes(CAS_OBJECT_BYTES)
    blob.chmod(0o444)
    write_keychain_layout(home)
    return cas


def arm_bombs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LifecycleDatabase, "initialize", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "add", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "delete", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "_run", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "read", bomb)


def run_backup(home: Path, dest: Path) -> int:
    from scripts.second_brain_mac_backup import main

    return main(
        [
            "--passwd-home",
            str(home),
            "--workspace-ref",
            PINNED_WORKSPACE,
            "--dest",
            str(dest),
        ]
    )
