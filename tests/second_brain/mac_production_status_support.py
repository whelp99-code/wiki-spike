"""Helpers for unauthorized Mac production status tests."""
from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.macos_keychain import MacOSKeychainKeyStore
from wiki_spike.infrastructure.macos_keychain_backend import SecurityCliKeychainBackend
from wiki_spike.workspace_format import (
    WORKSPACE_FORMAT_FILENAME,
    ProfileSelection,
    WorkspaceFormatMarker,
)


@dataclass(frozen=True, slots=True)
class PasswdRecord:
    pw_dir: str


def passwd_lookup(home: Path) -> Callable[[int], PasswdRecord]:
    """Return a getpwuid stand-in whose pw_dir is ``home``."""

    def lookup(uid: int) -> PasswdRecord:
        _ = uid
        return PasswdRecord(pw_dir=str(home))

    return lookup


def marked_root(tmp_path: Path) -> Path:
    root = tmp_path / "mac-root"
    root.mkdir()
    marker = WorkspaceFormatMarker.create(
        workspace_id="mac-root",
        profile_selection=ProfileSelection.FIELD_AEAD,
        encrypted_lifecycle_enabled=True,
    )
    _ = (root / WORKSPACE_FORMAT_FILENAME).write_bytes(marker.canonical_bytes())
    return root


def isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(home))


def bomb(*_args: str | bytes | Path, **_kwargs: str | bytes | Path) -> None:
    raise AssertionError("Mac status must refuse before constructing storage")


def bomb_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LifecycleDatabase, "__init__", bomb)
    monkeypatch.setattr(EncryptedContentStore, "__init__", bomb)
    monkeypatch.setattr(MacOSKeychainKeyStore, "__init__", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "_run", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "add", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "read", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "delete", bomb)


def tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
    """Capture relative paths with type, mode, and file bytes or link targets."""
    snapshot: dict[str, tuple[str, int, bytes | None]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        relative_dir = directory.relative_to(root).as_posix()
        if relative_dir != ".":
            meta = os.lstat(directory)
            snapshot[relative_dir] = ("dir", stat.S_IMODE(meta.st_mode), None)
        for name in sorted(dirnames + filenames):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if relative in snapshot:
                continue
            meta = os.lstat(path)
            mode = stat.S_IMODE(meta.st_mode)
            if stat.S_ISLNK(meta.st_mode):
                snapshot[relative] = ("lnk", mode, os.readlink(path).encode())
            elif stat.S_ISDIR(meta.st_mode):
                snapshot[relative] = ("dir", mode, None)
            elif stat.S_ISREG(meta.st_mode):
                snapshot[relative] = ("reg", mode, path.read_bytes())
            else:
                snapshot[relative] = ("other", mode, None)
    return snapshot
