"""Unauthorized Mac status must refuse before any production storage exists."""
from __future__ import annotations

import ast
import os
import socket
import stat
from pathlib import Path

import pytest

from wiki_spike.composition.mac_production import main
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.macos_keychain import MacOSKeychainKeyStore
from wiki_spike.infrastructure.macos_keychain_backend import SecurityCliKeychainBackend
from wiki_spike.workspace_format import (
    WORKSPACE_FORMAT_FILENAME,
    ProfileSelection,
    WorkspaceFormatMarker,
)

COMPOSITION = Path("src/wiki_spike/composition/mac_production.py")
PYPROJECT = Path("pyproject.toml")
AUTHORITY_REQUIRED_TOKEN = "authority is required"
BANNED_IMPORTS = {
    "http",
    "importlib",
    "multiprocessing",
    "requests",
    "socket",
    "sqlite3",
    "subprocess",
    "urllib",
    "wiki_spike.infrastructure.encrypted_cas",
    "wiki_spike.infrastructure.lifecycle_db",
    "wiki_spike.infrastructure.macos_keychain",
    "wiki_spike.infrastructure.macos_keychain_backend",
}
STORAGE_DIR_NAMES = frozenset({"cas", "keychain", "keychains", "objects", "tombstones"})
STORAGE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})


def _marked_root(tmp_path: Path) -> Path:
    root = tmp_path / "mac-root"
    root.mkdir()
    marker = WorkspaceFormatMarker.create(
        workspace_id="mac-root",
        profile_selection=ProfileSelection.FIELD_AEAD,
        encrypted_lifecycle_enabled=True,
    )
    _ = (root / WORKSPACE_FORMAT_FILENAME).write_bytes(marker.canonical_bytes())
    return root


def _tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
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


def _storage_paths(root: Path) -> list[str]:
    found: list[str] = []
    for path in root.rglob("*"):
        name = path.name.lower()
        if name in STORAGE_DIR_NAMES or Path(name).suffix.lower() in STORAGE_SUFFIXES:
            found.append(path.relative_to(root).as_posix())
    return found


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"__import__", "eval", "exec"}:
                names.add(node.func.id)
    return names


def _bomb(*_args: str | bytes | Path, **_kwargs: str | bytes | Path) -> None:
    raise AssertionError("Mac status must refuse before constructing storage")


def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))


def test_status_exits_with_authority_required_when_marker_only_root_has_no_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert AUTHORITY_REQUIRED_TOKEN in captured.err


def test_status_keeps_recursive_byte_and_mode_tree_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    before = _tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    assert code == 1
    assert _tree_snapshot(tmp_path) == before
    _ = capsys.readouterr()


def test_status_creates_no_sqlite_cas_or_keychain_dirs_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)

    code = main(["--root", str(root), "status"])

    assert code == 1
    assert _storage_paths(tmp_path) == []
    _ = capsys.readouterr()


def test_status_refuses_before_constructing_db_cas_or_keychain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    monkeypatch.setattr(LifecycleDatabase, "__init__", _bomb)
    monkeypatch.setattr(EncryptedContentStore, "__init__", _bomb)
    monkeypatch.setattr(MacOSKeychainKeyStore, "__init__", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "_run", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "add", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "read", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "delete", _bomb)

    code = main(["--root", str(root), "status"])

    assert code == 1
    assert AUTHORITY_REQUIRED_TOKEN in capsys.readouterr().err


def test_status_does_not_listen_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    monkeypatch.setattr(socket.socket, "bind", _bomb)
    monkeypatch.setattr(socket.socket, "listen", _bomb)

    code = main(["--root", str(root), "status"])

    assert code == 1
    _ = capsys.readouterr()


def test_status_denies_symlink_root_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    target = tmp_path / "target"
    target.mkdir()
    root = tmp_path / "root-link"
    root.symlink_to(target, target_is_directory=True)
    before = _tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert "workspace root denied: unknown" in captured.err
    assert _tree_snapshot(tmp_path) == before
    assert list(target.iterdir()) == []


def test_status_denies_mixed_root_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    _ = (root / "control.sqlite").write_bytes(b"legacy plaintext")
    before = _tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert "workspace root denied: mixed" in captured.err
    assert _tree_snapshot(tmp_path) == before
    assert _storage_paths(tmp_path) == ["mac-root/control.sqlite"]


def test_mac_production_does_not_import_storage_or_network_constructors() -> None:
    imported = _imported(COMPOSITION)
    assert BANNED_IMPORTS.isdisjoint(imported), sorted(imported & BANNED_IMPORTS)


def test_installed_wiki_entry_points_at_mac_production_main() -> None:
    assert 'wiki = "wiki_spike.composition.mac_production:main"' in PYPROJECT.read_text(
        encoding="utf-8"
    )
