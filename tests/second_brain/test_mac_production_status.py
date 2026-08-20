"""Unauthorized Mac status must refuse before any production storage exists."""
from __future__ import annotations

import socket
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_support import (
    passwd_lookup,
    tree_snapshot,
)
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

AUTHORITY_REQUIRED_TOKEN = "authority is required"
SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"
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


def _storage_paths(root: Path) -> list[str]:
    found: list[str] = []
    for path in root.rglob("*"):
        name = path.name.lower()
        if name in STORAGE_DIR_NAMES or Path(name).suffix.lower() in STORAGE_SUFFIXES:
            found.append(path.relative_to(root).as_posix())
    return found


def _bomb(*_args: str | bytes | Path, **_kwargs: str | bytes | Path) -> None:
    raise AssertionError("Mac status must refuse before constructing storage")


def _isolate_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(home))


def _bomb_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LifecycleDatabase, "__init__", _bomb)
    monkeypatch.setattr(EncryptedContentStore, "__init__", _bomb)
    monkeypatch.setattr(MacOSKeychainKeyStore, "__init__", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "_run", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "add", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "read", _bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "delete", _bomb)


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


@pytest.mark.parametrize(
    "token",
    [
        SIGNED_AUTHORITY_ABSENT_TOKEN,
        PERSISTENCE_PROFILE_ABSENT_TOKEN,
        SERVING_READY_ABSENT_TOKEN,
    ],
)
def test_status_refuses_when_production_artifact_is_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    token: str,
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    _bomb_storage(monkeypatch)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert token in captured.err


def test_status_leaves_passwd_home_application_support_uncreated_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    root = _marked_root(tmp_path)
    _bomb_storage(monkeypatch)
    env_home = tmp_path / "home"
    before_passwd = tree_snapshot(passwd_home)
    before_env = tree_snapshot(env_home)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert SIGNED_AUTHORITY_ABSENT_TOKEN in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN in captured.err
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert tree_snapshot(passwd_home) == before_passwd
    assert tree_snapshot(env_home) == before_env
    assert not (passwd_home / "Library").exists()


def test_status_ignores_home_env_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    _ = (home_env / "keep.txt").write_bytes(b"untouched")
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    root = _marked_root(tmp_path)
    _bomb_storage(monkeypatch)
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = main(["--root", str(root), "status"])

    _ = capsys.readouterr()
    assert code == 1
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
    assert not (home_env / "Library").exists()
    assert not (passwd_home / "Library" / "Application Support" / "wiki-spike").exists()


def test_status_keeps_recursive_byte_and_mode_tree_when_unauthorized(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    assert code == 1
    assert tree_snapshot(tmp_path) == before
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
    _bomb_storage(monkeypatch)

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
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert "workspace root denied: unknown" in captured.err
    assert tree_snapshot(tmp_path) == before
    assert list(target.iterdir()) == []


def test_status_denies_mixed_root_without_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    _ = (root / "control.sqlite").write_bytes(b"legacy plaintext")
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert "workspace root denied: mixed" in captured.err
    assert tree_snapshot(tmp_path) == before
    assert _storage_paths(tmp_path) == ["mac-root/control.sqlite"]


def test_status_denies_mixed_marker_plus_extra_file_without_writes_or_constructors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    _ = (root / "extra").write_bytes(b"foreign extra")
    _bomb_storage(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert "workspace root denied: mixed" in captured.err
    assert tree_snapshot(tmp_path) == before
