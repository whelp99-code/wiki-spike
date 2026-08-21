"""Present Mac signed-authority files are verified before storage constructors."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_persistence_support import (
    pin_trusted,
    signed_persistence_pair,
    write_closed_artifacts,
)
from tests.second_brain.mac_production_status_support import (
    bomb_storage,
    isolate_home,
    marked_root,
    passwd_lookup,
    tree_snapshot,
)
from tests.second_brain.test_mac_signed_authority_bundle import bundle_bytes
from wiki_spike.composition.mac_production import main

SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"
MISSING_FIELDS_TOKEN = "missing required fields"
UNTRUSTED_TOKEN = "untrusted"
INVALID_AUTHORITY = b"{}"


def _write_closed_artifacts(home: Path, authority: bytes) -> None:
    closed = (
        home
        / "Library"
        / "Application Support"
        / "wiki-spike"
        / "second-brain-v1"
    )
    closed.mkdir(parents=True)
    _ = (closed / "signed-authority.json").write_bytes(authority)
    _ = (closed / "persistence-profile.json").write_bytes(b"{}")
    _ = (closed / "persistence-receipt.json").write_bytes(b"{}")


def test_status_refuses_invalid_present_authority_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    _write_closed_artifacts(home, INVALID_AUTHORITY)
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert MISSING_FIELDS_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert "authenticated V2 product ready" not in captured.out


def test_status_refuses_untrusted_present_authority_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    _write_closed_artifacts(home, bundle_bytes())
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert UNTRUSTED_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert "authenticated V2 product ready" not in captured.out


def test_status_does_not_compose_when_present_authority_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    profile, receipt = signed_persistence_pair()
    write_closed_artifacts(
        tmp_path / "home",
        authority=bundle_bytes(),
        profile=profile,
        receipt=receipt,
    )
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert "authenticated V2 product ready" not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_ignores_home_env_authority_and_does_not_create_passwd_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    _write_closed_artifacts(home_env, INVALID_AUTHORITY)
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert SIGNED_AUTHORITY_ABSENT_TOKEN in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN in captured.err
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert MISSING_FIELDS_TOKEN not in captured.err
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
    assert not (passwd_home / "Library").exists()


def test_status_verifies_passwd_home_authority_and_ignores_home_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    _write_closed_artifacts(home_env, bundle_bytes())
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    _write_closed_artifacts(passwd_home, INVALID_AUTHORITY)
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert MISSING_FIELDS_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
