"""Present Mac persistence profile/receipt files are verified before storage."""
from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.mac_production_status_persistence_support import (
    INVALID_PROFILE,
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
from tests.second_brain.test_macos_persistence_profile import persistence_profile
from wiki_spike.composition.mac_production import main
from wiki_spike.memory_core.contracts import canonical_bytes

AUTHORITY_REQUIRED_TOKEN = "authority is required"
SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"
INVALID_FIELDS_TOKEN = "contract fields invalid"
UNTRUSTED_TOKEN = "signature verification failed"
MISMATCH_TOKEN = "does not authorize the selected profile"


def test_status_refuses_invalid_present_profile_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    write_closed_artifacts(
        tmp_path / "home",
        authority=bundle_bytes(),
        profile=INVALID_PROFILE,
        receipt=INVALID_PROFILE,
    )
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert INVALID_FIELDS_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert "authenticated V2 product ready" not in captured.out


def test_status_refuses_untrusted_present_profile_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    profile, receipt = signed_persistence_pair(
        Ed25519PrivateKey.generate(),
        Ed25519PrivateKey.generate(),
    )
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
    assert UNTRUSTED_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert "authenticated V2 product ready" not in captured.out


def test_status_refuses_mismatched_present_profile_and_receipt_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    profile = persistence_profile(sqlcipher_artifact_digest="0" * 64)
    _, receipt = signed_persistence_pair()
    write_closed_artifacts(
        tmp_path / "home",
        authority=bundle_bytes(),
        profile=canonical_bytes(profile.to_mapping()),
        receipt=receipt,
    )
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert MISMATCH_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert "authenticated V2 product ready" not in captured.out


def test_status_does_not_compose_when_present_profile_verifies(
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
    assert AUTHORITY_REQUIRED_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN not in captured.err
    assert "authenticated V2 product ready" not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_ignores_home_env_profile_and_does_not_create_passwd_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    write_closed_artifacts(
        home_env,
        authority=bundle_bytes(),
        profile=INVALID_PROFILE,
        receipt=INVALID_PROFILE,
    )
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
    assert INVALID_FIELDS_TOKEN not in captured.err
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
    assert not (passwd_home / "Library").exists()


def test_status_verifies_passwd_home_profile_and_ignores_home_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    profile, receipt = signed_persistence_pair()
    write_closed_artifacts(
        home_env, authority=bundle_bytes(), profile=profile, receipt=receipt
    )
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    write_closed_artifacts(
        passwd_home,
        authority=bundle_bytes(),
        profile=INVALID_PROFILE,
        receipt=INVALID_PROFILE,
    )
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert INVALID_FIELDS_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
