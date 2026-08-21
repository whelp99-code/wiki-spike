"""After SERVING_READY inspect, existing CAS/Keychain/bind must fail closed."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_compose_support import (
    AUTHORITY_REQUIRED_TOKEN,
    BIND_TOKEN,
    CAS_TOKEN,
    KEYCHAIN_TOKEN,
    PRODUCT_READY,
    SERVING_READY_ABSENT_TOKEN,
    SIGNED_AUTHORITY_ABSENT_TOKEN,
    STAGE3_PIN_NAMES,
    STAGE3_TOKEN,
    assert_minted_from_bundle,
    bomb_existing_opens,
    cas_root,
    compose_mod,
    freeze_trusted_now,
    pin_and_bomb,
    pin_stage3,
    ready_cas_keychain_root,
    write_cas_layout,
    write_keychain_layout,
    write_serving_ready,
)
from tests.second_brain.mac_production_status_persistence_support import track_mint
from tests.second_brain.mac_production_status_serving_support import (
    sqlite_path,
    write_lifecycle_database,
    write_verified_artifacts,
)
from tests.second_brain.mac_production_status_support import (
    isolate_home,
    marked_root,
    passwd_lookup,
    tree_snapshot,
)
from wiki_spike.composition.mac_production import main
from wiki_spike.composition.mac_production_compose import compose_existing_mac_product
from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
)


def _status(root: Path) -> int:
    return main(["--root", str(root), "status"])


def test_status_refuses_missing_cas_after_serving_ready_without_constructors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_serving_ready(home)
    root = marked_root(tmp_path)
    pin_and_bomb(monkeypatch)
    seen: list[Path] = []
    real_open = EncryptedContentStore.open_existing

    def recording(cas_path: Path) -> EncryptedContentStore:
        seen.append(cas_path)
        return real_open(cas_path)

    monkeypatch.setattr(EncryptedContentStore, "open_existing", recording)
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert seen == [cas_root(home)]
    assert CAS_TOKEN in captured.err
    assert KEYCHAIN_TOKEN not in captured.err
    assert BIND_TOKEN not in captured.err
    assert AUTHORITY_REQUIRED_TOKEN not in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert SERVING_READY_ABSENT_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_refuses_missing_keychain_after_cas_without_constructors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_serving_ready(home)
    _ = write_cas_layout(home)
    root = marked_root(tmp_path)
    pin_and_bomb(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert KEYCHAIN_TOKEN in captured.err
    assert CAS_TOKEN not in captured.err
    assert BIND_TOKEN not in captured.err
    assert AUTHORITY_REQUIRED_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_refuses_unset_stage3_pins_after_existing_cas_keychain_bind(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "wiki_spike.infrastructure.macos_keychain_existing.sys.platform",
        "linux",
    )
    root = ready_cas_keychain_root(tmp_path, monkeypatch)
    minted = track_mint(monkeypatch)
    seen: dict[str, object] = {}
    real_compose = compose_existing_mac_product

    def wrapping(
        *,
        v1_dir: Path,
        database: LifecycleDatabase,
        authorization: object,
        workspace_ref: str,
        keychain_directory: Path,
        authority: SecurityContextAuthority,
    ) -> SecondBrainProductV2:
        seen["authority"] = authority
        return real_compose(
            v1_dir=v1_dir,
            database=database,
            authorization=authorization,
            workspace_ref=workspace_ref,
            keychain_directory=keychain_directory,
            authority=authority,
        )

    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.compose_existing_mac_product",
        wrapping,
    )
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert_minted_from_bundle(minted, seen.get("authority"))
    assert STAGE3_TOKEN in captured.err
    assert BIND_TOKEN not in captured.err
    assert CAS_TOKEN not in captured.err
    assert KEYCHAIN_TOKEN not in captured.err
    assert AUTHORITY_REQUIRED_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_mac_production_compose_does_not_pin_security_authority() -> None:
    source = Path("src/wiki_spike/composition/mac_production_compose.py").read_text(
        encoding="utf-8"
    )
    assert "PINNED_SECURITY_AUTHORITY" not in source


def test_status_does_not_open_cas_or_keychain_when_serving_inspect_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_verified_artifacts(home)
    write_lifecycle_database(sqlite_path(home), authority_state="INACTIVE")
    _ = write_cas_layout(home)
    _ = write_keychain_layout(home)
    root = marked_root(tmp_path)
    pin_and_bomb(monkeypatch)
    bomb_existing_opens(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert "not ACTIVE" in captured.err
    assert CAS_TOKEN not in captured.err
    assert KEYCHAIN_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_ignores_home_env_cas_and_keychain_after_serving_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    write_serving_ready(home_env)
    _ = write_cas_layout(home_env)
    _ = write_keychain_layout(home_env)
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    write_serving_ready(passwd_home)
    root = marked_root(tmp_path)
    pin_and_bomb(monkeypatch)
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert CAS_TOKEN in captured.err
    assert KEYCHAIN_TOKEN not in captured.err
    assert BIND_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd


def test_status_prints_product_ready_when_stage3_pins_are_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        "wiki_spike.infrastructure.macos_keychain_existing.sys.platform",
        "linux",
    )
    root = ready_cas_keychain_root(tmp_path, monkeypatch)
    pin_stage3(monkeypatch)
    freeze_trusted_now(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 0
    assert PRODUCT_READY in captured.out
    assert STAGE3_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before


def test_production_compose_stage3_pins_remain_none() -> None:
    for name in STAGE3_PIN_NAMES:
        assert getattr(compose_mod, name) is None
