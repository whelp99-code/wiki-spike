"""Present Mac lifecycle DB is inspected for ACTIVE + SERVING_READY before composition."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_persistence_support import pin_trusted
from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    bomb_product_constructors,
    pin_workspace,
    sqlite_path,
    write_lifecycle_database,
    write_schema_drift,
    write_verified_artifacts,
)
from tests.second_brain.mac_production_status_support import (
    bomb,
    bomb_storage,
    isolate_home,
    marked_root,
    passwd_lookup,
    tree_snapshot,
)
from wiki_spike.composition.mac_production import main
from wiki_spike.infrastructure.lifecycle_db_existing import ExistingLifecycleDatabase
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready as real_inspect,
)

AUTHORITY_REQUIRED_TOKEN = "authority is required"
SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"
PRODUCT_READY = "authenticated V2 product ready"


def _status(root: Path) -> int:
    return main(["--root", str(root), "status"])


def test_status_does_not_open_sqlite_when_closed_artifacts_are_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.open_existing_lifecycle_database",
        bomb,
        raising=False,
    )
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert SIGNED_AUTHORITY_ABSENT_TOKEN in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN in captured.err
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert tree_snapshot(tmp_path) == before
    assert PRODUCT_READY not in captured.out


@pytest.mark.parametrize("kind", ["missing", "symlink", "directory"])
def test_status_refuses_non_regular_sqlite_after_persistence_verifies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_verified_artifacts(home)
    path = sqlite_path(home)
    if kind == "symlink":
        path.symlink_to(tmp_path / "missing-target")
    elif kind == "directory":
        path.mkdir()
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.open_existing_lifecycle_database",
        bomb,
        raising=False,
    )
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert PRODUCT_READY not in captured.out


@pytest.mark.parametrize(
    ("kind", "token"),
    [
        ("inactive", "not ACTIVE"),
        ("not_serving", "not SERVING_READY"),
        ("schema", "schema"),
        ("wal", "WAL"),
        ("unpinned", "invalid workspace ref"),
    ],
)
def test_status_refuses_existing_sqlite_that_is_not_serving_ready(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    kind: str,
    token: str,
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_verified_artifacts(home)
    path = sqlite_path(home)
    if kind == "schema":
        write_schema_drift(path)
    elif kind == "wal":
        write_lifecycle_database(path)
        _ = Path(f"{path}-wal").write_bytes(b"wal")
    elif kind == "inactive":
        write_lifecycle_database(path, authority_state="INACTIVE")
    elif kind == "not_serving":
        write_lifecycle_database(path, migration_state="READY_NON_SERVING")
    else:
        write_lifecycle_database(path)
    root = marked_root(tmp_path)
    bomb_product_constructors(monkeypatch)
    if kind == "unpinned":
        pin_trusted(monkeypatch)
    else:
        pin_workspace(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert token in captured.err
    assert AUTHORITY_REQUIRED_TOKEN not in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(tmp_path) == before
    assert PRODUCT_READY not in captured.out


def test_status_does_not_compose_when_serving_ready_inspects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_verified_artifacts(home)
    write_lifecycle_database(sqlite_path(home))
    root = marked_root(tmp_path)
    bomb_product_constructors(monkeypatch)
    pin_workspace(monkeypatch)
    seen: list[str] = []

    def recording(
        database: ExistingLifecycleDatabase, workspace_ref: str
    ) -> object:
        seen.append(workspace_ref)
        return real_inspect(database, workspace_ref)

    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.inspect_existing_serving_ready",
        recording,
        raising=False,
    )
    before = tree_snapshot(tmp_path)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert seen == [PINNED_WORKSPACE]
    assert "existing CAS" in captured.err
    assert AUTHORITY_REQUIRED_TOKEN not in captured.err
    assert SERVING_READY_ABSENT_TOKEN not in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN not in captured.err
    assert PRODUCT_READY not in captured.out
    assert tree_snapshot(tmp_path) == before


def test_status_inspects_passwd_home_sqlite_and_ignores_home_env(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    home_env = tmp_path / "home-env"
    home_env.mkdir()
    write_verified_artifacts(home_env)
    write_lifecycle_database(sqlite_path(home_env))
    monkeypatch.setenv("HOME", str(home_env))
    passwd_home = tmp_path / "passwd-home"
    passwd_home.mkdir()
    monkeypatch.setattr("pwd.getpwuid", passwd_lookup(passwd_home))
    write_verified_artifacts(passwd_home)
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    pin_trusted(monkeypatch)
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.open_existing_lifecycle_database",
        bomb,
        raising=False,
    )
    before_home = tree_snapshot(home_env)
    before_passwd = tree_snapshot(passwd_home)

    code = _status(root)

    captured = capsys.readouterr()
    assert code == 1
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert SIGNED_AUTHORITY_ABSENT_TOKEN not in captured.err
    assert tree_snapshot(home_env) == before_home
    assert tree_snapshot(passwd_home) == before_passwd
    assert PRODUCT_READY not in captured.out
