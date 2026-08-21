"""Helpers for Mac production SERVING_READY lifecycle status tests."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_persistence_support import (
    pin_trusted,
    signed_persistence_pair,
    write_closed_artifacts,
)
from tests.second_brain.mac_production_status_support import bomb
from tests.second_brain.test_mac_signed_authority_bundle import bundle_bytes
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.macos_keychain import MacOSKeychainKeyStore
from wiki_spike.infrastructure.macos_keychain_backend import SecurityCliKeychainBackend

PINNED_WORKSPACE = "workspace:" + "ab" * 32


def sqlite_path(home: Path) -> Path:
    return (
        home
        / "Library"
        / "Application Support"
        / "wiki-spike"
        / "second-brain-v1"
        / "lifecycle.sqlite3"
    )


def write_verified_artifacts(home: Path) -> None:
    profile, receipt = signed_persistence_pair()
    write_closed_artifacts(
        home,
        authority=bundle_bytes(),
        profile=profile,
        receipt=receipt,
    )


def pin_workspace(monkeypatch: pytest.MonkeyPatch) -> None:
    pin_trusted(monkeypatch)
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.PINNED_WORKSPACE_REF",
        PINNED_WORKSPACE,
        raising=False,
    )


def write_lifecycle_database(
    path: Path,
    *,
    authority_state: str | None = "ACTIVE",
    migration_state: str | None = "SERVING_READY",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    database = LifecycleDatabase(path)
    database.initialize()
    assert database.con is not None
    if authority_state is not None:
        _ = database.con.execute(
            "INSERT INTO ledger_authority VALUES(?,?,?,?,?)",
            (
                PINNED_WORKSPACE,
                "capability:test",
                "1",
                authority_state,
                "2026-08-21T00:00:00Z",
            ),
        )
    if migration_state is not None:
        _ = database.con.execute(
            "INSERT INTO ledger_migration VALUES(?,?,?,?,?)",
            (
                "migration:test",
                PINNED_WORKSPACE,
                migration_state,
                "cd" * 32,
                "2026-08-21T00:00:01Z",
            ),
        )
    database.close()
    path.chmod(0o600)


def write_schema_drift(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path)
    _ = connection.execute(
        "CREATE TABLE ledger_authority(workspace_ref TEXT PRIMARY KEY)"
    )
    connection.close()
    path.chmod(0o600)


def bomb_product_constructors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(LifecycleDatabase, "initialize", bomb)
    monkeypatch.setattr(EncryptedContentStore, "__init__", bomb)
    monkeypatch.setattr(MacOSKeychainKeyStore, "__init__", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "_run", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "add", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "read", bomb)
    monkeypatch.setattr(SecurityCliKeychainBackend, "delete", bomb)
