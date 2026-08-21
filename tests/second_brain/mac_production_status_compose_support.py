"""Helpers for Mac production post-SERVING_READY compose status tests."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    bomb_product_constructors,
    pin_workspace,
    sqlite_path,
    write_lifecycle_database,
    write_verified_artifacts,
)
from tests.second_brain.mac_production_status_support import bomb
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.memory_core.contracts import canonical_bytes

CAS_TOKEN = "existing CAS"
KEYCHAIN_TOKEN = "existing Keychain"
BIND_TOKEN = "an initialized exact LifecycleDatabase is required"
PRODUCT_READY = "authenticated V2 product ready"
AUTHORITY_REQUIRED_TOKEN = "authority is required"
SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"


def v1_dir(home: Path) -> Path:
    return home / "Library" / "Application Support" / "wiki-spike" / "second-brain-v1"


def cas_root(home: Path) -> Path:
    return v1_dir(home) / "cas"


def keychain_index(home: Path) -> Path:
    return v1_dir(home) / "keychain"


def keychain_directory(home: Path) -> Path:
    return home / "Library" / "Keychains"


def write_cas_layout(home: Path) -> Path:
    root = cas_root(home)
    root.mkdir(mode=0o700)
    (root / "objects").mkdir(mode=0o700)
    (root / "tombstones").mkdir(mode=0o700)
    for path in (root, root / "objects", root / "tombstones"):
        path.chmod(0o700)
    return root


def write_keychain_layout(home: Path, namespace: str = PINNED_WORKSPACE) -> Path:
    index_dir = keychain_index(home)
    index_dir.mkdir(mode=0o700)
    index_dir.chmod(0o700)
    keychain_dir = keychain_directory(home)
    keychain_dir.mkdir(mode=0o700)
    keychain_dir.chmod(0o700)
    account = hashlib.sha256(f"{namespace}\0serving-ark-v1".encode()).hexdigest()
    record = index_dir / f"{account}.json"
    _ = record.write_bytes(
        canonical_bytes(
            {
                "ark_handle": "serving-ark-v1",
                "destroyed": False,
                "destroyed_at": None,
                "metadata_digest": "cd" * 32,
                "namespace": namespace,
                "receipt_digest": None,
            }
        )
    )
    record.chmod(0o600)
    return index_dir


def write_serving_ready(home: Path) -> None:
    write_verified_artifacts(home)
    write_lifecycle_database(sqlite_path(home))


def pin_and_bomb(monkeypatch: pytest.MonkeyPatch) -> None:
    pin_workspace(monkeypatch)
    bomb_product_constructors(monkeypatch)
    monkeypatch.setattr(LifecycleLedgerAuthority, "set_authority", bomb)


def bomb_existing_opens(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(EncryptedContentStore, "open_existing", bomb)
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production_compose.open_existing_macos_keychain_store",
        bomb,
    )
