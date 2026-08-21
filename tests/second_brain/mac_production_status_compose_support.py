"""Helpers for Mac production post-SERVING_READY compose status tests."""
from __future__ import annotations

import hashlib
from datetime import datetime, tzinfo
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_persistence_support import MintCall
from tests.second_brain.mac_production_status_serving_support import (
    PINNED_WORKSPACE,
    bomb_product_constructors,
    pin_workspace,
    sqlite_path,
    write_lifecycle_database,
    write_verified_artifacts,
)
from tests.second_brain.mac_production_status_support import (
    bomb,
    isolate_home,
    marked_root,
)
from tests.second_brain.test_mac_signed_authority_bundle import (
    NOW,
    TRUSTED,
    bundle_bytes,
)
from wiki_spike.applications.mac_signed_authority_bundle_verify import (
    verify_mac_signed_authority_bundle,
)
from wiki_spike.composition import mac_production_compose as compose_mod
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
)

CAS_TOKEN = "existing CAS"
KEYCHAIN_TOKEN = "existing Keychain"
BIND_TOKEN = "an initialized exact LifecycleDatabase is required"
STAGE3_TOKEN = "trusted Stage-3 authority dependencies are required"
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


class FixtureRecallVerifier:
    def verify_signed_bytes(
        self,
        *,
        signer_ref: str,
        algorithm: str,
        key_id: str,
        signature: str,
        payload: bytes,
    ) -> bool:
        _ = signer_ref, algorithm, key_id, signature, payload
        return True


def fixture_clock() -> str:
    return "2026-01-01T00:00:00Z"


def fixture_snapshot_signer(payload: bytes) -> str:
    _ = payload
    return "fixture"


STAGE3_PIN_NAMES = (
    "PINNED_RECALL_VERIFIER",
    "PINNED_CLOCK",
    "PINNED_PROVENANCE",
    "PINNED_SNAPSHOT_SIGNER",
    "PINNED_SIGNER_REF",
    "PINNED_KEY_ID",
)


def freeze_trusted_now(monkeypatch: pytest.MonkeyPatch) -> None:
    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> datetime:
            return NOW if tz is None else NOW.astimezone(tz)

    monkeypatch.setattr(
        "wiki_spike.memory_core.second_brain_contracts.datetime",
        FrozenDateTime,
    )
    monkeypatch.setattr(
        "wiki_spike.memory_core.second_brain_security_contracts.datetime",
        FrozenDateTime,
    )


def pin_stage3(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compose_mod, "PINNED_RECALL_VERIFIER", FixtureRecallVerifier())
    monkeypatch.setattr(compose_mod, "PINNED_CLOCK", fixture_clock)
    monkeypatch.setattr(compose_mod, "PINNED_PROVENANCE", {})
    monkeypatch.setattr(compose_mod, "PINNED_SNAPSHOT_SIGNER", fixture_snapshot_signer)
    monkeypatch.setattr(compose_mod, "PINNED_SIGNER_REF", "signer:fixture")
    monkeypatch.setattr(compose_mod, "PINNED_KEY_ID", "key:fixture")


def ready_cas_keychain_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    write_serving_ready(home)
    write_cas_layout(home)
    write_keychain_layout(home)
    pin_and_bomb(monkeypatch)
    return marked_root(tmp_path)


def assert_minted_from_bundle(minted: list[MintCall], authority: object) -> None:
    assert len(minted) == 1
    decisions, scope, expected, aggregate, keys, now = minted[0]
    bundle = verify_mac_signed_authority_bundle(bundle_bytes(), TRUSTED, now=NOW)
    assert [item.to_mapping() for item in decisions] == [
        item.record.to_mapping() for item in bundle.decision_records
    ]
    assert scope.to_mapping() == bundle.aggregate.contract.resolved_scope.to_mapping()
    assert (
        expected.to_mapping()
        == bundle.aggregate.contract.expected_scope_manifest.to_mapping()
    )
    assert aggregate.to_mapping() == bundle.aggregate.to_mapping()
    assert keys is TRUSTED
    assert now == NOW
    assert isinstance(authority, SecurityContextAuthority)
