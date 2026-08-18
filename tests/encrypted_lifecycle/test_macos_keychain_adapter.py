from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import override

import pytest

from wiki_spike.infrastructure import macos_keychain
from wiki_spike.infrastructure.keystore import (
    KeyAlreadyExists,
    KeyDestroyed,
    PlatformKeyStore,
    RecoveryKeyStore,
)
from wiki_spike.infrastructure.macos_keychain import (
    KeychainBackend,
    MacOSKeychainKeyStore,
    ProductionCustodyError,
    require_macos_production_custody,
)

_NAMESPACE = "workspace:test"
_HANDLE = "ark:test"
_SERVICE = "wiki-spike.tests.macos-keychain"
_WRAPPED_DEK = "11" * 32
_OTHER_WRAPPED_DEK = "22" * 32
_METADATA_DIGEST = sha256(b"metadata").hexdigest()


@dataclass(slots=True)
class FakeKeychainBackend(KeychainBackend):
    items: dict[tuple[str, str], str] = field(default_factory=dict)

    @override
    def add(self, *, service: str, account: str, secret: str) -> bool:
        key = (service, account)
        if key in self.items:
            return False
        self.items[key] = secret
        return True

    @override
    def read(self, *, service: str, account: str) -> str | None:
        return self.items.get((service, account))

    @override
    def delete(self, *, service: str, account: str) -> bool:
        return self.items.pop((service, account), None) is not None


def _store(
    tmp_path: Path,
    backend: FakeKeychainBackend,
) -> MacOSKeychainKeyStore:
    keychain_directory = tmp_path / "Keychains"
    keychain_directory.mkdir()
    return MacOSKeychainKeyStore(
        index_dir=tmp_path / "keychain-index",
        service=_SERVICE,
        backend=backend,
        keychain_directory=keychain_directory,
    )


def test_keychain_adapter_preserves_create_only_readback_and_destroy(
    tmp_path: Path,
) -> None:
    backend = FakeKeychainBackend()
    store = _store(tmp_path, backend)

    created = store.create_only(
        _NAMESPACE,
        _HANDLE,
        _WRAPPED_DEK,
        _METADATA_DIGEST,
    )
    assert created.created is True
    assert created.already_exists is False
    assert list(backend.items.values()) == [_WRAPPED_DEK]

    repeated = store.create_only(
        _NAMESPACE,
        _HANDLE,
        _WRAPPED_DEK,
        _METADATA_DIGEST,
    )
    assert repeated.created is False
    assert repeated.already_exists is True
    with pytest.raises(KeyAlreadyExists):
        _ = store.create_only(
            _NAMESPACE,
            _HANDLE,
            _OTHER_WRAPPED_DEK,
            _METADATA_DIGEST,
        )

    receipt = store.readback_challenge(_NAMESPACE, _HANDLE)
    assert receipt.verified is True
    assert _WRAPPED_DEK not in repr(receipt)
    assert store.get_ark_dek(_NAMESPACE, _HANDLE) == bytes.fromhex(_WRAPPED_DEK)
    assert store.inventory(_NAMESPACE)[0].destroyed is False
    assert all(
        _WRAPPED_DEK not in path.read_text(encoding="utf-8")
        for path in store.index_dir.glob("*.json")
    )

    absence = store.destroy(_NAMESPACE, _HANDLE)
    assert absence.prior_metadata_digest == _METADATA_DIGEST
    assert backend.items == {}
    assert store.inventory(_NAMESPACE)[0].destroyed is True
    with pytest.raises(KeyDestroyed):
        _ = store.readback_challenge(_NAMESPACE, _HANDLE)
    with pytest.raises(KeyDestroyed):
        _ = store.create_only(
            _NAMESPACE,
            _HANDLE,
            _WRAPPED_DEK,
            _METADATA_DIGEST,
        )


def test_create_rolls_back_keychain_item_when_index_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeKeychainBackend()
    store = _store(tmp_path, backend)

    def fail_index_write(_path: Path, _payload: bytes) -> None:
        raise OSError("simulated index failure")

    monkeypatch.setattr(macos_keychain, "_write_exclusive", fail_index_write)
    with pytest.raises(ProductionCustodyError, match="metadata index"):
        _ = store.create_only(
            _NAMESPACE,
            _HANDLE,
            _WRAPPED_DEK,
            _METADATA_DIGEST,
        )

    assert backend.items == {}


def test_production_custody_rejects_file_backed_platform_store(
    tmp_path: Path,
) -> None:
    platform = PlatformKeyStore(tmp_path / "platform")
    recovery = RecoveryKeyStore(tmp_path / "recovery")

    with pytest.raises(ProductionCustodyError, match="macOS Keychain"):
        _ = require_macos_production_custody(platform=platform, recovery=recovery)


def test_production_custody_rejects_same_device_recovery(
    tmp_path: Path,
) -> None:
    platform = _store(tmp_path, FakeKeychainBackend())
    recovery = RecoveryKeyStore(tmp_path / "recovery")

    with pytest.raises(ProductionCustodyError, match="physically separate"):
        _ = require_macos_production_custody(platform=platform, recovery=recovery)


def test_production_custody_accepts_distinct_devices(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    platform = _store(tmp_path, FakeKeychainBackend())
    recovery = RecoveryKeyStore(tmp_path / "recovery")

    def distinct_device(path: Path) -> int:
        return 1 if path == platform.keychain_directory else 2

    monkeypatch.setattr(
        "wiki_spike.infrastructure.macos_keychain._device_id",
        distinct_device,
    )
    binding = require_macos_production_custody(
        platform=platform,
        recovery=recovery,
    )

    assert binding.separate_devices is True
    assert binding.platform_service == _SERVICE
    assert binding.platform_device != binding.recovery_device
