"""Existing-only Mac Keychain adapter admission never provisions or calls Keychain."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import override

import pytest

from wiki_spike.infrastructure.macos_keychain import (
    KeychainBackend,
    MacOSKeychainKeyStore,
    ProductionCustodyError,
)
from wiki_spike.infrastructure.macos_keychain_existing import (
    MAC_KEYCHAIN_SERVICE,
    SERVING_ARK_HANDLE,
    open_existing_macos_keychain_store,
)
from wiki_spike.memory_core.contracts import canonical_bytes

_NAMESPACE = "workspace:" + "ab" * 32
_METADATA_DIGEST = "cd" * 32


class RefusingBackend(KeychainBackend):
    @override
    def add(self, *, service: str, account: str, secret: str) -> bool:
        raise AssertionError("open_existing must not add Keychain items")

    @override
    def read(self, *, service: str, account: str) -> str | None:
        raise AssertionError("open_existing must not read Keychain items")

    @override
    def delete(self, *, service: str, account: str) -> bool:
        raise AssertionError("open_existing must not delete Keychain items")


def _layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    index_dir = tmp_path / "keychain-index"
    index_dir.mkdir(mode=0o700)
    keychain_dir = tmp_path / "Keychains"
    keychain_dir.mkdir(mode=0o700)
    account = hashlib.sha256(
        f"{_NAMESPACE}\0{SERVING_ARK_HANDLE}".encode()
    ).hexdigest()
    record = index_dir / f"{account}.json"
    _ = record.write_bytes(
        canonical_bytes(
            {
                "ark_handle": SERVING_ARK_HANDLE,
                "destroyed": False,
                "destroyed_at": None,
                "metadata_digest": _METADATA_DIGEST,
                "namespace": _NAMESPACE,
                "receipt_digest": None,
            }
        )
    )
    record.chmod(0o600)
    return index_dir, keychain_dir, record


def _snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    result: dict[str, tuple[int, bytes | None]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result[relative] = (stat.S_IMODE(metadata.st_mode), payload)
    return result


def test_open_existing_validates_index_without_backend_calls(
    tmp_path: Path,
) -> None:
    index_dir, keychain_dir, _record = _layout(tmp_path)
    before = _snapshot(tmp_path)

    store = open_existing_macos_keychain_store(
        index_dir=index_dir,
        service=MAC_KEYCHAIN_SERVICE,
        namespace=_NAMESPACE,
        ark_handle=SERVING_ARK_HANDLE,
        backend=RefusingBackend(),
        keychain_directory=keychain_dir,
    )

    assert type(store) is MacOSKeychainKeyStore
    assert store.index_dir == index_dir
    assert store.service == MAC_KEYCHAIN_SERVICE
    assert store.keychain_directory == keychain_dir
    assert _snapshot(tmp_path) == before


@pytest.mark.parametrize("missing", ["index", "record"])
def test_open_existing_refuses_missing_paths_without_creation(
    tmp_path: Path,
    missing: str,
) -> None:
    index_dir, keychain_dir, record = _layout(tmp_path)
    if missing == "index":
        record.unlink()
        index_dir.rmdir()
    else:
        record.unlink()

    with pytest.raises(ProductionCustodyError, match="existing Keychain"):
        _ = open_existing_macos_keychain_store(
            index_dir=index_dir,
            service=MAC_KEYCHAIN_SERVICE,
            namespace=_NAMESPACE,
            ark_handle=SERVING_ARK_HANDLE,
            backend=RefusingBackend(),
            keychain_directory=keychain_dir,
        )

    assert not record.exists()


@pytest.mark.parametrize("target", ["index", "record"])
def test_open_existing_refuses_symlink_paths(
    tmp_path: Path,
    target: str,
) -> None:
    index_dir, keychain_dir, record = _layout(tmp_path)
    if target == "index":
        real = tmp_path / "real-index"
        _ = index_dir.rename(real)
        index_dir.symlink_to(real, target_is_directory=True)
    else:
        real = tmp_path / "real-record"
        _ = record.rename(real)
        record.symlink_to(real)

    with pytest.raises(ProductionCustodyError, match="existing Keychain"):
        _ = open_existing_macos_keychain_store(
            index_dir=index_dir,
            service=MAC_KEYCHAIN_SERVICE,
            namespace=_NAMESPACE,
            ark_handle=SERVING_ARK_HANDLE,
            backend=RefusingBackend(),
            keychain_directory=keychain_dir,
        )


@pytest.mark.parametrize(("target", "mode"), [("index", 0o755), ("record", 0o644)])
def test_open_existing_refuses_bad_modes(
    tmp_path: Path,
    target: str,
    mode: int,
) -> None:
    index_dir, keychain_dir, record = _layout(tmp_path)
    (index_dir if target == "index" else record).chmod(mode)

    with pytest.raises(ProductionCustodyError, match="mode"):
        _ = open_existing_macos_keychain_store(
            index_dir=index_dir,
            service=MAC_KEYCHAIN_SERVICE,
            namespace=_NAMESPACE,
            ark_handle=SERVING_ARK_HANDLE,
            backend=RefusingBackend(),
            keychain_directory=keychain_dir,
        )


def test_open_existing_refuses_wrong_service_or_handle(tmp_path: Path) -> None:
    index_dir, keychain_dir, _record = _layout(tmp_path)
    for service, handle in (
        ("wiki-spike.other", SERVING_ARK_HANDLE),
        (MAC_KEYCHAIN_SERVICE, "other-handle"),
    ):
        with pytest.raises(ProductionCustodyError, match="fixed"):
            _ = open_existing_macos_keychain_store(
                index_dir=index_dir,
                service=service,
                namespace=_NAMESPACE,
                ark_handle=handle,
                backend=RefusingBackend(),
                keychain_directory=keychain_dir,
            )
