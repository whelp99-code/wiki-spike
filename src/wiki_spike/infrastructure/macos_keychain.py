from __future__ import annotations

import hashlib
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure import keystore as ks
from wiki_spike.infrastructure import macos_keychain_backend as _backend
from wiki_spike.memory_core.contracts import canonical_bytes

KeychainBackend = _backend.KeychainBackend
ProductionCustodyError = _backend.ProductionCustodyError
SecurityCliKeychainBackend = _backend.SecurityCliKeychainBackend

_OPAQUE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_INDEX = re.compile(r'^\{"ark_handle":"(?P<handle>[A-Za-z0-9._:-]{1,256})","destroyed":(?P<destroyed>true|false),"destroyed_at":(?P<destroyed_at>null|"[0-9TZ:-]+"),"metadata_digest":"(?P<metadata>[0-9a-f]{64})","namespace":"(?P<namespace>[A-Za-z0-9._:-]{1,256})","receipt_digest":(?P<receipt>null|"[0-9a-f]{64}")\}$')


@dataclass(frozen=True, slots=True)
class _IndexRecord:
    namespace: str
    ark_handle: str
    metadata_digest: str
    destroyed_at: str | None
    receipt_digest: str | None
    destroyed: bool

    def payload(self) -> bytes:
        return canonical_bytes({"namespace": self.namespace, "ark_handle": self.ark_handle,
            "metadata_digest": self.metadata_digest, "destroyed_at": self.destroyed_at,
            "receipt_digest": self.receipt_digest, "destroyed": self.destroyed})


class MacOSKeychainKeyStore:
    def __init__(
        self,
        index_dir: str | Path,
        service: str,
        backend: KeychainBackend | None = None,
        keychain_directory: str | Path | None = None,
    ) -> None:
        _validate_opaque("service", service)
        if backend is None:
            if sys.platform != "darwin":
                raise ProductionCustodyError("macOS Keychain custody requires Darwin")
            backend = SecurityCliKeychainBackend()
        self.index_dir: Path = Path(index_dir)
        created_index = not self.index_dir.exists()
        self.index_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.index_dir.chmod(0o700)
        if created_index:
            _fsync_directory(self.index_dir.parent)
        self.service: str = service
        self._backend: KeychainBackend = backend
        default_directory = Path.home() / "Library/Keychains"
        self.keychain_directory: Path = Path(
            keychain_directory if keychain_directory is not None else default_directory
        )

    def create_only(
        self, namespace: str, ark_handle: str, wrapped_dek_hex: str, metadata_digest: str
    ) -> ks.CreateOnlyResult:
        account = _account(namespace, ark_handle)
        _validate_digest("wrapped DEK", wrapped_dek_hex)
        _validate_digest("metadata digest", metadata_digest)
        existing = self._load(account)
        stored_value = self._backend.read(service=self.service, account=account)
        if existing is not None:
            if existing.destroyed:
                raise ks.KeyDestroyed("forward-only Keychain custody was destroyed")
            if stored_value is None:
                raise ks.KeyStoreCorrupt("active Keychain index has no matching item")
            if existing.metadata_digest != metadata_digest:
                raise ks.KeyCollision("Keychain handle is claimed by a different key intent")
            if stored_value != wrapped_dek_hex:
                raise ks.KeyAlreadyExists("Keychain create-only key material conflicts")
            return ks.CreateOnlyResult(created=False, already_exists=True)
        if stored_value is not None:
            raise ks.KeyStoreCorrupt("orphan Keychain item has no metadata index")
        if not self._backend.add(service=self.service, account=account, secret=
            wrapped_dek_hex):
            raise ks.KeyStoreCorrupt("Keychain item appeared during exclusive create")
        record = _IndexRecord(namespace, ark_handle, metadata_digest, None, None, False)
        try:
            _write_exclusive(self._path(account), record.payload())
        except OSError:
            try:
                rolled_back = self._backend.delete(
                    service=self.service,
                    account=account,
                )
            except ProductionCustodyError:
                raise ProductionCustodyError(
                    "metadata index create and Keychain rollback failed"
                ) from None
            if not rolled_back:
                raise ProductionCustodyError(
                    "metadata index create failed after Keychain item disappeared"
                ) from None
            raise ProductionCustodyError("metadata index create failed") from None
        return ks.CreateOnlyResult(created=True, already_exists=False)

    def readback_challenge(self, namespace: str, ark_handle: str) -> ks.ReadbackReceipt:
        record, dek_hex = self._active(namespace, ark_handle)
        dek = bytes.fromhex(dek_hex)
        aad = record.metadata_digest.encode("ascii")
        nonce_hex, challenge = os.urandom(12).hex(), os.urandom(32)
        ciphertext_hex, tag_hex = crypto.aes_gcm_seal(dek, nonce_hex, challenge, aad=aad)
        verified = crypto.aes_gcm_open(dek, nonce_hex, ciphertext_hex, tag_hex, aad=aad) == challenge
        digest = hashlib.sha256(
            canonical_bytes({"namespace": namespace, "ark_handle": ark_handle,
                "metadata_digest": record.metadata_digest, "nonce_hex": nonce_hex,
                "ciphertext_hex": ciphertext_hex, "tag_hex": tag_hex, "verified": verified})
        ).hexdigest()
        return ks.ReadbackReceipt(namespace, ark_handle, record.metadata_digest, digest, verified)

    def get_ark_dek(self, namespace: str, ark_handle: str) -> bytes:
        return bytes.fromhex(self._active(namespace, ark_handle)[1])

    def inventory(self, namespace: str) -> list[ks.InventoryEntry]:
        _validate_opaque("namespace", namespace)
        entries: list[ks.InventoryEntry] = []
        for path in sorted(self.index_dir.glob("*.json")):
            record = _read_record(path)
            account = _account(record.namespace, record.ark_handle)
            if not record.destroyed and self._backend.read(
                service=self.service, account=account
            ) is None:
                raise ks.KeyStoreCorrupt("active Keychain index has no matching item")
            if record.namespace == namespace:
                entries.append(ks.InventoryEntry(
                    record.namespace, record.ark_handle, record.metadata_digest, record.destroyed))
        return sorted(entries, key=lambda entry: entry.ark_handle)

    def destroy(self, namespace: str, ark_handle: str) -> ks.AbsenceReceipt:
        account = _account(namespace, ark_handle)
        record = self._load(account)
        if record is None:
            raise ks.KeyNotFound("Keychain custody metadata was not found")
        if record.destroyed:
            if record.destroyed_at is None or record.receipt_digest is None:
                raise ks.KeyStoreCorrupt("Keychain tombstone is incomplete")
            return ks.AbsenceReceipt(
                namespace, ark_handle, record.metadata_digest, record.destroyed_at, record.receipt_digest)
        if self._backend.read(service=self.service, account=account) is None:
            raise ks.KeyStoreCorrupt("active Keychain index has no matching item")
        if not self._backend.delete(service=self.service, account=account):
            raise ks.KeyStoreCorrupt("Keychain item disappeared during destroy")
        destroyed_at = _now()
        digest = hashlib.sha256(
            canonical_bytes({"namespace": namespace, "ark_handle": ark_handle,
                "prior_metadata_digest": record.metadata_digest, "destroyed_at": destroyed_at})
        ).hexdigest()
        tombstone = _IndexRecord(
            namespace, ark_handle, record.metadata_digest, destroyed_at, digest, True
        )
        _replace_atomic(self._path(account), tombstone.payload())
        return ks.AbsenceReceipt(namespace, ark_handle, record.metadata_digest, destroyed_at, digest)

    def _active(self, namespace: str, ark_handle: str) -> tuple[_IndexRecord, str]:
        account = _account(namespace, ark_handle)
        record = self._load(account)
        if record is None:
            raise ks.KeyNotFound("Keychain custody metadata was not found")
        if record.destroyed:
            raise ks.KeyDestroyed("forward-only Keychain custody was destroyed")
        stored_value = self._backend.read(service=self.service, account=account)
        if stored_value is None:
            raise ks.KeyStoreCorrupt("active Keychain index has no matching item")
        _validate_digest("stored Keychain key", stored_value)
        return record, stored_value

    def _load(self, account: str) -> _IndexRecord | None:
        path = self._path(account)
        return _read_record(path) if path.exists() else None

    def _path(self, account: str) -> Path:
        return self.index_dir / f"{account}.json"


@dataclass(frozen=True, slots=True)
class ProductionCustodyBinding:
    separate_devices: bool
    platform_service: str
    platform_device: int
    recovery_device: int


def require_macos_production_custody(
    platform: ks.KeyStore, recovery: ks.RecoveryKeyStore
) -> ProductionCustodyBinding:
    if not _is_exact_macos_store(platform):
        raise ProductionCustodyError("production platform custody must use macOS Keychain")
    platform_device = _device_id(platform.keychain_directory)
    recovery_device = _device_id(recovery.root_dir)
    if platform_device == recovery_device:
        raise ProductionCustodyError("recovery custody must be on a physically separate device")
    return ProductionCustodyBinding(True, platform.service, platform_device, recovery_device)


def _is_exact_macos_store(store: ks.KeyStore) -> TypeGuard[MacOSKeychainKeyStore]:
    return type(store) is MacOSKeychainKeyStore


def _device_id(path: Path) -> int:
    try:
        return path.stat().st_dev
    except OSError:
        raise ProductionCustodyError(
            "custody device identity could not be verified"
        ) from None


def _account(namespace: str, ark_handle: str) -> str:
    _validate_opaque("namespace", namespace)
    _validate_opaque("ark_handle", ark_handle)
    return hashlib.sha256(f"{namespace}\0{ark_handle}".encode()).hexdigest()


def _validate_opaque(name: str, value: str) -> None:
    if _OPAQUE.fullmatch(value) is None:
        raise ProductionCustodyError(f"invalid opaque {name}")


def _validate_digest(name: str, value: str) -> None:
    if _HEX_64.fullmatch(value) is None:
        raise ProductionCustodyError(f"invalid lowercase {name} hex")


def _read_record(path: Path) -> _IndexRecord:
    try:
        match = _INDEX.fullmatch(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ks.KeyStoreCorrupt("Keychain index is unreadable") from exc
    if match is None:
        raise ks.KeyStoreCorrupt("Keychain index is malformed or non-canonical")
    destroyed = match["destroyed"] == "true"
    destroyed_at = None if match["destroyed_at"] == "null" else match["destroyed_at"][1:-1]
    receipt_digest = None if match["receipt"] == "null" else match["receipt"][1:-1]
    if destroyed != (destroyed_at is not None and receipt_digest is not None):
        raise ks.KeyStoreCorrupt("Keychain index tombstone is incomplete")
    if path.name != f"{_account(match['namespace'], match['handle'])}.json":
        raise ks.KeyStoreCorrupt("Keychain index identity does not match its filename")
    return _IndexRecord(match["namespace"], match["handle"], match["metadata"],
        destroyed_at, receipt_digest, destroyed)


def _write_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            _ = os.fchmod(stream.fileno(), 0o600)
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def _replace_atomic(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{uuid.uuid4().hex}")
    try:
        _write_exclusive(temporary, payload)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError:
        temporary.unlink(missing_ok=True)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
