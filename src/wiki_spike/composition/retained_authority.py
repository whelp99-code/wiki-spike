"""Durable file-backed retained authority for native shadow measurement.

Implements the MonotonicAppendAuthority protocol with:
- Ed25519-signed receipts
- Append-only journal with fsync durability
- Atomic compare-and-advance via file locking
- Monotonic revision counter
- Separate trust domain from the measurement journal
"""
from __future__ import annotations

import fcntl
import json
import os
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from wiki_spike.applications.second_brain_shadow_measurement import (
    AuthoritySnapshot,
    ShadowMeasurementError,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

_AUTHORITY_DOMAIN = "second-brain-native-shadow-authority-v1"
_METADATA_FILE = "metadata.json"
_JOURNAL_FILE = "journal.bin"
_PRIVATE_KEY_FILE = "authority.key"
_PUBLIC_KEY_FILE = "authority.pub"
_LOCK_FILE = "authority.lock"
_RECEIPT_TTL = timedelta(minutes=5)


class LocalRetainedAuthorityError(RuntimeError):
    """The local retained authority is misconfigured or inconsistent."""


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _line(event: Mapping[str, Any]) -> bytes:
    payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
    return f"{len(payload):08x}:".encode("ascii") + payload + b"\n"


def _read_events(path: Path) -> list[dict[str, Any]]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    events: list[dict[str, Any]] = []
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < 9:
            raise LocalRetainedAuthorityError("authority journal has an incomplete frame")
        header = raw[offset:offset + 9]
        try:
            size = int(header[:8], 16)
        except ValueError as exc:
            raise LocalRetainedAuthorityError("authority journal frame header is malformed") from exc
        if header[8:9] != b":" or size < 2 or len(raw) - offset < 10 + size:
            raise LocalRetainedAuthorityError("authority journal frame is malformed")
        payload = raw[offset + 9:offset + 9 + size]
        if raw[offset + 9 + size:offset + 10 + size] != b"\n":
            raise LocalRetainedAuthorityError("authority journal frame terminator is malformed")
        try:
            event = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalRetainedAuthorityError("authority journal is malformed") from exc
        if not isinstance(event, dict):
            raise LocalRetainedAuthorityError("authority journal event is malformed")
        events.append(event)
        offset += 10 + size
    return events


def provision_authority(
    directory: str | Path,
    *,
    identity: str = "wiki-spike-local-retained-authority",
    policy_id: str = "retention-immutable-v1",
) -> Path:
    """Provision a fresh authority directory with signing key and metadata.

    Returns the authority directory path. Raises if the directory already
    contains authority state.
    """
    auth_dir = Path(directory)
    if (auth_dir / _METADATA_FILE).exists() or (auth_dir / _JOURNAL_FILE).exists():
        raise LocalRetainedAuthorityError("authority directory already provisioned")
    auth_dir.mkdir(parents=True, exist_ok=False)

    key = Ed25519PrivateKey.generate()
    private_hex = key.private_bytes(
        Encoding.Raw,
        PrivateFormat.Raw,
        NoEncryption(),
    ).hex()
    public_hex = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    (auth_dir / _PRIVATE_KEY_FILE).write_text(private_hex + "\n", encoding="utf-8")
    os.chmod(auth_dir / _PRIVATE_KEY_FILE, 0o600)
    (auth_dir / _PUBLIC_KEY_FILE).write_text(public_hex + "\n", encoding="utf-8")

    endpoint = f"retention-authority://local/{auth_dir.resolve()}"
    metadata = {
        "identity": identity,
        "endpoint": endpoint,
        "policy_id": policy_id,
        "public_key_fingerprint": sha256(bytes.fromhex(public_hex)).hexdigest(),
        "provisioned_at": _stamp(_now()),
    }
    (auth_dir / _METADATA_FILE).write_text(
        json.dumps(metadata, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    # Create empty journal
    (auth_dir / _JOURNAL_FILE).write_bytes(b"")
    return auth_dir


class LocalRetainedAuthority:
    """Durable file-backed authority satisfying MonotonicAppendAuthority.

    The authority directory must be provisioned via ``provision_authority``
    before first use. The signing key is loaded once at construction and
    never rotated during a session.
    """

    def __init__(self, directory: str | Path) -> None:
        self._dir = Path(directory)
        metadata_path = self._dir / _METADATA_FILE
        if not metadata_path.exists():
            raise LocalRetainedAuthorityError(
                f"authority directory is not provisioned: {self._dir}"
            )
        try:
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise LocalRetainedAuthorityError("authority metadata is unreadable") from exc

        self._identity: str = metadata["identity"]
        self._endpoint: str = metadata["endpoint"]
        self._policy_id: str = metadata["policy_id"]

        key_path = self._dir / _PRIVATE_KEY_FILE
        try:
            raw_key = bytes.fromhex(key_path.read_text(encoding="utf-8").strip())
            self._key = Ed25519PrivateKey.from_private_bytes(raw_key)
        except (OSError, ValueError) as exc:
            raise LocalRetainedAuthorityError("authority signing key is unreadable") from exc

        self._public_key = self._key.public_key()
        self._public_key_fingerprint = sha256(
            self._public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        ).hexdigest()

        if self._public_key_fingerprint != metadata.get("public_key_fingerprint"):
            raise LocalRetainedAuthorityError("authority key does not match metadata fingerprint")

        self._journal_path = self._dir / _JOURNAL_FILE
        self._lock_path = self._dir / _LOCK_FILE

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def policy_id(self) -> str:
        return self._policy_id

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public_key

    def _locked(self):
        handle = self._lock_path.open("a+")
        class Lock:
            def __enter__(_self):
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                return _self
            def __exit__(_self, *args):
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                handle.close()
        return Lock()

    def _read_journal(self) -> list[dict[str, Any]]:
        return _read_events(self._journal_path)

    def _append_durable(self, event: Mapping[str, Any]) -> None:
        descriptor = os.open(self._journal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            payload = _line(event)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short authority journal write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _build_snapshot(self, events: list[dict[str, Any]], nonce: str) -> AuthoritySnapshot:
        root = sha256(canonical_ledger_bytes(
            _AUTHORITY_DOMAIN, {"events": [dict(e) for e in events]}
        )).hexdigest()
        issued = _now()
        payload = {
            "identity": self._identity,
            "endpoint": self._endpoint,
            "policy_id": self._policy_id,
            "public_key_fingerprint": self._public_key_fingerprint,
            "revision": len(events),
            "root": root,
            "request_nonce": nonce,
            "issued_at": _stamp(issued),
            "expires_at": _stamp(issued + _RECEIPT_TTL),
            "events": tuple(dict(e) for e in events),
        }
        signature = self._key.sign(
            canonical_ledger_bytes(_AUTHORITY_DOMAIN, payload)
        ).hex()
        return AuthoritySnapshot(**payload, signature=signature)

    def snapshot(self, *, request_nonce: str) -> AuthoritySnapshot:
        with self._locked():
            events = self._read_journal()
        return self._build_snapshot(events, request_nonce)

    def compare_and_advance(
        self, *, expected_revision: int, event: Mapping[str, Any], request_nonce: str
    ) -> AuthoritySnapshot:
        with self._locked():
            events = self._read_journal()
            if len(events) != expected_revision:
                raise ShadowMeasurementError(
                    f"authority CAS conflict: expected revision {expected_revision}, "
                    f"actual {len(events)}"
                )
            self._append_durable(event)
            events.append(deepcopy(dict(event)))
        return self._build_snapshot(events, request_nonce)


__all__ = [
    "LocalRetainedAuthority",
    "LocalRetainedAuthorityError",
    "provision_authority",
]
