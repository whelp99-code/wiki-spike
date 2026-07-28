"""Fixture-only low-level clients for frozen Stage-2 connector ports."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping


class FixtureCaptureClientError(ValueError):
    pass


@dataclass(frozen=True)
class ReadOnlyMigrationCapability:
    """Unforgeable-by-value capability issued only by this fixture client."""
    _issuer: object
    migration_ref: str


class FixtureCaptureClients:
    """In-memory fixture payload/ciphertext/credential boundary; never does I/O."""

    def __init__(self, *, payloads: Mapping[str, bytes] | None = None, ciphertexts: Mapping[str, bytes] | None = None, credentials: Mapping[str, object] | None = None) -> None:
        self._payloads = dict(payloads or {})
        self._ciphertexts = dict(ciphertexts or {})
        self._credentials = dict(credentials or {})
        self._issuer = object()

    @staticmethod
    def _read(values: Mapping[str, bytes], ref: str) -> bytes:
        if not isinstance(ref, str) or ref not in values:
            raise FixtureCaptureClientError("unknown fixture reference")
        value = values[ref]
        if not isinstance(value, bytes):
            raise FixtureCaptureClientError("fixture values must be bytes")
        return value

    def read_fixture_payload(self, request_ref: str) -> bytes:
        return self._read(self._payloads, request_ref)

    def read_fixture_ciphertext(self, fixture_ref: str) -> bytes:
        return self._read(self._ciphertexts, fixture_ref)

    def resolve_fixture_credential(self, credential_ref: str) -> object:
        if not isinstance(credential_ref, str) or credential_ref not in self._credentials:
            raise FixtureCaptureClientError("unknown fixture credential")
        return self._credentials[credential_ref]

    def issue_read_only_migration_capability(self, migration_ref: str) -> ReadOnlyMigrationCapability:
        if not isinstance(migration_ref, str) or not migration_ref:
            raise FixtureCaptureClientError("migration reference is required")
        return ReadOnlyMigrationCapability(self._issuer, migration_ref)

    def verify_read_only_migration_capability(self, capability: object, migration_ref: str) -> None:
        if not isinstance(capability, ReadOnlyMigrationCapability) or capability._issuer is not self._issuer or capability.migration_ref != migration_ref:
            raise FixtureCaptureClientError("independently verified read-only migration capability required")


class FixtureNativeMappingSealer:
    """One-way fixture sealer retaining only digest-derived opaque references."""

    def __init__(self) -> None:
        self._sealed: dict[str, str] = {}

    def seal_native_mapping(self, scope: object, capture_ref: str, native_mapping: bytes) -> str:
        scope_ref = getattr(scope, "scope_ref", None)
        if not isinstance(scope_ref, str) or not isinstance(capture_ref, str) or not isinstance(native_mapping, bytes):
            raise FixtureCaptureClientError("invalid fixture native mapping")
        sealed_ref = "sealed-mapping:" + sha256(scope_ref.encode() + b"\0" + capture_ref.encode() + b"\0" + native_mapping).hexdigest()
        self._sealed.setdefault(capture_ref, sealed_ref)
        return sealed_ref
