"""Synthetic-only fixture clients and authenticated encrypted mapping sealer."""
from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

from wiki_spike.infrastructure.crypto import aes_gcm_seal
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.memory_core.second_brain_capture import EncryptedNativeMappingRefV1, SourceScopeRefV1


class FixtureCaptureClientError(ValueError):
    pass


@dataclass(frozen=True)
class ReadOnlyMigrationCapability:
    _issuer: object
    migration_ref: str
    scope_ref: str
    scope_epoch: str
    evidence_signature: str


class FixtureCaptureClients:
    """In-memory synthetic persistence boundary; it is never production I/O."""

    def __init__(self, *, payloads: Mapping[str, bytes] | None = None, ciphertexts: Mapping[str, bytes] | None = None, credentials: Mapping[str, object] | None = None) -> None:
        self._payloads = dict(payloads or {})
        self._ciphertexts = dict(ciphertexts or {})
        self._credentials = dict(credentials or {})
        self._issuer, self._signing_key = object(), secrets.token_bytes(32)

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

    def issue_read_only_migration_capability(self, migration_ref: str, scope: SourceScopeRefV1) -> ReadOnlyMigrationCapability:
        if not isinstance(migration_ref, str) or not migration_ref or not isinstance(scope, SourceScopeRefV1):
            raise FixtureCaptureClientError("migration reference and resolved scope are required")
        evidence = f"{migration_ref}\0{scope.scope_ref}\0{scope.scope_epoch}".encode("ascii")
        return ReadOnlyMigrationCapability(self._issuer, migration_ref, scope.scope_ref, scope.scope_epoch, hmac.digest(self._signing_key, evidence, "sha256").hex())

    def verify_read_only_migration_capability(self, capability: object, migration_ref: str, scope: SourceScopeRefV1) -> None:
        if not isinstance(capability, ReadOnlyMigrationCapability) or capability._issuer is not self._issuer or not isinstance(scope, SourceScopeRefV1):
            raise FixtureCaptureClientError("signed resolved-scope migration capability required")
        evidence = f"{migration_ref}\0{scope.scope_ref}\0{scope.scope_epoch}".encode("ascii")
        expected = hmac.digest(self._signing_key, evidence, "sha256").hex()
        if (capability.migration_ref != migration_ref or capability.scope_ref != scope.scope_ref
                or capability.scope_epoch != scope.scope_epoch
                or not hmac.compare_digest(capability.evidence_signature, expected)):
            raise FixtureCaptureClientError("migration capability does not bind the resolved scope evidence")


class FixtureNativeMappingSealer:
    """AES-GCM seals native mappings into CAS and returns a capture-bound opaque ref."""

    def __init__(self, cas: EncryptedContentStore, dek: bytes) -> None:
        if not isinstance(cas, EncryptedContentStore) or len(dek) != 32:
            raise FixtureCaptureClientError("encrypted CAS and a 32-byte mapping key are required")
        self._cas, self._dek = cas, bytes(dek)
        self._sealed: dict[str, str] = {}

    def seal_native_mapping(self, scope: SourceScopeRefV1, capture_ref: str, native_mapping: bytes) -> EncryptedNativeMappingRefV1:
        if not isinstance(scope, SourceScopeRefV1) or not isinstance(capture_ref, str) or not isinstance(native_mapping, bytes) or not native_mapping:
            raise FixtureCaptureClientError("invalid fixture native mapping")
        aad = ("second-brain-capture/native-mapping/" + scope.scope_ref + "/" + capture_ref).encode("ascii")
        nonce = secrets.token_bytes(12).hex()
        ciphertext_hex, tag_hex = aes_gcm_seal(self._dek, nonce, native_mapping, aad)
        blob = self._cas.put(bytes.fromhex(nonce + ciphertext_hex + tag_hex))
        sealed_ref = "encrypted-native-mapping:" + blob
        existing = self._sealed.setdefault(capture_ref, sealed_ref)
        if existing != sealed_ref:
            raise FixtureCaptureClientError("capture identity is already bound to different sealed evidence")
        return EncryptedNativeMappingRefV1(capture_ref, sealed_ref)
