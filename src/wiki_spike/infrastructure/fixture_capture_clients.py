"""Synthetic-only fixture clients and authenticated encrypted mapping sealer."""
from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from hashlib import sha256
from typing import Mapping

from wiki_spike.infrastructure.crypto import aes_gcm_seal
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import FixtureCaptureLifecycleDatabase
from wiki_spike.memory_core.second_brain_capture_contracts import (
    EncryptedContentRefV1,
    EncryptedNativeMappingRefV1,
    SourceScopeRefV1,
    canonical_identity_body_digest,
)


class FixtureCaptureClientError(ValueError):
    pass


@dataclass(frozen=True)
class ReadOnlyMigrationCapability:
    _issuer: object
    migration_ref: str
    migration_registration_identity: str
    scope: SourceScopeRefV1
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
        identity = canonical_identity_body_digest(
            "migration-registration-identity-v1",
            {"migration_ref": migration_ref, "scope": scope.to_mapping()},
        )
        evidence = canonical_identity_body_digest(
            "read-only-migration-capability-v1",
            {"migration_registration_identity": identity, "scope": scope.to_mapping()},
        ).encode("ascii")
        return ReadOnlyMigrationCapability(
            self._issuer, migration_ref, identity, scope,
            hmac.digest(self._signing_key, evidence, "sha256").hex(),
        )

    def verify_read_only_migration_capability(self, capability: object, migration_ref: str, scope: SourceScopeRefV1) -> None:
        if not isinstance(capability, ReadOnlyMigrationCapability) or capability._issuer is not self._issuer or not isinstance(scope, SourceScopeRefV1):
            raise FixtureCaptureClientError("signed resolved-scope migration capability required")
        identity = canonical_identity_body_digest(
            "migration-registration-identity-v1",
            {"migration_ref": migration_ref, "scope": scope.to_mapping()},
        )
        evidence = canonical_identity_body_digest(
            "read-only-migration-capability-v1",
            {"migration_registration_identity": identity, "scope": scope.to_mapping()},
        ).encode("ascii")
        expected = hmac.digest(self._signing_key, evidence, "sha256").hex()
        if (capability.migration_ref != migration_ref
                or capability.migration_registration_identity != identity
                or capability.scope != scope
                or not hmac.compare_digest(capability.evidence_signature, expected)):
            raise FixtureCaptureClientError("migration capability does not bind complete scope and registration evidence")


class _FixtureEvidenceSealer:
    """Durably binds one complete canonical capture identity before CAS writes."""

    def __init__(self, database: FixtureCaptureLifecycleDatabase, cas: EncryptedContentStore, dek: bytes, evidence_kind: str, ref_kind: str) -> None:
        if (not isinstance(database, FixtureCaptureLifecycleDatabase)
                or not isinstance(cas, EncryptedContentStore)
                or len(dek) != 32):
            raise FixtureCaptureClientError("fixture database, encrypted CAS, and a 32-byte key are required")
        self._database, self._cas, self._dek = database, cas, bytes(dek)
        self._evidence_kind, self._ref_kind = evidence_kind, ref_kind

    def _seal(self, scope: SourceScopeRefV1, capture_ref: str, evidence: bytes) -> str:
        if not isinstance(scope, SourceScopeRefV1) or not isinstance(capture_ref, str) or not isinstance(evidence, bytes) or not evidence:
            raise FixtureCaptureClientError("invalid fixture capture evidence")
        evidence_digest = sha256(evidence).hexdigest()
        identity_body = {
            "scope": scope.to_mapping(),
            "capture_ref": capture_ref,
            "evidence_kind": self._evidence_kind,
            "evidence_digest": evidence_digest,
        }
        identity_digest = canonical_identity_body_digest("fixture-capture-binding-v1", identity_body)
        identity_ref = f"{self._ref_kind}:{identity_digest}"
        key = (
            scope.workspace_ref, scope.source_profile, scope.source_domain, scope.source_ref,
            scope.scope_ref, scope.scope_epoch, capture_ref, self._evidence_kind,
        )
        with self._database.unit_of_work() as uow:
            row = uow._con.execute(
                "SELECT evidence_digest, identity_ref, cas_locator_ref FROM capture_identity_binding "
                "WHERE workspace_ref=? AND source_profile_state=? AND source_domain_state=? "
                "AND source_ref=? AND scope_ref=? AND scope_epoch_sequence=? AND capture_ref=? AND evidence_kind=?",
                key,
            ).fetchone()
            if row is not None:
                if row[0] != evidence_digest or row[1] != identity_ref:
                    raise FixtureCaptureClientError("capture identity is already bound to different sealed evidence")
                self._cas.get(row[2].split(":", 1)[1])
                return row[1]
            aad = canonical_identity_body_digest("fixture-capture-aad-v1", identity_body).encode("ascii")
            nonce = secrets.token_bytes(12).hex()
            ciphertext_hex, tag_hex = aes_gcm_seal(self._dek, nonce, evidence, aad)
            locator_ref = "encrypted-cas:" + self._cas.put(bytes.fromhex(nonce + ciphertext_hex + tag_hex))
            uow._con.execute(
                "INSERT INTO capture_identity_binding VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (*key, evidence_digest, identity_ref, locator_ref),
            )
        return identity_ref


class FixtureEncryptedContentSealer(_FixtureEvidenceSealer):
    """Fixture-only randomized-AEAD content authority with durable bindings."""

    def __init__(self, database: FixtureCaptureLifecycleDatabase, cas: EncryptedContentStore, dek: bytes) -> None:
        super().__init__(database, cas, dek, "content", "encrypted-content")

    def seal_content(self, scope: SourceScopeRefV1, capture_ref: str, content: bytes) -> EncryptedContentRefV1:
        return EncryptedContentRefV1(capture_ref, self._seal(scope, capture_ref, content))


class FixtureNativeMappingSealer(_FixtureEvidenceSealer):
    """Fixture-only randomized-AEAD native-mapping authority with durable bindings."""

    def __init__(self, database: FixtureCaptureLifecycleDatabase, cas: EncryptedContentStore, dek: bytes) -> None:
        super().__init__(database, cas, dek, "native-mapping", "encrypted-native-mapping")

    def seal_native_mapping(self, scope: SourceScopeRefV1, capture_ref: str, native_mapping: bytes) -> EncryptedNativeMappingRefV1:
        return EncryptedNativeMappingRefV1(capture_ref, self._seal(scope, capture_ref, native_mapping))
