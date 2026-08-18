"""Fail-closed verifier for the signed macOS field-AEAD persistence profile."""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.second_brain_persistence import (
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
)


class PersistenceProfileAuthorizationError(ValueError):
    """The signed persistence profile cannot authorize serving components."""


@final
class _PersistenceProfileMint:
    __slots__ = ()


_PROFILE_MINT = _PersistenceProfileMint()


@final
class VerifiedPersistenceProfile:
    """Nominal capability sealed to one initialized database and CAS pair."""

    __slots__ = (
        "__cas",
        "__database",
        "__mint",
        "__profile_digest",
        "__receipt_digest",
    )

    def __init__(
        self,
        mint: _PersistenceProfileMint,
        database: LifecycleDatabase,
        cas: EncryptedContentStore,
        profile_digest: str,
        receipt_digest: str,
    ) -> None:
        if mint is not _PROFILE_MINT:
            raise PersistenceProfileAuthorizationError(
                "verified persistence profiles must be minted by the verifier"
            )
        self.__mint = mint
        self.__database = database
        self.__cas = cas
        self.__profile_digest = profile_digest
        self.__receipt_digest = receipt_digest

    @property
    def serving_ready(self) -> bool:
        """Report current readiness without acting as the composition proof."""
        return self.is_authorized_for(self.__database, self.__cas)

    @property
    def profile_name(self) -> str:
        return "mac-field-aead-v1"

    @property
    def database_page_cipher(self) -> str:
        return "none"

    @property
    def profile_digest(self) -> str:
        return self.__profile_digest

    @property
    def receipt_digest(self) -> str:
        return self.__receipt_digest

    def is_authorized_for(
        self, database: LifecycleDatabase, cas: EncryptedContentStore
    ) -> bool:
        """Bind authorization to exact live component identities, not equality."""
        try:
            return (
                self.__mint is _PROFILE_MINT
                and self.__database is database
                and self.__cas is cas
                and database.con is not None
            )
        except AttributeError:
            return False


type _JsonValue = None | bool | str | list[_JsonValue] | _JsonObject


@dataclass(frozen=True, slots=True)
class _JsonObject:
    pairs: tuple[tuple[str, _JsonValue], ...]


def _parse_sqlcipher_artifact(raw: bytes) -> None:
    objects: list[_JsonObject] = []

    def parse_object(items: list[tuple[str, _JsonValue]]) -> _JsonObject:
        keys = tuple(key for key, _value in items)
        if len(keys) != len(set(keys)):
            raise PersistenceProfileAuthorizationError(
                "SQLCipher artifact contains duplicate JSON fields"
            )
        parsed = _JsonObject(tuple(items))
        objects.append(parsed)
        return parsed

    try:
        if not isinstance(
            json.loads(raw, object_pairs_hook=parse_object), _JsonObject
        ):
            raise PersistenceProfileAuthorizationError(
                "SQLCipher artifact must be a JSON object"
            )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact must be valid JSON"
        ) from exc
    value = dict(objects[-1].pairs)
    expected: dict[str, _JsonValue] = {
        "schema": "wiki-sqlcipher-feasibility-v1",
        "platform": "darwin/arm64",
        "status": "platform_unavailable",
        "must_verdict": "NOT_RUN",
        "library": None,
        "checks": [],
    }
    if any(
        value.get(field) != expected_value
        for field, expected_value in expected.items()
    ):
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact must record darwin/arm64 platform_unavailable and NOT_RUN"
        )


def verify_mac_persistence_profile(
    *,
    profile: MacPersistenceProfileV1,
    receipt: PersistenceProfileReceiptV1,
    owner_public_key: Ed25519PublicKey,
    approver_public_key: Ed25519PublicKey,
    sqlcipher_artifact_path: Path,
    database: LifecycleDatabase,
    cas: EncryptedContentStore,
) -> VerifiedPersistenceProfile:
    """Verify two-party authorization and mint an identity-bound capability."""
    if type(database) is not LifecycleDatabase or database.con is None:
        raise PersistenceProfileAuthorizationError(
            "an initialized exact LifecycleDatabase is required"
        )
    if type(cas) is not EncryptedContentStore:
        raise PersistenceProfileAuthorizationError(
            "an exact EncryptedContentStore is required"
        )
    parsed_profile = MacPersistenceProfileV1.from_mapping(profile.to_mapping())
    parsed_receipt = PersistenceProfileReceiptV1.from_mapping(receipt.to_mapping())
    if parsed_receipt.profile_digest != parsed_profile.profile_digest:
        raise PersistenceProfileAuthorizationError(
            "persistence receipt does not authorize the selected profile"
        )
    if parsed_receipt.owner_key_id == parsed_receipt.approver_key_id:
        raise PersistenceProfileAuthorizationError(
            "owner and approver key ids must be distinct"
        )
    if owner_public_key.public_bytes_raw() == approver_public_key.public_bytes_raw():
        raise PersistenceProfileAuthorizationError(
            "owner and approver public keys must be distinct"
        )
    try:
        artifact_bytes = sqlcipher_artifact_path.read_bytes()
    except OSError as exc:
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact could not be read"
        ) from exc
    if sha256(artifact_bytes).hexdigest() != parsed_profile.sqlcipher_artifact_digest:
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact digest does not match the signed profile"
        )
    _parse_sqlcipher_artifact(artifact_bytes)
    payload = parsed_receipt.signature_payload()
    try:
        crypto.verify(
            owner_public_key,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
            parsed_receipt.owner_signature,
        )
        crypto.verify(
            approver_public_key,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
            parsed_receipt.approver_signature,
        )
    except (InvalidSignature, ValueError) as exc:
        raise PersistenceProfileAuthorizationError(
            "persistence profile signature verification failed"
        ) from exc
    return VerifiedPersistenceProfile(
        _PROFILE_MINT,
        database,
        cas,
        parsed_profile.profile_digest,
        parsed_receipt.receipt_digest,
    )
