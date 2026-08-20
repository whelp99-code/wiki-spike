"""Fail-closed verifier for the signed macOS field-AEAD persistence profile."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
from typing import final, override

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile_checks import (
    PersistenceProfileAuthorizationError,
    parse_sqlcipher_artifact,
)
from wiki_spike.memory_core.second_brain_persistence import (
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
)

__all__ = ("PersistenceProfileAuthorizationError",)


@final
class _PersistenceProfileMint:
    __slots__ = ()


_PROFILE_MINT = _PersistenceProfileMint()


@final
class _PersistenceAuthorizationMint:
    __slots__ = ()


_AUTHORIZATION_MINT = _PersistenceAuthorizationMint()


@final
class VerifiedPersistenceAuthorization:
    """Pure two-party authorization, not yet bound to live storage."""

    __slots__ = ("__mint", "__profile_digest", "__receipt_digest")

    def __init__(
        self,
        mint: _PersistenceAuthorizationMint,
        profile_digest: str,
        receipt_digest: str,
    ) -> None:
        if mint is not _AUTHORIZATION_MINT:
            raise PersistenceProfileAuthorizationError(
                "verified persistence authorizations must be minted by the verifier"
            )
        self.__mint = mint
        self.__profile_digest = profile_digest
        self.__receipt_digest = receipt_digest

    @property
    def profile_digest(self) -> str:
        return self.__profile_digest

    @property
    def receipt_digest(self) -> str:
        return self.__receipt_digest

    def verified_digests(
        self, mint: _PersistenceAuthorizationMint
    ) -> tuple[str, str]:
        if mint is not _AUTHORIZATION_MINT or self.__mint is not _AUTHORIZATION_MINT:
            raise PersistenceProfileAuthorizationError(
                "persistence authorization is not verifier-minted"
            )
        return self.__profile_digest, self.__receipt_digest

    def __copy__(self) -> VerifiedPersistenceAuthorization:
        raise PersistenceProfileAuthorizationError(
            "verified persistence authorization cannot be copied"
        )

    def __deepcopy__(
        self, memo: dict[int, object]
    ) -> VerifiedPersistenceAuthorization:
        _ = memo
        raise PersistenceProfileAuthorizationError(
            "verified persistence authorization cannot be copied"
        )

    @override
    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("verified persistence authorization cannot be serialized")


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


def verify_mac_persistence_authorization(
    *,
    profile: MacPersistenceProfileV1,
    receipt: PersistenceProfileReceiptV1,
    owner_key_id: str,
    owner_public_key: Ed25519PublicKey,
    approver_key_id: str,
    approver_public_key: Ed25519PublicKey,
    sqlcipher_artifact_bytes: bytes,
) -> VerifiedPersistenceAuthorization:
    """Verify profile, evidence, and signatures without touching live storage."""
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
    if (
        parsed_receipt.owner_key_id != owner_key_id
        or parsed_receipt.approver_key_id != approver_key_id
    ):
        raise PersistenceProfileAuthorizationError(
            "persistence receipt key ids do not match pinned identities"
        )
    if owner_public_key.public_bytes_raw() == approver_public_key.public_bytes_raw():
        raise PersistenceProfileAuthorizationError(
            "owner and approver public keys must be distinct"
        )
    if (
        sha256(sqlcipher_artifact_bytes).hexdigest()
        != parsed_profile.sqlcipher_artifact_digest
    ):
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact digest does not match the signed profile"
        )
    parse_sqlcipher_artifact(sqlcipher_artifact_bytes)
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
    return VerifiedPersistenceAuthorization(
        _AUTHORIZATION_MINT,
        parsed_profile.profile_digest,
        parsed_receipt.receipt_digest,
    )


def bind_mac_persistence_profile(
    authorization: object,
    *,
    database: LifecycleDatabase,
    cas: EncryptedContentStore,
) -> VerifiedPersistenceProfile:
    """Bind a pure authorization to exact initialized live component instances."""
    if type(database) is not LifecycleDatabase or database.con is None:
        raise PersistenceProfileAuthorizationError(
            "an initialized exact LifecycleDatabase is required"
        )
    if type(cas) is not EncryptedContentStore:
        raise PersistenceProfileAuthorizationError(
            "an exact EncryptedContentStore is required"
        )
    if type(authorization) is not VerifiedPersistenceAuthorization:
        raise PersistenceProfileAuthorizationError(
            "an exact verified persistence authorization is required"
        )
    profile_digest, receipt_digest = authorization.verified_digests(_AUTHORIZATION_MINT)
    return VerifiedPersistenceProfile(
        _PROFILE_MINT,
        database,
        cas,
        profile_digest,
        receipt_digest,
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
    """Compatibility wrapper for pure authorization followed by live binding."""
    try:
        artifact_bytes = sqlcipher_artifact_path.read_bytes()
    except OSError as exc:
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact could not be read"
        ) from exc
    authorization = verify_mac_persistence_authorization(
        profile=profile,
        receipt=receipt,
        owner_key_id=receipt.owner_key_id,
        owner_public_key=owner_public_key,
        approver_key_id=receipt.approver_key_id,
        approver_public_key=approver_public_key,
        sqlcipher_artifact_bytes=artifact_bytes,
    )
    return bind_mac_persistence_profile(
        authorization,
        database=database,
        cas=cas,
    )
