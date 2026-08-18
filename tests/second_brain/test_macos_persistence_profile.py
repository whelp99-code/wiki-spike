from __future__ import annotations

import sqlite3
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.composition.second_brain_product import (
    ProductCompositionError,
    compose_second_brain_product_v2,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    VerifiedPersistenceProfile,
    verify_mac_persistence_profile,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_persistence import (
    MAC_FIELD_AEAD_PROFILE_V1,
    PERSISTENCE_PROFILE_RECEIPT_V1,
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
    persistence_profile_authorization_payload,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
)

SQLCIPHER_ARTIFACT = Path(
    "artifacts/encrypted-lifecycle/sqlcipher-feasibility-darwin-arm64.json"
)


def persistence_profile(
    *,
    sqlcipher_artifact_digest: str | None = None,
    sqlcipher_status: str = "platform_unavailable",
    sqlcipher_must_verdict: str = "NOT_RUN",
) -> MacPersistenceProfileV1:
    artifact_digest = sqlcipher_artifact_digest or sha256(
        SQLCIPHER_ARTIFACT.read_bytes()
    ).hexdigest()
    body = {
        "profile_version": MAC_FIELD_AEAD_PROFILE_V1,
        "profile_name": "mac-field-aead-v1",
        "sqlite_runtime": f"python-stdlib-sqlite3/{sqlite3.sqlite_version}",
        "state_authority": "LifecycleDatabase",
        "content_store": "EncryptedContentStore",
        "content_cipher": "AES-256-GCM",
        "database_page_cipher": "none",
        "sqlcipher_status": sqlcipher_status,
        "sqlcipher_must_verdict": sqlcipher_must_verdict,
        "sqlcipher_artifact_digest": artifact_digest,
    }
    return MacPersistenceProfileV1.from_mapping(
        body
        | {
            "profile_digest": canonical_ledger_digest(
                "mac-persistence-profile-v1",
                body,
            )
        }
    )


def persistence_receipt(
    profile: MacPersistenceProfileV1,
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> PersistenceProfileReceiptV1:
    authorized_at = "2026-08-18T00:00:00Z"
    signature_payload = persistence_profile_authorization_payload(
        receipt_version=PERSISTENCE_PROFILE_RECEIPT_V1,
        profile_digest=profile.profile_digest,
        owner_key_id="wiki-owner-2026",
        approver_key_id="wiki-approver-2026",
        authorized_at=authorized_at,
    )
    body = {
        "receipt_version": PERSISTENCE_PROFILE_RECEIPT_V1,
        "profile_digest": profile.profile_digest,
        "owner_key_id": "wiki-owner-2026",
        "approver_key_id": "wiki-approver-2026",
        "owner_signature": crypto.sign(
            owner,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            signature_payload,
        ),
        "approver_signature": crypto.sign(
            approver,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            signature_payload,
        ),
        "authorized_at": authorized_at,
    }
    return PersistenceProfileReceiptV1.from_mapping(
        body
        | {
            "receipt_digest": canonical_ledger_digest(
                "persistence-profile-receipt-v1",
                body,
            )
        }
    )


def test_exact_signed_field_aead_profile_authorizes_real_components(
    tmp_path: Path,
) -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")

    verified = verify_mac_persistence_profile(
        profile=profile,
        receipt=receipt,
        owner_public_key=owner.public_key(),
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
        database=database,
        cas=cas,
    )

    assert isinstance(verified, VerifiedPersistenceProfile)
    assert verified.serving_ready is True
    assert verified.profile_name == "mac-field-aead-v1"
    assert verified.database_page_cipher == "none"
    database.close()


def test_field_aead_profile_rejects_false_sqlcipher_pass() -> None:
    with pytest.raises(ValueError, match="SQLCipher"):
        _ = persistence_profile(
            sqlcipher_status="pass",
            sqlcipher_must_verdict="PASS",
        )


def test_profile_authorization_rejects_same_owner_and_approver_key(
    tmp_path: Path,
) -> None:
    owner = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, owner)
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")

    with pytest.raises(
        PersistenceProfileAuthorizationError,
        match="distinct",
    ):
        _ = verify_mac_persistence_profile(
            profile=profile,
            receipt=receipt,
            owner_public_key=owner.public_key(),
            approver_public_key=owner.public_key(),
            sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
            database=database,
            cas=cas,
        )
    database.close()


def test_profile_authorization_rejects_stale_sqlcipher_artifact(
    tmp_path: Path,
) -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile(sqlcipher_artifact_digest="0" * 64)
    receipt = persistence_receipt(profile, owner, approver)
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")

    with pytest.raises(
        PersistenceProfileAuthorizationError,
        match="SQLCipher artifact",
    ):
        _ = verify_mac_persistence_profile(
            profile=profile,
            receipt=receipt,
            owner_public_key=owner.public_key(),
            approver_public_key=approver.public_key(),
            sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
            database=database,
            cas=cas,
        )
    database.close()


def test_profile_authorization_rejects_relabelled_key_id(
    tmp_path: Path,
) -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)
    relabelled_body = receipt.to_mapping()
    del relabelled_body["receipt_digest"]
    relabelled_body["owner_key_id"] = "forged-owner-label"
    relabelled = PersistenceProfileReceiptV1.from_mapping(
        relabelled_body
        | {
            "receipt_digest": canonical_ledger_digest(
                "persistence-profile-receipt-v1",
                relabelled_body,
            )
        }
    )
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")

    with pytest.raises(
        PersistenceProfileAuthorizationError,
        match="signature verification",
    ):
        _ = verify_mac_persistence_profile(
            profile=profile,
            receipt=relabelled,
            owner_public_key=owner.public_key(),
            approver_public_key=approver.public_key(),
            sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
            database=database,
            cas=cas,
        )
    database.close()


def test_product_composition_rejects_missing_persistence_profile(
    tmp_path: Path,
) -> None:
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    with pytest.raises(ProductCompositionError, match="persistence profile"):
        _ = compose_second_brain_product_v2(
            authority=cast(SecurityContextAuthority, object()),
            database=database,
            cas=cas,
            persistence_profile=None,
        )
    database.close()
