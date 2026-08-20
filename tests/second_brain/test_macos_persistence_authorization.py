"""Pure persistence authorization precedes live DB/CAS binding."""
from __future__ import annotations

import copy
import pickle
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.test_macos_persistence_profile import (
    SQLCIPHER_ARTIFACT,
    persistence_profile,
    persistence_receipt,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    VerifiedPersistenceAuthorization,
    VerifiedPersistenceProfile,
    bind_mac_persistence_profile,
    verify_mac_persistence_authorization,
)


def test_pure_authorization_verifies_before_storage_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)

    def refuse_storage(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("pure authorization must not construct storage")

    monkeypatch.setattr(LifecycleDatabase, "__init__", refuse_storage)
    monkeypatch.setattr(EncryptedContentStore, "__init__", refuse_storage)

    authorization = verify_mac_persistence_authorization(
        profile=profile,
        receipt=receipt,
        owner_key_id="wiki-owner-2026",
        owner_public_key=owner.public_key(),
        approver_key_id="wiki-approver-2026",
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_bytes=SQLCIPHER_ARTIFACT.read_bytes(),
    )

    assert isinstance(authorization, VerifiedPersistenceAuthorization)
    assert authorization.profile_digest == profile.profile_digest
    assert authorization.receipt_digest == receipt.receipt_digest


def test_verified_authorization_binds_exact_live_instances(tmp_path: Path) -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)
    authorization = verify_mac_persistence_authorization(
        profile=profile,
        receipt=receipt,
        owner_key_id="wiki-owner-2026",
        owner_public_key=owner.public_key(),
        approver_key_id="wiki-approver-2026",
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_bytes=SQLCIPHER_ARTIFACT.read_bytes(),
    )
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")

    verified = bind_mac_persistence_profile(
        authorization,
        database=database,
        cas=cas,
    )

    assert isinstance(verified, VerifiedPersistenceProfile)
    assert verified.is_authorized_for(database, cas)
    database.close()


def test_pure_authorization_requires_pinned_key_ids() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)

    with pytest.raises(PersistenceProfileAuthorizationError, match="key ids"):
        _ = verify_mac_persistence_authorization(
            profile=profile,
            receipt=receipt,
            owner_key_id="wrong-owner",
            owner_public_key=owner.public_key(),
            approver_key_id="wiki-approver-2026",
            approver_public_key=approver.public_key(),
            sqlcipher_artifact_bytes=SQLCIPHER_ARTIFACT.read_bytes(),
        )


def test_verified_authorization_refuses_copy_and_pickle() -> None:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)
    authorization = verify_mac_persistence_authorization(
        profile=profile,
        receipt=receipt,
        owner_key_id="wiki-owner-2026",
        owner_public_key=owner.public_key(),
        approver_key_id="wiki-approver-2026",
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_bytes=SQLCIPHER_ARTIFACT.read_bytes(),
    )

    with pytest.raises(PersistenceProfileAuthorizationError, match="cannot be copied"):
        _ = copy.copy(authorization)
    with pytest.raises(PersistenceProfileAuthorizationError, match="cannot be copied"):
        _ = copy.deepcopy(authorization)
    with pytest.raises(TypeError, match="cannot be serialized"):
        _ = pickle.dumps(authorization)
