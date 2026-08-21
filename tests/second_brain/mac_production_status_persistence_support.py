"""Helpers for Mac production persistence-profile status tests."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.test_mac_signed_authority_bundle import (
    APPROVER,
    NOW,
    OWNER,
    TRUSTED,
)
from tests.second_brain.test_macos_persistence_profile import (
    SQLCIPHER_ARTIFACT,
    persistence_profile,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedDecisionKeyBindingsV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_persistence import (
    PERSISTENCE_PROFILE_RECEIPT_V1,
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
    persistence_profile_authorization_payload,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
    mint_security_context_authority,
)

INVALID_PROFILE = b"{}"


def signed_receipt(
    profile: MacPersistenceProfileV1,
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> PersistenceProfileReceiptV1:
    authorized_at = "2026-08-18T00:00:00Z"
    payload = persistence_profile_authorization_payload(
        receipt_version=PERSISTENCE_PROFILE_RECEIPT_V1,
        profile_digest=profile.profile_digest,
        owner_key_id="owner",
        approver_key_id="approver",
        authorized_at=authorized_at,
    )
    body = {
        "receipt_version": PERSISTENCE_PROFILE_RECEIPT_V1,
        "profile_digest": profile.profile_digest,
        "owner_key_id": "owner",
        "approver_key_id": "approver",
        "owner_signature": crypto.sign(
            owner, PERSISTENCE_PROFILE_SIGNATURE_DOMAIN, payload
        ),
        "approver_signature": crypto.sign(
            approver, PERSISTENCE_PROFILE_SIGNATURE_DOMAIN, payload
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


def signed_persistence_pair(
    owner: Ed25519PrivateKey = OWNER,
    approver: Ed25519PrivateKey = APPROVER,
) -> tuple[bytes, bytes]:
    profile = persistence_profile()
    receipt = signed_receipt(profile, owner, approver)
    return canonical_bytes(profile.to_mapping()), canonical_bytes(receipt.to_mapping())


def write_closed_artifacts(
    home: Path,
    *,
    authority: bytes,
    profile: bytes,
    receipt: bytes,
) -> None:
    closed = (
        home
        / "Library"
        / "Application Support"
        / "wiki-spike"
        / "second-brain-v1"
    )
    closed.mkdir(parents=True)
    _ = (closed / "signed-authority.json").write_bytes(authority)
    _ = (closed / "persistence-profile.json").write_bytes(profile)
    _ = (closed / "persistence-receipt.json").write_bytes(receipt)


def pin_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.PINNED_TRUSTED_KEYS",
        TRUSTED,
        raising=False,
    )
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.PINNED_TRUSTED_NOW",
        NOW,
        raising=False,
    )
    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.PINNED_SQLCIPHER_ARTIFACT_BYTES",
        SQLCIPHER_ARTIFACT.read_bytes(),
        raising=False,
    )


MintCall = tuple[
    Sequence[DecisionRecordV1],
    ResolvedScopeV1,
    ExpectedScopeManifestV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedDecisionKeyBindingsV1,
    datetime | None,
]


def track_mint(monkeypatch: pytest.MonkeyPatch) -> list[MintCall]:
    calls: list[MintCall] = []

    def tracking(
        decisions: Sequence[DecisionRecordV1],
        scope: ResolvedScopeV1,
        expected_scopes: ExpectedScopeManifestV1,
        aggregate: SignedSecondBrainContractEnvelopeV1,
        trusted_keys: TrustedDecisionKeyBindingsV1,
        *,
        now: datetime | None = None,
    ) -> SecurityContextAuthority:
        calls.append(
            (decisions, scope, expected_scopes, aggregate, trusted_keys, now)
        )
        return mint_security_context_authority(
            decisions, scope, expected_scopes, aggregate, trusted_keys, now=now
        )

    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.mint_security_context_authority",
        tracking,
        raising=False,
    )
    return calls
