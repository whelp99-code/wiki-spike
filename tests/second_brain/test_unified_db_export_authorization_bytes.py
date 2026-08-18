"""Byte-first verifier probes: canonical snapshot, SplitBody, mutation."""
from __future__ import annotations

from collections.abc import Iterator

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.unified_db_export_authorization_support import (
    NOW,
    authorization_body,
    expected_digests,
    sign_body,
    signed_request,
    trusted_pair,
)
from wiki_spike.applications.unified_db_export_authorization_verify import (
    ExportAuthorizationVerifyRequestV1,
    verify_export_only_authorization,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    InMemoryExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


class SplitBody:
    """Mapping whose items() view disagrees with __getitem__."""

    _base: dict[str, JsonValue]

    def __init__(self, base: dict[str, JsonValue]) -> None:
        self._base = base

    def __getitem__(self, key: str) -> JsonValue:
        if key == "authorization_id":
            return "export-auth-evil"
        return self._base[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._base)

    def __len__(self) -> int:
        return len(self._base)

    def items(self) -> Iterator[tuple[str, JsonValue]]:
        return iter(self._base.items())


def test_verifier_accepts_only_exact_canonical_body_bytes() -> None:
    request, _nonces = signed_request()
    assert isinstance(request.body_bytes, bytes)
    pretty = canonical_bytes(authorization_body()).replace(b":", b": ")
    spaced = ExportAuthorizationVerifyRequestV1(
        pretty,
        request.envelopes,
        request.trusted,
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError), match="canonical"):
        _ = verify_export_only_authorization(
            spaced, InMemoryExportAuthorizationNonceStore()
        )


def test_split_body_items_versus_getitem_cannot_mint() -> None:
    base = authorization_body()
    split = SplitBody(base)
    assert split["authorization_id"] == "export-auth-evil"
    items_view = dict(split.items())
    assert items_view["authorization_id"] == "export-auth-001"
    getitem_view = {key: split[key] for key in split}
    assert canonical_bytes(getitem_view) != canonical_bytes(items_view)
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    envelopes = sign_body(base, owner, approver)
    trusted = trusted_pair(owner, approver)
    good = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(items_view),
        envelopes,
        trusted,
        expected_digests(),
        NOW,
    )
    token = verify_export_only_authorization(
        good, InMemoryExportAuthorizationNonceStore()
    )
    assert token.claim().authorization_id == "export-auth-001"
    evil = ExportAuthorizationVerifyRequestV1(
        canonical_bytes(getitem_view),
        envelopes,
        trusted,
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_export_only_authorization(
            evil, InMemoryExportAuthorizationNonceStore()
        )


def test_source_mutation_after_snapshot_cannot_change_verified_bytes() -> None:
    body = authorization_body()
    request, nonces = signed_request(body=body)
    body["authorization_id"] = "export-auth-mutated"
    token = verify_export_only_authorization(request, nonces)
    assert token.claim().authorization_id == "export-auth-001"


def test_oversized_body_bytes_are_rejected_before_decode() -> None:
    request, _nonces = signed_request()
    huge = b"{" + (b"a" * 2_000_000) + b"}"
    oversized = ExportAuthorizationVerifyRequestV1(
        huge,
        request.envelopes,
        request.trusted,
        expected_digests(),
        NOW,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError), match="1048576|bound|cap"):
        _ = verify_export_only_authorization(
            oversized, InMemoryExportAuthorizationNonceStore()
        )
