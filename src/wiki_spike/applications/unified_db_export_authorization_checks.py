"""Pure checks for LIVE_EXPORT_ONLY verification. Do not issue grants."""
from __future__ import annotations

from datetime import UTC, datetime

from wiki_spike.applications.unified_db_export_authorization_types import (
    ExpectedExportAuthorizationDigestsV1,
)
from wiki_spike.applications.unified_db_snapshot_export_io import HARD_CAP
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
    parse_utc,
)
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
    parse_export_only_envelopes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def bind_expected_digests(
    authorization: UnifiedDbExportOnlyAuthorizationV1,
    expected: ExpectedExportAuthorizationDigestsV1,
) -> None:
    pairs = (
        ("profile", authorization.profile_digest, expected.profile_digest),
        ("plan", authorization.plan_digest, expected.plan_digest),
        ("mapping", authorization.mapping_digest, expected.mapping_digest),
        ("adapter", authorization.adapter_digest, expected.adapter_digest),
        ("inventory", authorization.inventory_digest, expected.inventory_digest),
        ("destination", authorization.destination_digest, expected.destination_digest),
    )
    for name, actual, wanted in pairs:
        if actual != wanted:
            raise InvalidContractValue(f"{name} digest does not match the expected digest")


def bind_trusted_time(
    authorization: UnifiedDbExportOnlyAuthorizationV1, now: datetime
) -> None:
    if now.utcoffset() is None:
        raise InvalidContractValue("trusted now must carry a timezone utcoffset")
    current = now.astimezone(UTC)
    not_before = parse_utc(authorization.not_before, "not_before")
    expires = parse_utc(authorization.expires_at, "expires_at")
    if current < not_before:
        raise InvalidContractValue("authorization is not yet valid")
    if expires <= current:
        raise InvalidContractValue("authorization is expired")


def bind_export_signatures(
    snapshot: dict[str, JsonValue],
    envelopes: tuple[Ed25519SignatureEnvelopeV1, ...],
    trusted: TrustedAuthorityBindingsV1,
) -> None:
    parsed = parse_export_only_envelopes(tuple(item.to_mapping() for item in envelopes))
    for envelope in parsed:
        if not trusted.matches(envelope):
            raise InvalidContractValue("untrusted export authorization signature")
        if not envelope.verify(EXPORT_ONLY_AUTHORIZATION_DOMAIN, snapshot):
            raise InvalidContractValue("untrusted or invalid export authorization signature")


def snapshot_from_canonical_bytes(body_bytes: bytes) -> dict[str, JsonValue]:
    if len(body_bytes) > HARD_CAP:
        raise UnifiedDbExportError("authorization body exceeds 1048576")
    snapshot = decode_json_object(body_bytes.decode("utf-8"))
    if canonical_bytes(snapshot) != body_bytes:
        raise InvalidContractValue("authorization body is not the canonical encoding")
    return snapshot
