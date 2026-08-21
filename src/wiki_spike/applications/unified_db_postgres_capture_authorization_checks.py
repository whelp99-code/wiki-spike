"""Pure checks for POSTGRES_METADATA_CAPTURE_ONLY. Do not issue grants."""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
)
from wiki_spike.applications.unified_db_snapshot_export_io import HARD_CAP
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)
from wiki_spike.memory_core.unified_db_export_authorization import parse_utc
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN,
    parse_metadata_capture_envelopes,
)
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    PostgresMetadataCaptureReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_UNBOUND_ARTIFACT_DIGEST: Final = "0" * 64


def bind_expected_digests(
    authorization: UnifiedDbMetadataCaptureOnlyAuthorizationV1,
    expected: ExpectedMetadataCaptureDigestsV1,
) -> None:
    pairs = (
        (
            "query manifest",
            authorization.query_manifest_digest,
            expected.query_manifest_digest,
        ),
        (
            "capture plan",
            authorization.capture_plan_digest,
            expected.capture_plan_digest,
        ),
        ("output", authorization.output_digest, expected.output_digest),
        (
            "destination",
            authorization.destination.destination_digest,
            expected.destination_digest,
        ),
    )
    for name, actual, wanted in pairs:
        if actual != wanted:
            raise InvalidContractValue(f"{name} digest does not match the expected digest")


def bind_produced_capture_digests(
    authorization: UnifiedDbMetadataCaptureOnlyAuthorizationV1,
    receipt: PostgresMetadataCaptureReceiptV1,
) -> None:
    """Refuse 64-zero plan/output digests as wildcards for produced artifacts."""
    pairs = (
        (
            "capture plan",
            authorization.capture_plan_digest,
            receipt.capture_plan_digest,
        ),
        ("output", authorization.output_digest, receipt.output_digest),
    )
    for name, actual, produced in pairs:
        if actual == produced:
            continue
        if actual == _UNBOUND_ARTIFACT_DIGEST:
            raise InvalidContractValue(
                f"{name} digest does not match the expected digest"
            )


def bind_trusted_time(
    authorization: UnifiedDbMetadataCaptureOnlyAuthorizationV1, now: datetime
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


def bind_capture_signatures(
    snapshot: dict[str, JsonValue],
    envelopes: tuple[Ed25519SignatureEnvelopeV1, ...],
    trusted: TrustedAuthorityBindingsV1,
) -> None:
    parsed = parse_metadata_capture_envelopes(tuple(item.to_mapping() for item in envelopes))
    for envelope in parsed:
        if not trusted.matches(envelope):
            raise InvalidContractValue("untrusted metadata capture authorization signature")
        if not envelope.verify(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN, snapshot):
            raise InvalidContractValue(
                "untrusted or invalid metadata capture authorization signature"
            )


def snapshot_from_canonical_bytes(body_bytes: bytes) -> dict[str, JsonValue]:
    if len(body_bytes) > HARD_CAP:
        raise UnifiedDbExportError("authorization body exceeds 1048576")
    snapshot = decode_json_object(body_bytes.decode("utf-8"))
    if canonical_bytes(snapshot) != body_bytes:
        raise InvalidContractValue("authorization body is not the canonical encoding")
    return snapshot
