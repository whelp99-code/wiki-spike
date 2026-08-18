"""Domain-separated signing bytes for LIVE_EXPORT_ONLY authorization."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue
from .second_brain_contracts import Ed25519SignatureEnvelopeV1

EXPORT_ONLY_AUTHORIZATION_DOMAIN: Final = (
    b"wiki-spike.second-brain.unified-db.export-only-authorization.v1\x00"
)
EXPORT_ONLY_SIGNATURE_VERSION: Final = (
    "second-brain-unified-db-export-only-authorization-signature-v1"
)


def export_only_authorization_signing_bytes(body: Mapping[str, JsonValue]) -> bytes:
    return EXPORT_ONLY_AUTHORIZATION_DOMAIN + canonical_bytes(body)


def parse_export_only_envelopes(
    values: Sequence[Mapping[str, JsonValue]],
) -> tuple[Ed25519SignatureEnvelopeV1, Ed25519SignatureEnvelopeV1]:
    if len(values) != 2:
        raise InvalidContractValue("exactly two public signature envelopes are required")
    signatures = tuple(
        Ed25519SignatureEnvelopeV1.from_mapping(item, version=EXPORT_ONLY_SIGNATURE_VERSION)
        for item in values
    )
    roles = tuple(item.role for item in signatures)
    if roles != ("approver", "owner"):
        raise InvalidContractValue(
            "signatures must be canonically ordered as approver then owner"
        )
    first, second = signatures
    if first.key_id == second.key_id or first.public_key_b64 == second.public_key_b64:
        raise InvalidContractValue(
            "owner and Security approver must have distinct key identities and public keys"
        )
    return first, second
