"""Domain-separated signing bytes for POSTGRES_METADATA_CAPTURE_ONLY."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue
from .second_brain_contracts import Ed25519SignatureEnvelopeV1

METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN: Final = (
    b"wiki-spike.second-brain.unified-db.postgres-metadata-capture-only-authorization.v1\x00"
)
METADATA_CAPTURE_ONLY_SIGNATURE_VERSION: Final = (
    "second-brain-unified-db-postgres-metadata-capture-only-authorization-signature-v1"
)


def metadata_capture_authorization_signing_bytes(body: Mapping[str, JsonValue]) -> bytes:
    return METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN + canonical_bytes(body)


def parse_metadata_capture_envelopes(
    values: Sequence[Mapping[str, JsonValue]],
) -> tuple[Ed25519SignatureEnvelopeV1, Ed25519SignatureEnvelopeV1]:
    if len(values) != 2:
        raise InvalidContractValue("exactly two public signature envelopes are required")
    signatures = tuple(
        Ed25519SignatureEnvelopeV1.from_mapping(
            item, version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION
        )
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
