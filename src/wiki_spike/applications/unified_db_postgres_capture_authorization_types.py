"""Wire types for POSTGRES_METADATA_CAPTURE_ONLY verification."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)


@dataclass(frozen=True, slots=True)
class ExpectedMetadataCaptureDigestsV1:
    query_manifest_digest: str
    capture_plan_digest: str
    output_digest: str


@dataclass(frozen=True, slots=True)
class MetadataCaptureVerifyRequestV1:
    body_bytes: bytes
    envelopes: tuple[Ed25519SignatureEnvelopeV1, ...]
    trusted: TrustedAuthorityBindingsV1
    expected: ExpectedMetadataCaptureDigestsV1
    now: datetime
