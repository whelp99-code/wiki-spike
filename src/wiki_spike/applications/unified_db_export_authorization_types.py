"""Wire types for LIVE_EXPORT_ONLY verification."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from wiki_spike.memory_core.second_brain_contracts import (
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)


@dataclass(frozen=True, slots=True)
class ExpectedExportAuthorizationDigestsV1:
    profile_digest: str
    plan_digest: str
    mapping_digest: str
    adapter_digest: str
    inventory_digest: str
    destination_digest: str


@dataclass(frozen=True, slots=True)
class ExportAuthorizationVerifyRequestV1:
    body_bytes: bytes
    envelopes: tuple[Ed25519SignatureEnvelopeV1, ...]
    trusted: TrustedAuthorityBindingsV1
    expected: ExpectedExportAuthorizationDigestsV1
    now: datetime
