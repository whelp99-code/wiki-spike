"""Evidence-manifest envelope parse for Mac signed authority."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnsupportedContractVersion
from .mac_signed_authority_parse import (
    EVIDENCE_ENVELOPE_VERSION,
    EVIDENCE_MANIFEST_VERSION,
    EVIDENCE_SIGNATURE_VERSION,
    parse_const,
    parse_decision_identity,
    parse_signature_set,
    parse_utc_text,
    require_array,
    require_mapping,
    strict_fields,
)
from .second_brain_contracts import Ed25519SignatureEnvelopeV1
from .snapshot_import_parse import parse_digest

_EVIDENCE_ENVELOPE_FIELDS: Final = frozenset(
    {
        "evidence_envelope_version",
        "evidence_manifest_digest",
        "evidence_body",
        "signatures",
    }
)
_EVIDENCE_BODY_FIELDS: Final = frozenset(
    {
        "evidence_manifest_version",
        "observed_at",
        "expires_at",
        "decision_evidence",
    }
)
_EVIDENCE_ENTRY_FIELDS: Final = frozenset(
    {"decision_id", "scope_kind", "scope_name", "evidence_digest"}
)
type DecisionIdentity = tuple[str, str, str | None]


@dataclass(frozen=True, slots=True)
class EvidenceManifestBodyV1:
    evidence_manifest_version: str
    observed_at: str
    expires_at: str
    evidence: dict[DecisionIdentity, str]

    def to_mapping(self) -> dict[str, JsonValue]:
        entries = sorted(
            self.evidence.items(),
            key=lambda item: (item[0][0], item[0][1], item[0][2] or ""),
        )
        evidence: list[JsonValue] = []
        for identity, digest in entries:
            entry: dict[str, JsonValue] = {
                "decision_id": identity[0],
                "scope_kind": identity[1],
                "scope_name": identity[2],
                "evidence_digest": digest,
            }
            evidence.append(entry)
        return {
            "evidence_manifest_version": self.evidence_manifest_version,
            "observed_at": self.observed_at,
            "expires_at": self.expires_at,
            "decision_evidence": evidence,
        }


@dataclass(frozen=True, slots=True)
class EvidenceManifestEnvelopeV1:
    evidence_envelope_version: str
    evidence_manifest_digest: str
    body: EvidenceManifestBodyV1
    signatures: tuple[Ed25519SignatureEnvelopeV1, ...]

    def signing_payload(self) -> dict[str, JsonValue]:
        return {
            "evidence_envelope_version": self.evidence_envelope_version,
            "evidence_manifest_digest": self.evidence_manifest_digest,
            "evidence_body": self.body.to_mapping(),
        }

    def to_mapping(self) -> dict[str, JsonValue]:
        payload = self.signing_payload()
        signatures: list[JsonValue] = []
        for item in self.signatures:
            mapped: dict[str, JsonValue] = {
                "signature_version": item.signature_version,
                "role": item.role,
                "key_id": item.key_id,
                "public_key_b64": item.public_key_b64,
                "signature_b64": item.signature_b64,
            }
            signatures.append(mapped)
        return {
            "evidence_envelope_version": payload["evidence_envelope_version"],
            "evidence_manifest_digest": payload["evidence_manifest_digest"],
            "evidence_body": payload["evidence_body"],
            "signatures": signatures,
        }


def parse_evidence_manifest(value: JsonValue) -> EvidenceManifestEnvelopeV1:
    data = require_mapping(value, "evidence_manifest")
    strict_fields(data, _EVIDENCE_ENVELOPE_FIELDS)
    if data["evidence_envelope_version"] != EVIDENCE_ENVELOPE_VERSION:
        raise UnsupportedContractVersion("unsupported evidence_envelope_version")
    digest = parse_digest(data["evidence_manifest_digest"], "evidence_manifest_digest")
    body_data = require_mapping(data["evidence_body"], "evidence_body")
    if sha256(canonical_bytes(body_data)).hexdigest() != digest:
        raise InvalidContractValue("evidence manifest digest does not match its body")
    strict_fields(body_data, _EVIDENCE_BODY_FIELDS)
    _ = parse_const(
        body_data["evidence_manifest_version"],
        "evidence_manifest_version",
        EVIDENCE_MANIFEST_VERSION,
    )
    observed = parse_utc_text(body_data["observed_at"], "observed_at")
    expires = parse_utc_text(body_data["expires_at"], "expires_at")
    if expires <= observed:
        raise InvalidContractValue("evidence manifest expires_at must be after observed_at")
    entries: dict[DecisionIdentity, str] = {}
    ordering: list[tuple[str, str, str]] = []
    evidence_items = require_array(body_data["decision_evidence"], "decision_evidence")
    for index, item in enumerate(evidence_items):
        entry = require_mapping(item, f"decision_evidence[{index}]")
        strict_fields(entry, _EVIDENCE_ENTRY_FIELDS)
        identity = parse_decision_identity(entry, f"decision_evidence[{index}]")
        if identity in entries:
            raise InvalidContractValue("evidence manifest contains a duplicate decision identity")
        ordering.append((identity[0], identity[1], identity[2] or ""))
        entries[identity] = parse_digest(entry["evidence_digest"], "evidence_digest")
    if tuple(sorted(ordering)) != tuple(ordering):
        raise InvalidContractValue("evidence manifest.decision_evidence must be sorted")
    body = EvidenceManifestBodyV1(EVIDENCE_MANIFEST_VERSION, observed, expires, entries)
    return EvidenceManifestEnvelopeV1(
        EVIDENCE_ENVELOPE_VERSION,
        digest,
        body,
        parse_signature_set(
            data["signatures"],
            "evidence_manifest.signatures",
            EVIDENCE_SIGNATURE_VERSION,
        ),
    )
