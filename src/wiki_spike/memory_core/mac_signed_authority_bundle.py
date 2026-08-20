"""Parse the Mac signed-authority bundle against a closed field set."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .mac_signed_authority_evidence import (
    EvidenceManifestEnvelopeV1,
    parse_evidence_manifest,
)
from .mac_signed_authority_parse import (
    AUTHORITY_BUNDLE_VERSION,
    EVIDENCE_ENVELOPE_VERSION,
    EVIDENCE_MANIFEST_VERSION,
    EVIDENCE_SIGNATURE_VERSION,
    EVIDENCE_SIGNING_DOMAIN,
    RESOLUTION_RECEIPT_VERSION,
    load_canonical_object,
    parse_record_name,
    parse_workspace_ref,
    require_array,
    require_mapping,
    strict_fields,
)
from .mac_signed_authority_receipt import (
    ResolutionReceiptV1,
    parse_resolution_receipt,
)
from .second_brain_contracts import (
    DecisionRecordV1,
    SignedSecondBrainContractEnvelopeV1,
)

_BUNDLE_FIELDS: Final = frozenset(
    {
        "authority_bundle_version",
        "workspace_ref",
        "decision_records",
        "aggregate",
        "evidence_manifest",
        "resolution_receipt",
    }
)
_RECORD_FIELDS: Final = frozenset({"name", "record"})


@dataclass(frozen=True, slots=True)
class DecisionRecordBindingV1:
    name: str
    record: DecisionRecordV1


@dataclass(frozen=True, slots=True)
class SignedAuthorityBundleV1:
    authority_bundle_version: str
    workspace_ref: str
    decision_records: tuple[DecisionRecordBindingV1, ...]
    aggregate: SignedSecondBrainContractEnvelopeV1
    evidence_manifest: EvidenceManifestEnvelopeV1
    resolution_receipt: ResolutionReceiptV1


def _parse_binding(value: JsonValue, field: str) -> DecisionRecordBindingV1:
    data = require_mapping(value, field)
    strict_fields(data, _RECORD_FIELDS)
    record = require_mapping(data["record"], f"{field}.record")
    return DecisionRecordBindingV1(
        parse_record_name(data["name"]),
        DecisionRecordV1.from_mapping(record),
    )


def _parse_decision_records(value: JsonValue) -> tuple[DecisionRecordBindingV1, ...]:
    items = require_array(value, "decision_records")
    if not items:
        raise InvalidContractValue("decision_records must be a non-empty array")
    bindings = tuple(
        _parse_binding(item, f"decision_records[{index}]") for index, item in enumerate(items)
    )
    names = tuple(item.name for item in bindings)
    if names != tuple(sorted(names)) or len(set(names)) != len(names):
        raise InvalidContractValue("decision_records names must be sorted and unique")
    return bindings


def parse_mac_signed_authority_bundle(raw: bytes) -> SignedAuthorityBundleV1:
    data = load_canonical_object(raw)
    strict_fields(data, _BUNDLE_FIELDS)
    if data["authority_bundle_version"] != AUTHORITY_BUNDLE_VERSION:
        raise UnsupportedContractVersion("unsupported authority_bundle_version")
    return SignedAuthorityBundleV1(
        AUTHORITY_BUNDLE_VERSION,
        parse_workspace_ref(data["workspace_ref"]),
        _parse_decision_records(data["decision_records"]),
        SignedSecondBrainContractEnvelopeV1.from_mapping(
            require_mapping(data["aggregate"], "aggregate")
        ),
        parse_evidence_manifest(data["evidence_manifest"]),
        parse_resolution_receipt(data["resolution_receipt"]),
    )


__all__ = (
    "AUTHORITY_BUNDLE_VERSION",
    "EVIDENCE_ENVELOPE_VERSION",
    "EVIDENCE_MANIFEST_VERSION",
    "EVIDENCE_SIGNATURE_VERSION",
    "EVIDENCE_SIGNING_DOMAIN",
    "RESOLUTION_RECEIPT_VERSION",
    "DecisionRecordBindingV1",
    "SignedAuthorityBundleV1",
    "parse_mac_signed_authority_bundle",
)
