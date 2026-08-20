"""Canonical JSON loaders and field helpers for Mac signed authority."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue
from .second_brain_contracts import Ed25519SignatureEnvelopeV1
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import UnifiedDbExportError
from .unified_db_snapshot_export_json import decode_json_object

AUTHORITY_BUNDLE_VERSION: Final = "second-brain-mac-signed-authority-v1"
EVIDENCE_MANIFEST_VERSION: Final = "second-brain-evidence-manifest-v1"
EVIDENCE_ENVELOPE_VERSION: Final = "second-brain-evidence-manifest-envelope-v1"
EVIDENCE_SIGNATURE_VERSION: Final = "second-brain-evidence-manifest-signature-v1"
EVIDENCE_SIGNING_DOMAIN: Final = b"wiki-spike.second-brain.evidence-manifest.v1\x00"
RESOLUTION_RECEIPT_VERSION: Final = "second-brain-contract-resolution-receipt-v1"

_WORKSPACE_REF: Final = re.compile(r"^workspace:[0-9a-f]{64}$")
_UTC: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_RECORD_NAME: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def load_canonical_object(raw: bytes) -> dict[str, JsonValue]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidContractValue("bundle is not canonical JSON") from exc
    try:
        converted = decode_json_object(text)
    except UnifiedDbExportError as extra:
        raise InvalidContractValue(str(extra)) from extra
    if canonical_bytes(converted) != raw:
        raise InvalidContractValue("bundle is not canonical JSON")
    return converted


def parse_const(value: JsonValue, field: str, expected: str) -> str:
    parsed = parse_string(value, field)
    if parsed != expected:
        raise InvalidContractValue(f"{field} must be {expected!r}")
    return parsed


def parse_workspace_ref(value: JsonValue) -> str:
    parsed = parse_string(value, "workspace_ref")
    if _WORKSPACE_REF.fullmatch(parsed) is None:
        raise InvalidContractValue("workspace_ref must be a workspace digest reference")
    return parsed


def parse_record_name(value: JsonValue) -> str:
    parsed = parse_string(value, "name")
    if _RECORD_NAME.fullmatch(parsed) is None:
        raise InvalidContractValue("decision record name is invalid")
    return parsed


def parse_utc_text(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    if _UTC.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp")
    try:
        _ = datetime.strptime(parsed, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp") from exc
    return parsed


def parse_bool(value: JsonValue, field: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidContractValue(f"{field} must be a boolean")
    return value


def require_mapping(value: JsonValue, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise InvalidContractValue(f"{field} must be an object")
    return value


def require_array(value: JsonValue, field: str) -> list[JsonValue]:
    if not isinstance(value, list):
        raise InvalidContractValue(f"{field} must be an array")
    return value


def parse_signature_set(
    value: JsonValue,
    field: str,
    version: str,
) -> tuple[Ed25519SignatureEnvelopeV1, ...]:
    items = require_array(value, field)
    signatures = tuple(
        Ed25519SignatureEnvelopeV1.from_mapping(
            require_mapping(item, f"{field}[{index}]"), version=version
        )
        for index, item in enumerate(items)
    )
    if len(signatures) != 2:
        raise InvalidContractValue(f"{field} requires exactly approver and owner signatures")
    if tuple(item.role for item in signatures) != ("approver", "owner"):
        raise InvalidContractValue(f"{field} must be canonically ordered approver then owner")
    if (
        signatures[0].key_id == signatures[1].key_id
        or signatures[0].public_key_b64 == signatures[1].public_key_b64
    ):
        raise InvalidContractValue(f"{field} owner and approver must have distinct identities")
    return signatures


def optional_string(value: JsonValue, field: str) -> str | None:
    if value is None:
        return None
    return parse_string(value, field)


def optional_digest(value: JsonValue, field: str) -> str | None:
    if value is None:
        return None
    return parse_digest(value, field)


def parse_decision_identity(
    data: Mapping[str, JsonValue], field: str
) -> tuple[str, str, str | None]:
    decision_id = parse_string(data["decision_id"], f"{field}.decision_id")
    scope_kind = parse_string(data["scope_kind"], f"{field}.scope_kind")
    scope_name = data["scope_name"]
    if scope_name is not None and (not isinstance(scope_name, str) or not scope_name):
        raise InvalidContractValue(
            f"{field}.scope_name must be a non-empty string or null"
        )
    return decision_id, scope_kind, scope_name


__all__ = (
    "AUTHORITY_BUNDLE_VERSION",
    "EVIDENCE_ENVELOPE_VERSION",
    "EVIDENCE_MANIFEST_VERSION",
    "EVIDENCE_SIGNATURE_VERSION",
    "EVIDENCE_SIGNING_DOMAIN",
    "RESOLUTION_RECEIPT_VERSION",
    "load_canonical_object",
    "optional_digest",
    "optional_string",
    "parse_bool",
    "parse_const",
    "parse_decision_identity",
    "parse_record_name",
    "parse_signature_set",
    "parse_utc_text",
    "parse_workspace_ref",
    "require_array",
    "require_mapping",
    "strict_fields",
)
