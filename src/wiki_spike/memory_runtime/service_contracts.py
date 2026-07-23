"""Shared strict helpers for Phase 4 service contracts (P4-03+).

The helpers deliberately keep values JSON-canonical, content-bound, and
provider/storage independent.  Runtime services use references and digests at
boundaries; source bodies and credentials are never placed in public metadata.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
import re
import unicodedata
from typing import Any, Iterable, Mapping, Sequence

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_runtime.contracts import canonical_bytes
from wiki_spike.memory_runtime.errors import InvalidContractValue, UnknownContractField

HEX64 = re.compile(r"^[0-9a-f]{64}$")
SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
UTC_SECOND = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
CANONICAL_INT = re.compile(r"^(0|[1-9][0-9]*)$")

SENSITIVITY_RANK = {"public": 0, "internal": 1, "private": 2, "secret": 3}
MODALITY_RANK = {"possible": 0, "likely": 1, "asserted": 2, "explicit": 3}


def strict_mapping(
    data: Mapping[str, object], allowed: Iterable[str], required: Iterable[str], label: str
) -> dict[str, object]:
    if not isinstance(data, Mapping):
        raise InvalidContractValue(f"{label} must be an object")
    allowed_set, required_set = set(allowed), set(required)
    unknown = set(data) - allowed_set
    missing = required_set - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def nonempty(value: object, field: str, maximum: int = 1024) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a string")
    value = unicodedata.normalize("NFC", value)
    if not value or not value.strip() or len(value) > maximum:
        raise InvalidContractValue(f"{field} must be a bounded non-empty string")
    return value


def optional_nonempty(value: object, field: str, maximum: int = 1024) -> str | None:
    if value is None:
        return None
    return nonempty(value, field, maximum)


def safe_code(value: object, field: str) -> str:
    text = nonempty(value, field, 128)
    if not SAFE_CODE.fullmatch(text):
        raise InvalidContractValue(f"{field} must be a canonical lowercase code")
    return text


def hex64(value: object, field: str) -> str:
    text = nonempty(value, field, 64)
    if not HEX64.fullmatch(text):
        raise InvalidContractValue(f"{field} must be lowercase SHA-256 hex")
    return text


def canonical_int(value: object, field: str, *, maximum: int | None = None) -> int:
    if not isinstance(value, str) or not CANONICAL_INT.fullmatch(value):
        raise InvalidContractValue(f"{field} must be a canonical non-negative integer string")
    result = int(value)
    if maximum is not None and result > maximum:
        raise InvalidContractValue(f"{field} exceeds maximum {maximum}")
    return result


def utc_second(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not UTC_SECOND.fullmatch(value):
        raise InvalidContractValue(f"{field} must be canonical UTC seconds")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} is invalid") from exc
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise InvalidContractValue(f"{field} is not canonical")
    return parsed


def format_utc(value: datetime) -> str:
    if value.tzinfo is None:
        raise InvalidContractValue("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def string_tuple(
    value: object,
    field: str,
    *,
    allow_empty: bool = True,
    sorted_unique: bool = False,
    codes: bool = False,
) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array")
    result = tuple((safe_code(item, field) if codes else nonempty(item, field)) for item in value)
    if not allow_empty and not result:
        raise InvalidContractValue(f"{field} must not be empty")
    if sorted_unique and tuple(sorted(set(result))) != result:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return result


def canonical_object(value: object, field: str) -> dict[str, JsonValue]:
    if not isinstance(value, Mapping):
        raise InvalidContractValue(f"{field} must be an object")
    normalized = json.loads(canonical_bytes({"value": value}).decode("utf-8"))["value"]
    if not isinstance(normalized, dict):
        raise InvalidContractValue(f"{field} must remain an object")
    return normalized


def canonical_array(value: object, field: str) -> list[JsonValue]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array")
    normalized = json.loads(canonical_bytes({"value": list(value)}).decode("utf-8"))["value"]
    if not isinstance(normalized, list):
        raise InvalidContractValue(f"{field} must remain an array")
    return normalized


def content_id(domain: str, payload: Mapping[str, Any]) -> str:
    return sha256(domain.encode("utf-8") + b"\x00" + canonical_bytes(payload)).hexdigest()


def body_digest(domain: str, body: str) -> str:
    normalized = unicodedata.normalize("NFC", body)
    return sha256(domain.encode("utf-8") + b"\x00" + normalized.encode("utf-8")).hexdigest()


def sensitivity(value: object, field: str = "sensitivity") -> str:
    text = safe_code(value, field)
    if text not in SENSITIVITY_RANK:
        raise InvalidContractValue(f"{field} is unsupported")
    return text


def modality(value: object, field: str = "modality") -> str:
    text = safe_code(value, field)
    if text not in MODALITY_RANK:
        raise InvalidContractValue(f"{field} is unsupported")
    return text


def ensure_no_secret_keys(value: Mapping[str, object], *, label: str = "payload") -> None:
    forbidden = {
        "api_key", "token", "access_token", "refresh_token", "password", "secret",
        "credential", "authorization", "cookie", "provider_client", "private_key",
    }
    for key, item in value.items():
        lowered = key.lower()
        if lowered in forbidden or any(part in lowered for part in ("api_key", "access_token", "password", "private_key")):
            raise InvalidContractValue(f"{label} contains forbidden credential field: {key}")
        if isinstance(item, Mapping):
            ensure_no_secret_keys(item, label=label)
        elif isinstance(item, list):
            for child in item:
                if isinstance(child, Mapping):
                    ensure_no_secret_keys(child, label=label)


def sorted_unique(items: Sequence[str], field: str) -> tuple[str, ...]:
    result = tuple(items)
    if tuple(sorted(set(result))) != result:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return result


def verify_content_id(current: str, domain: str, mapping: Mapping[str, object], id_field: str, label: str) -> None:
    payload = dict(mapping)
    payload.pop(id_field, None)
    if current != content_id(domain, payload):
        raise InvalidContractValue(f"{label} mismatch")
