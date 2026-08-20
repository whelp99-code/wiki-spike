"""Closed parse and digest helpers for identity authorization V2."""
from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from typing import Final

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue
from .snapshot_import_parse import parse_digest, parse_string, strict_fields

IDENTITY_AUTH_VERSION: Final = "second-brain-identity-auth-v2"
RESERVED_REVIEW_ACTIONS: Final = frozenset(
    {
        "device.enroll",
        "device.revoke",
        "delegation.grant",
        "delegation.revoke",
        "workspace.owner.transfer",
    }
)
_REF: Final = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")
_DECIMAL: Final = re.compile(r"^(0|[1-9][0-9]*)$")
_POSITIVE: Final = re.compile(r"^[1-9][0-9]*$")
_ACTION: Final = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_DOMAIN: Final = b"wiki-spike.second-brain.identity-auth.v2/"


def identity_auth_digest(kind: str, body: Mapping[str, JsonValue]) -> str:
    try:
        domain = _DOMAIN + kind.encode("ascii") + b"\0"
    except UnicodeEncodeError as exc:
        raise InvalidContractValue("identity authorization kind must be ASCII") from exc
    return sha256(domain + canonical_bytes(dict(body))).hexdigest()


def parse_const(value: JsonValue, field: str, expected: str) -> str:
    parsed = parse_string(value, field)
    if parsed != expected:
        raise InvalidContractValue(f"{field} must be {expected!r}")
    return parsed


def parse_ref(value: JsonValue, field: str, kind: str | None = None) -> str:
    parsed = parse_string(value, field)
    if _REF.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be an opaque keyed reference")
    if kind is not None and not parsed.startswith(f"{kind}:"):
        raise InvalidContractValue(f"{field} must use the {kind} reference kind")
    return parsed


def parse_positive(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    if _POSITIVE.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a canonical positive decimal")
    return parsed


def parse_decimal(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    if _DECIMAL.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a canonical decimal")
    return parsed


def parse_instant(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    try:
        instant = datetime.fromisoformat(parsed)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be a UTC-second instant") from exc
    canonical = instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if parsed != canonical:
        raise InvalidContractValue(f"{field} must use canonical UTC-second spelling")
    return parsed


def require_before(start: str, end: str, field: str) -> None:
    first = datetime.fromisoformat(start)
    second = datetime.fromisoformat(end)
    if first >= second:
        raise InvalidContractValue(f"{field} must be later than its start")


def parse_actions(value: JsonValue, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty array")
    parsed: list[str] = []
    for item in value:
        action = parse_string(item, field)
        if _ACTION.fullmatch(action) is None:
            raise InvalidContractValue(f"{field} contains an invalid action")
        parsed.append(action)
    if parsed != sorted(set(parsed)):
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return tuple(parsed)


def refuse_reserved_review_actions(actions: tuple[str, ...]) -> None:
    if RESERVED_REVIEW_ACTIONS.intersection(actions):
        raise InvalidContractValue("review delegation contains a reserved owner action")


def parse_header(
    data: Mapping[str, JsonValue],
    fields: frozenset[str],
) -> None:
    strict_fields(data, fields)
    _ = parse_const(
        data["identity_auth_version"],
        "identity_auth_version",
        IDENTITY_AUTH_VERSION,
    )


def require_digest(
    actual: JsonValue,
    field: str,
    kind: str,
    body: Mapping[str, JsonValue],
) -> None:
    parsed = parse_digest(actual, field)
    if parsed != identity_auth_digest(kind, body):
        raise InvalidContractValue(f"{field} does not bind contract fields")
