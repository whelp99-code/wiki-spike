"""Shared parse helpers for bounded snapshot import contracts."""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnknownContractField
from .source_discovery import SourceName

_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")


def strict_fields(data: Mapping[str, JsonValue], fields: frozenset[str]) -> None:
    unknown = set(data) - fields
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    missing = fields - set(data)
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")


def parse_string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    if "\x00" in value:
        raise InvalidContractValue(f"{field} must not contain NUL")
    return value


def parse_digest(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    if _DIGEST.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return parsed


def parse_source_name(value: JsonValue) -> SourceName:
    match value:  # noqa: MATCH_OK
        case "me-wiki":
            return "me-wiki"
        case "unified-db":
            return "unified-db"
        case "legacy Mem0/RAG":
            return "legacy Mem0/RAG"
        case _:
            raise InvalidContractValue("source_name is not an approved discovery source")


def import_namespace(source_name: SourceName) -> str:
    """Return the only legal non-serving import namespace for a source."""
    return f"second-brain:import:{source_name}"
