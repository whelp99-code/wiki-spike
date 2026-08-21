"""Shared parsers for live-export identity, mapping, and plan contracts."""
from __future__ import annotations

import re
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue
from .snapshot_import_parse import parse_string
from .unified_db_snapshot_export import parse_decimal

UINT64_MAX: Final = 18446744073709551615
OID_MAX: Final = 4294967295
SERVER_VERSION_MIN: Final = 90000
SERVER_VERSION_MAX: Final = 1999999
_TOKEN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_IDENT: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TABLE: Final = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$"
)
_MAPPER_VERSION: Final = re.compile(r"^v[1-9][0-9]*$")


def parse_ascii_token(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if _TOKEN.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be an ASCII token")
    return text


def parse_identifier(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if _IDENT.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be an ASCII identifier")
    return text


def parse_qualified_table(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if _TABLE.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be schema.table")
    return text


def parse_mapper_version(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if _MAPPER_VERSION.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be a version token")
    return text


def parse_canonical_uint(value: JsonValue, field: str, maximum: int) -> str:
    text = parse_decimal(value, field)
    if int(text) > maximum:
        raise InvalidContractValue(f"{field} exceeds the allowed range")
    return text


def parse_server_version_num(value: JsonValue, field: str) -> str:
    text = parse_decimal(value, field)
    number = int(text)
    if number < SERVER_VERSION_MIN or number > SERVER_VERSION_MAX:
        raise InvalidContractValue(f"{field} is malformed")
    return text


def require_column(name: str, columns: tuple[str, ...], field: str) -> str:
    if name not in columns:
        raise InvalidContractValue(f"{field} must be one of the closed columns")
    return name
