"""Strict fixture-only unified-db export contracts."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .snapshot_import_parse import parse_digest, parse_string, strict_fields

PROFILE_VERSION: Final = "second-brain-unified-db-export-profile-v1"
PLAN_VERSION: Final = "second-brain-unified-db-export-plan-v1"
AUTHORITY_VERSION: Final = "second-brain-unified-db-export-fixture-authority-v1"
AUTHORITY_KIND: Final = "FIXTURE_ONLY"
EXPORT_ONLY: Final = "EXPORT_ONLY"
IDENTITY_MAPPING: Final = "source_id+native_id"
REVISION_MAPPING: Final = "declared_revision"
WATERMARK_MAPPING: Final = "explicit_cursor_map"
DELETION_POLICY: Final = "EXPLICIT_TOMBSTONE_ONLY"
HISTORY_POLICY: Final = "DECLARED_ROWS_ONLY"
ABSENCE_POLICY: Final = "ABSENCE_IS_NOT_DELETION"
ROW_ORDER: Final = "source_id,native_id"
MAX_BOUND: Final = "1048576"
_DECIMAL: Final = re.compile(r"^(0|[1-9][0-9]*)$")
_ROW_FIELDS: Final = frozenset(
    {
        "source_id",
        "native_id",
        "content_hash",
        "revision",
        "watermark",
        "tombstone",
        "body_hex",
    }
)
_AUTHORITY_FIELDS: Final = frozenset({"authority_version", "authority_kind"})


class UnifiedDbExportError(ValueError):
    """Export refused because safety or contract could not be proven."""


class PackageDurabilityUncertain(UnifiedDbExportError):
    """Package is published but parent durability could not be proven."""

    destination: str
    receipt_digest: str

    def __init__(self, destination: str, receipt_digest: str) -> None:
        super().__init__(
            "PUBLISHED_DURABILITY_UNCERTAIN destination="
            + destination
            + " receipt_digest="
            + receipt_digest
            + " reconciliation required"
        )
        self.destination = destination
        self.receipt_digest = receipt_digest


def parse_decimal(value: JsonValue, field: str) -> str:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a canonical decimal string")
    return value


def parse_false(value: JsonValue, field: str) -> bool:
    if value is not False:
        raise InvalidContractValue(f"{field} must be false")
    return False


def parse_true(value: JsonValue, field: str) -> bool:
    if value is not True:
        raise InvalidContractValue(f"{field} must be true")
    return True


def parse_names(value: JsonValue, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty array")
    names = tuple(parse_string(item, field) for item in value)
    if len(set(names)) != len(names):
        raise InvalidContractValue(f"{field} must be unique")
    return names


def parse_const(value: JsonValue, field: str, expected: str) -> str:
    parsed = parse_string(value, field)
    if parsed != expected:
        raise InvalidContractValue(f"{field} must be {expected}")
    return parsed


@dataclass(frozen=True, slots=True)
class FixtureExportAuthorityV1:
    authority_version: str
    authority_kind: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> FixtureExportAuthorityV1:
        strict_fields(data, _AUTHORITY_FIELDS)
        version = parse_string(data["authority_version"], "authority_version")
        if version != AUTHORITY_VERSION:
            raise UnsupportedContractVersion(f"unsupported authority_version: {version!r}")
        kind = parse_const(data["authority_kind"], "authority_kind", AUTHORITY_KIND)
        return cls(version, kind)

    def export_live(self, *_args: object, **_kwargs: object) -> None:
        raise UnifiedDbExportError("fixture-only authority cannot call live export")

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "authority_version": self.authority_version,
            "authority_kind": self.authority_kind,
        }


@dataclass(frozen=True, slots=True)
class UnifiedDbExportRowV1:
    source_id: str
    native_id: str
    content_hash: str
    revision: str
    watermark: str
    tombstone: bool
    body: bytes | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbExportRowV1:
        strict_fields(data, _ROW_FIELDS)
        tombstone = data["tombstone"]
        if not isinstance(tombstone, bool):
            raise InvalidContractValue("tombstone must be a boolean")
        digest = parse_digest(data["content_hash"], "content_hash")
        raw = data["body_hex"]
        if tombstone:
            if raw is not None:
                raise InvalidContractValue("tombstone rows must omit body_hex")
            body = None
        else:
            if not isinstance(raw, str) or not raw:
                raise InvalidContractValue("body_hex must be lowercase hex")
            try:
                body = bytes.fromhex(raw)
            except ValueError as exc:
                raise InvalidContractValue("body_hex must be lowercase hex") from exc
            if raw != body.hex() or sha256(body).hexdigest() != digest:
                raise InvalidContractValue("content_hash does not match body")
        return cls(
            parse_string(data["source_id"], "source_id"),
            parse_string(data["native_id"], "native_id"),
            digest,
            parse_string(data["revision"], "revision"),
            parse_string(data["watermark"], "watermark"),
            tombstone,
            body,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "source_id": self.source_id,
            "native_id": self.native_id,
            "content_hash": self.content_hash,
            "revision": self.revision,
            "watermark": self.watermark,
            "tombstone": self.tombstone,
            "body_hex": None if self.body is None else self.body.hex(),
        }
