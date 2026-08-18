"""Explicit per-source snapshot cursor map for fixture export."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields

CURSOR_MAP_VERSION: Final = "second-brain-unified-db-export-cursor-map-v1"
_FIELDS: Final = frozenset({"cursor_map_version", "cursors", "cursor_map_digest"})


@dataclass(frozen=True, slots=True)
class SnapshotCursorMapV1:
    cursor_map_version: str
    cursors: tuple[tuple[str, str], ...]
    cursor_map_digest: str

    @classmethod
    def create(cls, cursors: Mapping[str, str]) -> SnapshotCursorMapV1:
        ordered = tuple((key, cursors[key]) for key in sorted(cursors))
        provisional = cls(CURSOR_MAP_VERSION, ordered, "0" * 64)
        return cls.from_mapping(
            provisional.to_mapping()
            | {"cursor_map_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> SnapshotCursorMapV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["cursor_map_version"], "cursor_map_version")
        if version != CURSOR_MAP_VERSION:
            raise UnsupportedContractVersion(f"unsupported cursor_map_version: {version!r}")
        raw = data["cursors"]
        if not isinstance(raw, dict) or not raw:
            raise InvalidContractValue("cursors must be a non-empty object")
        items = tuple(
            (parse_string(key, "source_id"), parse_string(value, "cursor"))
            for key, value in raw.items()
        )
        keys = tuple(item[0] for item in items)
        if keys != tuple(sorted(set(keys))):
            raise InvalidContractValue("cursors must be unique and lexically sorted")
        parsed = cls(version, items, parse_digest(data["cursor_map_digest"], "cursor_map_digest"))
        if parsed.cursor_map_digest != parsed.computed_digest():
            raise InvalidContractValue("cursor_map_digest does not bind cursors")
        return parsed

    def as_dict(self) -> dict[str, str]:
        return {key: value for key, value in self.cursors}

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["cursor_map_digest"]
        return canonical_ledger_digest("unified-db-export-cursor-map-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "cursor_map_version": self.cursor_map_version,
            "cursors": {key: value for key, value in self.cursors},
            "cursor_map_digest": self.cursor_map_digest,
        }
