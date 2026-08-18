"""Deterministic package-relative payload manifest."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import parse_decimal

PAYLOAD_MANIFEST_VERSION: Final = "second-brain-unified-db-export-payload-manifest-v1"
_MANIFEST_FIELDS: Final = frozenset(
    {"manifest_version", "entry_count", "entries", "manifest_digest"}
)
_ENTRY_FIELDS: Final = frozenset({"relative_path", "size_bytes", "content_digest"})


@dataclass(frozen=True, slots=True)
class PayloadManifestEntryV1:
    relative_path: str
    size_bytes: str
    content_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PayloadManifestEntryV1:
        strict_fields(data, _ENTRY_FIELDS)
        return cls(
            parse_string(data["relative_path"], "relative_path"),
            parse_decimal(data["size_bytes"], "size_bytes"),
            parse_digest(data["content_digest"], "content_digest"),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "relative_path": self.relative_path,
            "size_bytes": self.size_bytes,
            "content_digest": self.content_digest,
        }


@dataclass(frozen=True, slots=True)
class PayloadManifestV1:
    manifest_version: str
    entry_count: str
    entries: tuple[PayloadManifestEntryV1, ...]
    manifest_digest: str

    @classmethod
    def create(cls, files: tuple[tuple[str, bytes], ...]) -> PayloadManifestV1:
        entries = tuple(
            PayloadManifestEntryV1(
                relative,
                str(len(content)),
                sha256(content).hexdigest(),
            )
            for relative, content in files
        )
        ordered = tuple(sorted(entries, key=lambda entry: entry.relative_path))
        provisional = cls(PAYLOAD_MANIFEST_VERSION, str(len(ordered)), ordered, "0" * 64)
        return cls.from_mapping(
            provisional.to_mapping() | {"manifest_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PayloadManifestV1:
        strict_fields(data, _MANIFEST_FIELDS)
        version = parse_string(data["manifest_version"], "manifest_version")
        if version != PAYLOAD_MANIFEST_VERSION:
            raise UnsupportedContractVersion(f"unsupported manifest_version: {version!r}")
        raw = data["entries"]
        if not isinstance(raw, list):
            raise InvalidContractValue("entries must be an array")
        entries = tuple(
            PayloadManifestEntryV1.from_mapping(item)
            for item in raw
            if isinstance(item, Mapping)
        )
        if len(entries) != len(raw):
            raise InvalidContractValue("every entry must be an object")
        paths = tuple(entry.relative_path for entry in entries)
        if paths != tuple(sorted(set(paths))):
            raise InvalidContractValue("entries must have unique lexically sorted paths")
        count = parse_decimal(data["entry_count"], "entry_count")
        if count != str(len(entries)):
            raise InvalidContractValue("entry_count does not match entries")
        parsed = cls(
            version,
            count,
            entries,
            parse_digest(data["manifest_digest"], "manifest_digest"),
        )
        if parsed.manifest_digest != parsed.computed_digest():
            raise InvalidContractValue("manifest_digest does not bind payload entries")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["manifest_digest"]
        return canonical_ledger_digest("unified-db-export-payload-manifest-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "manifest_version": self.manifest_version,
            "entry_count": self.entry_count,
            "entries": [entry.to_mapping() for entry in self.entries],
            "manifest_digest": self.manifest_digest,
        }
