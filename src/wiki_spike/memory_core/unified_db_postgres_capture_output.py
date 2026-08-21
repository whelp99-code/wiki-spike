"""Closed six-file output manifest for metadata capture artifacts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import parse_const, parse_decimal

CAPTURE_ARTIFACT_NAMES: Final = (
    "capture-plan.json",
    "catalog.json",
    "identity.json",
    "output-manifest.json",
    "query-manifest.json",
    "receipt.json",
)
OUTPUT_MANIFEST_VERSION: Final = (
    "second-brain-unified-db-postgres-metadata-capture-output-manifest-v1"
)
OUTPUT_MANIFEST_DOMAIN: Final = (
    "unified-db-postgres-metadata-capture-output-manifest-v1"
)
_MANIFEST_FIELDS: Final = frozenset(
    {
        "manifest_version",
        "source_name",
        "operation",
        "destination_digest",
        "entry_count",
        "entries",
        "manifest_digest",
    }
)
_ENTRY_FIELDS: Final = frozenset({"relative_path", "size_bytes", "content_digest"})


def require_capture_artifact_names(names: tuple[str, ...]) -> None:
    if names == CAPTURE_ARTIFACT_NAMES:
        return
    if len(names) != len(set(names)):
        raise InvalidContractValue("entries must have unique paths without duplicates")
    if tuple(sorted(names)) == CAPTURE_ARTIFACT_NAMES:
        raise InvalidContractValue("entries must be in lexicographic order")
    raise InvalidContractValue("capture artifacts must be the closed six-file set")


@dataclass(frozen=True, slots=True)
class PostgresMetadataCaptureArtifactV1:
    relative_path: str
    size_bytes: str
    content_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresMetadataCaptureArtifactV1:
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
class PostgresMetadataCaptureOutputManifestV1:
    manifest_version: str
    source_name: str
    operation: str
    destination_digest: str
    entry_count: str
    entries: tuple[PostgresMetadataCaptureArtifactV1, ...]
    manifest_digest: str

    @classmethod
    def create(
        cls, destination_digest: str, files: Mapping[str, bytes]
    ) -> PostgresMetadataCaptureOutputManifestV1:
        require_capture_artifact_names(tuple(sorted(files)))
        entries = tuple(
            PostgresMetadataCaptureArtifactV1(
                name, str(len(files[name])), sha256(files[name]).hexdigest()
            )
            for name in CAPTURE_ARTIFACT_NAMES
        )
        provisional = cls(
            OUTPUT_MANIFEST_VERSION,
            "unified-db",
            "METADATA_CAPTURE_ONLY",
            destination_digest,
            "6",
            entries,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"manifest_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> PostgresMetadataCaptureOutputManifestV1:
        strict_fields(data, _MANIFEST_FIELDS)
        version = parse_string(data["manifest_version"], "manifest_version")
        if version != OUTPUT_MANIFEST_VERSION:
            raise UnsupportedContractVersion(f"unsupported manifest_version: {version!r}")
        raw = data["entries"]
        if not isinstance(raw, list):
            raise InvalidContractValue("entries must be an array")
        entries = tuple(
            PostgresMetadataCaptureArtifactV1.from_mapping(item)
            for item in raw
            if isinstance(item, Mapping)
        )
        if len(entries) != len(raw):
            raise InvalidContractValue("every entry must be an object")
        require_capture_artifact_names(tuple(entry.relative_path for entry in entries))
        count = parse_decimal(data["entry_count"], "entry_count")
        if count != "6" or count != str(len(entries)):
            raise InvalidContractValue("entry_count must be 6")
        parsed = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", "METADATA_CAPTURE_ONLY"),
            parse_digest(data["destination_digest"], "destination_digest"),
            count,
            entries,
            parse_digest(data["manifest_digest"], "manifest_digest"),
        )
        if parsed.manifest_digest != parsed.computed_digest():
            raise InvalidContractValue("manifest_digest does not bind output entries")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["manifest_digest"]
        return canonical_ledger_digest(OUTPUT_MANIFEST_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "manifest_version": self.manifest_version,
            "source_name": self.source_name,
            "operation": self.operation,
            "destination_digest": self.destination_digest,
            "entry_count": self.entry_count,
            "entries": [entry.to_mapping() for entry in self.entries],
            "manifest_digest": self.manifest_digest,
        }


def verify_capture_artifact_bytes(
    manifest: PostgresMetadataCaptureOutputManifestV1,
    files: Mapping[str, bytes],
) -> None:
    require_capture_artifact_names(tuple(sorted(files)))
    for entry in manifest.entries:
        content = files[entry.relative_path]
        if sha256(content).hexdigest() != entry.content_digest:
            raise InvalidContractValue("content_digest does not match artifact bytes")
        if str(len(content)) != entry.size_bytes:
            raise InvalidContractValue("size_bytes does not match artifact bytes")
