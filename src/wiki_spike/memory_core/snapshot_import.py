"""Closed non-serving bounded snapshot import contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import (
    import_namespace,
    parse_digest,
    parse_source_name,
    parse_string,
    strict_fields,
)
from .snapshot_import_request import SNAPSHOT_IMPORT_REQUEST_V1, SnapshotImportRequestV1
from .source_discovery import SourceName

BOUNDED_SNAPSHOT_V1: Final = "bounded-source-snapshot-v1"
__all__ = (
    "BOUNDED_SNAPSHOT_V1",
    "SNAPSHOT_IMPORT_REQUEST_V1",
    "BoundedSnapshotV1",
    "SnapshotImportRequestV1",
    "SnapshotRecordV1",
    "import_namespace",
)
_SNAPSHOT_FIELDS: Final = frozenset(
    {
        "snapshot_version",
        "source_name",
        "native_namespace",
        "snapshot_watermark",
        "records",
        "snapshot_digest",
    }
)
_RECORD_FIELDS: Final = frozenset(
    {
        "native_id",
        "revision",
        "watermark",
        "tombstone",
        "relative_path",
        "content_digest",
    }
)


def _relative_path(value: JsonValue) -> str:
    path = parse_string(value, "relative_path")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or "\\" in path
        or path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InvalidContractValue("relative_path must be a canonical relative POSIX path")
    return path


@dataclass(frozen=True, slots=True)
class SnapshotRecordV1:
    native_id: str
    revision: str
    watermark: str
    tombstone: bool
    relative_path: str | None
    content_digest: str | None

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> SnapshotRecordV1:
        strict_fields(data, _RECORD_FIELDS)
        native_id = parse_string(data["native_id"], "native_id")
        revision = parse_string(data["revision"], "revision")
        watermark = parse_string(data["watermark"], "watermark")
        tombstone = data["tombstone"]
        if not isinstance(tombstone, bool):
            raise InvalidContractValue("tombstone must be a boolean")
        if tombstone:
            if data["relative_path"] is not None or data["content_digest"] is not None:
                raise InvalidContractValue("tombstone records must omit path and digest")
            return cls(native_id, revision, watermark, True, None, None)
        return cls(
            native_id,
            revision,
            watermark,
            False,
            _relative_path(data["relative_path"]),
            parse_digest(data["content_digest"], "content_digest"),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "native_id": self.native_id,
            "revision": self.revision,
            "watermark": self.watermark,
            "tombstone": self.tombstone,
            "relative_path": self.relative_path,
            "content_digest": self.content_digest,
        }


def _records(value: JsonValue) -> tuple[SnapshotRecordV1, ...]:
    if not isinstance(value, list):
        raise InvalidContractValue("records must be an array")
    records = tuple(
        SnapshotRecordV1.from_mapping(item)
        for item in value
        if isinstance(item, Mapping)
    )
    if len(records) != len(value):
        raise InvalidContractValue("every record must be an object")
    native_ids = tuple(record.native_id for record in records)
    if len(set(native_ids)) != len(native_ids):
        raise InvalidContractValue("duplicate or conflicting native identity")
    paths = tuple(
        record.relative_path for record in records if record.relative_path is not None
    )
    if len(set(paths)) != len(paths):
        raise InvalidContractValue("duplicate or conflicting identity path")
    return records


@dataclass(frozen=True, slots=True)
class BoundedSnapshotV1:
    snapshot_version: str
    source_name: SourceName
    native_namespace: str
    snapshot_watermark: str
    records: tuple[SnapshotRecordV1, ...]
    snapshot_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> BoundedSnapshotV1:
        strict_fields(data, _SNAPSHOT_FIELDS)
        version = parse_string(data["snapshot_version"], "snapshot_version")
        if version != BOUNDED_SNAPSHOT_V1:
            raise UnsupportedContractVersion(f"unsupported snapshot_version: {version!r}")
        source_name = parse_source_name(data["source_name"])
        namespace = parse_string(data["native_namespace"], "native_namespace")
        if namespace != import_namespace(source_name):
            raise InvalidContractValue("native_namespace is not the source import namespace")
        records = _records(data["records"])
        digest = parse_digest(data["snapshot_digest"], "snapshot_digest")
        snapshot = cls(
            version,
            source_name,
            namespace,
            parse_string(data["snapshot_watermark"], "snapshot_watermark"),
            records,
            digest,
        )
        if digest != snapshot.computed_digest():
            raise InvalidContractValue("snapshot_digest does not bind snapshot fields")
        return snapshot

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["snapshot_digest"]
        return canonical_ledger_digest(BOUNDED_SNAPSHOT_V1, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "snapshot_version": self.snapshot_version,
            "source_name": self.source_name,
            "native_namespace": self.native_namespace,
            "snapshot_watermark": self.snapshot_watermark,
            "records": [record.to_mapping() for record in self.records],
            "snapshot_digest": self.snapshot_digest,
        }

