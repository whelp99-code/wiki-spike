"""Public contracts for immutable database-snapshot decoding."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, NewType

TableName = NewType("TableName", str)
NativeId = NewType("NativeId", str)
Fingerprint = NewType("Fingerprint", str)

SNAPSHOT_VERSION: Final = "database-snapshot-v1"
SOURCE_PROFILE: Final = "Database snapshot"
MAX_SNAPSHOT_BYTES: Final = 67_108_864


class DatabaseSnapshotQuarantineReason(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    SOURCE_MUTATED = "SOURCE_MUTATED"
    LIVE_STORE = "LIVE_STORE"
    UNREADABLE = "UNREADABLE"
    INVALID_FORMAT = "INVALID_FORMAT"


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotReadProofV1:
    tables_read: tuple[TableName, ...]
    row_reads: tuple[tuple[TableName, int], ...]
    statements: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotRowV1:
    table: TableName
    native_id: NativeId
    fields: tuple[tuple[str, str], ...]
    revision: str


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotAcceptedScan:
    snapshot_version: str
    source_profile: str
    fingerprint: Fingerprint
    items: tuple[DatabaseSnapshotRowV1, ...]
    proof: DatabaseSnapshotReadProofV1


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotStoreQuarantined:
    reason: DatabaseSnapshotQuarantineReason


@dataclass(frozen=True, slots=True)
class DatabaseSnapshotScopeDisabled:
    source_profile: str = SOURCE_PROFILE


type DatabaseSnapshotReadResult = (
    DatabaseSnapshotAcceptedScan | DatabaseSnapshotStoreQuarantined | DatabaseSnapshotScopeDisabled
)
type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]
