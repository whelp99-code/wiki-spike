"""Bind fixture rows onto BoundedSnapshotV1 and package digests."""
from __future__ import annotations

from hashlib import sha256

from .contracts import JsonValue
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import import BOUNDED_SNAPSHOT_V1, BoundedSnapshotV1, SnapshotRecordV1
from .snapshot_import_parse import import_namespace
from .unified_db_snapshot_export import UnifiedDbExportError, UnifiedDbExportRowV1
from .unified_db_snapshot_export_cursors import SnapshotCursorMapV1


def bind_native_id(source_id: str, native_id: str) -> str:
    return canonical_ledger_digest(
        "unified-db-export-native-id-v1",
        {"source_id": source_id, "native_id": native_id},
    )


def payload_name(index: int) -> str:
    return f"{index:08d}.json"


def build_bounded_snapshot(
    rows: tuple[UnifiedDbExportRowV1, ...],
    cursors: SnapshotCursorMapV1,
) -> tuple[BoundedSnapshotV1, tuple[tuple[str, bytes], ...]]:
    records: list[SnapshotRecordV1] = []
    files: list[tuple[str, bytes]] = []
    live_index = 0
    for row in rows:
        native = bind_native_id(row.source_id, row.native_id)
        if row.tombstone:
            records.append(
                SnapshotRecordV1(native, row.revision, row.watermark, True, None, None)
            )
            continue
        if row.body is None:
            raise UnifiedDbExportError("live row is missing body")
        relative = payload_name(live_index)
        live_index += 1
        records.append(
            SnapshotRecordV1(
                native,
                row.revision,
                row.watermark,
                False,
                relative,
                row.content_hash,
            )
        )
        files.append((relative, row.body))
    body: dict[str, JsonValue] = {
        "snapshot_version": BOUNDED_SNAPSHOT_V1,
        "source_name": "unified-db",
        "native_namespace": import_namespace("unified-db"),
        "snapshot_watermark": cursors.cursor_map_digest,
        "records": [record.to_mapping() for record in records],
    }
    snapshot = BoundedSnapshotV1.from_mapping(
        body
        | {
            "snapshot_digest": canonical_ledger_digest(
                "bounded-source-snapshot-v1",
                body,
            )
        }
    )
    return snapshot, tuple(files)


def package_digest(
    snapshot_digest: str,
    files: tuple[tuple[str, bytes], ...],
    profile_digest: str,
    plan_digest: str,
    payload_manifest_digest: str,
    cursor_map_digest: str,
) -> str:
    return canonical_ledger_digest(
        "unified-db-export-package-v1",
        {
            "snapshot_digest": snapshot_digest,
            "payload": [
                {
                    "relative_path": relative,
                    "content_digest": sha256(content).hexdigest(),
                }
                for relative, content in files
            ],
            "payload_manifest_digest": payload_manifest_digest,
            "cursor_map_digest": cursor_map_digest,
            "profile_digest": profile_digest,
            "plan_digest": plan_digest,
        },
    )
