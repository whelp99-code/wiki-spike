"""Canonical export aggregate-byte accounting."""
from __future__ import annotations

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportRowV1

HARD_CAP = 1048576


def serialized_row_bytes(row: UnifiedDbExportRowV1) -> int:
    return len(
        canonical_bytes(
            {
                "source_id": row.source_id,
                "native_id": row.native_id,
                "revision": row.revision,
                "content_hash": row.content_hash,
                "watermark": row.watermark,
                "tombstone": row.tombstone,
            }
        )
    )


def aggregate_export_bytes(rows: tuple[UnifiedDbExportRowV1, ...]) -> int:
    total = 0
    for row in rows:
        total += serialized_row_bytes(row)
        if row.body is not None:
            total += len(row.body)
    return total
