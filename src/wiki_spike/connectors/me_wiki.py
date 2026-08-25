"""Typed canonical me-wiki migration reader."""
from __future__ import annotations

from hashlib import sha1, sha256
from pathlib import Path
from typing import Final

from wiki_spike.connectors.markdown import MarkdownPageV1, MarkdownVaultAdapter
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.snapshot_import import (
    BOUNDED_SNAPSHOT_V1,
    BoundedSnapshotV1,
    SnapshotRecordV1,
)
from wiki_spike.memory_core.snapshot_import_parse import import_namespace

SOURCE_NAME: Final = "me-wiki"


class MeWikiMigrationReader:
    """Read a local me-wiki export as a bounded migration snapshot."""

    source_name: Final = SOURCE_NAME

    def read_export(
        self,
        root: Path,
        watermark: str,
        previous: BoundedSnapshotV1 | None = None,
    ) -> BoundedSnapshotV1:
        prior = () if previous is None else tuple(
            (record.native_id, record.revision)
            for record in previous.records
            if not record.tombstone
        )
        vault = MarkdownVaultAdapter().read_tree(root, prior, previous is not None)
        records = tuple(
            sorted(
                (_record_from_page(root, page, watermark) for page in vault.pages),
                key=lambda record: record.native_id,
            )
        )
        return _bounded_snapshot(watermark, records)


def git_blob_oid(payload: bytes) -> str:
    """Return the git blob object ID for one raw export payload."""
    return sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload, usedforsecurity=False).hexdigest()


def _record_from_page(root: Path, page: MarkdownPageV1, watermark: str) -> SnapshotRecordV1:
    if page.tombstone or page.relative_path is None:
        return SnapshotRecordV1(page.native_id, page.revision, watermark, True, None, None, None)
    raw = (root / page.relative_path).read_bytes()
    return SnapshotRecordV1(
        page.relative_path,
        git_blob_oid(raw),
        watermark,
        False,
        page.relative_path,
        sha256(raw).hexdigest(),
        page.keyed_dedupe_ref,
    )


def _bounded_snapshot(watermark: str, records: tuple[SnapshotRecordV1, ...]) -> BoundedSnapshotV1:
    encoded: list[JsonValue] = [record.to_mapping() for record in records]
    body: dict[str, JsonValue] = {
        "snapshot_version": BOUNDED_SNAPSHOT_V1,
        "source_name": SOURCE_NAME,
        "native_namespace": import_namespace(SOURCE_NAME),
        "snapshot_watermark": watermark,
        "records": encoded,
    }
    return BoundedSnapshotV1.from_mapping(
        body | {"snapshot_digest": canonical_ledger_digest(BOUNDED_SNAPSHOT_V1, body)}
    )


__all__ = ["MeWikiMigrationReader", "git_blob_oid"]
