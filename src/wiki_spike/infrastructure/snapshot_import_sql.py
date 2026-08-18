"""SQLite row helpers for non-serving snapshot import commitments."""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from wiki_spike.infrastructure.snapshot_import_seal import (
    ImportKeys,
    SealedRecord,
    keyed_commit,
    record_set_digest,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.snapshot_import import SnapshotImportRequestV1
from wiki_spike.memory_core.snapshot_import_result import IMPORT_TRANSITIONS

_READY = "READY_NON_SERVING"
_NON_SERVING = "NON_SERVING"
_NON_ELIGIBLE = "NON_ELIGIBLE"
_RECONCILED = "RECONCILED"


class SnapshotImportStoreError(ValueError):
    """Import persistence refused an exact binding or restore commitment."""


def now_utc() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def require_connection(connection: sqlite3.Connection | None) -> sqlite3.Connection:
    if connection is None:
        raise SnapshotImportStoreError("an initialized LifecycleDatabase is required")
    connection.row_factory = sqlite3.Row
    return connection


def commitments(keys: ImportKeys, sealed: tuple[SealedRecord, ...]) -> tuple[str, str, str]:
    record_set = record_set_digest(keys, sealed)
    previous = "0" * 64
    head = previous
    for index, state in enumerate(IMPORT_TRANSITIONS):
        head = keyed_commit(
            keys,
            "transition-v1",
            canonical_bytes(
                {
                    "previous": previous,
                    "ordinal": str(index),
                    "state": state,
                    "record_set_digest": record_set,
                }
            ),
        )
        previous = head
    reconciliation = keyed_commit(
        keys,
        "reconciliation-v1",
        canonical_bytes({"state": _RECONCILED, "record_set_digest": record_set}),
    )
    return record_set, head, reconciliation


def cohort_row(connection: sqlite3.Connection, cohort_id: str) -> sqlite3.Row | None:
    return require_connection(connection).execute(
        "SELECT * FROM snapshot_import_cohort WHERE cohort_id=?",
        (cohort_id,),
    ).fetchone()


def record_rows(connection: sqlite3.Connection, cohort_id: str) -> list[sqlite3.Row]:
    return list(
        require_connection(connection).execute(
            "SELECT * FROM snapshot_import_record WHERE cohort_id=? "
            "ORDER BY CAST(record_sequence AS INTEGER)",
            (cohort_id,),
        )
    )


def insert_import(
    connection: sqlite3.Connection,
    keys: ImportKeys,
    request: SnapshotImportRequestV1,
    sealed: tuple[SealedRecord, ...],
    refs: tuple[str, ...],
) -> None:
    record_set, transition_head, reconciliation = commitments(keys, sealed)
    created = now_utc()
    connection.execute(
        "INSERT INTO snapshot_import_cohort VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            request.cohort_id,
            request.target_namespace,
            request.source_name,
            request.snapshot_digest,
            request.discovery_manifest_digest,
            request.resolved_scope_digest,
            _READY,
            _NON_SERVING,
            _NON_ELIGIBLE,
            str(len(sealed)),
            record_set,
            transition_head,
            reconciliation,
            created,
        ),
    )
    connection.executemany(
        "INSERT INTO snapshot_import_record VALUES (?,?,?,?,?,?,?,?)",
        [
            (
                request.cohort_id,
                item.ordinal,
                item.object_digest,
                item.revision_digest,
                item.watermark_digest,
                item.tombstone_state,
                item.payload_digest,
                refs[index],
            )
            for index, item in enumerate(sealed)
        ],
    )
    previous = "0" * 64
    for index, state in enumerate(IMPORT_TRANSITIONS):
        digest = keyed_commit(
            keys,
            "transition-v1",
            canonical_bytes(
                {
                    "previous": previous,
                    "ordinal": str(index),
                    "state": state,
                    "record_set_digest": record_set,
                }
            ),
        )
        connection.execute(
            "INSERT INTO snapshot_import_transition VALUES (?,?,?,?,?)",
            (request.cohort_id, str(index), state, digest, created),
        )
        previous = digest
    connection.execute(
        "INSERT INTO snapshot_import_reconciliation VALUES (?,?,?,?,?)",
        (request.cohort_id, _RECONCILED, reconciliation, record_set, created),
    )


def require_history(
    connection: sqlite3.Connection,
    keys: ImportKeys,
    cohort_id: str,
    request_row: sqlite3.Row,
    rows: list[sqlite3.Row],
) -> None:
    sealed = tuple(
        SealedRecord(
            row["record_sequence"],
            row["object_digest"],
            row["revision_digest"],
            row["watermark_digest"],
            row["tombstone_state"],
            row["payload_digest"],
            b"",
        )
        for row in rows
    )
    record_set, transition_head, reconciliation = commitments(keys, sealed)
    if (
        request_row["record_set_digest"] != record_set
        or request_row["transition_digest"] != transition_head
        or request_row["reconciliation_digest"] != reconciliation
    ):
        raise SnapshotImportStoreError("restore mismatch: record-set commitment")
    live = require_connection(connection)
    transitions = list(
        live.execute(
            "SELECT * FROM snapshot_import_transition WHERE cohort_id=? "
            "ORDER BY CAST(transition_sequence AS INTEGER)",
            (cohort_id,),
        )
    )
    if [row["transition_state"] for row in transitions] != list(IMPORT_TRANSITIONS):
        raise SnapshotImportStoreError("restore mismatch: transition sequence")
    recon = live.execute(
        "SELECT * FROM snapshot_import_reconciliation WHERE cohort_id=?",
        (cohort_id,),
    ).fetchone()
    if (
        recon is None
        or recon["reconciliation_state"] != _RECONCILED
        or recon["reconciliation_digest"] != reconciliation
        or recon["record_set_digest"] != record_set
    ):
        raise SnapshotImportStoreError("restore mismatch: reconciliation")


def require_exact(
    connection: sqlite3.Connection,
    keys: ImportKeys,
    request: SnapshotImportRequestV1,
    sealed: tuple[SealedRecord, ...],
    existing: sqlite3.Row,
) -> None:
    record_set, transition_head, reconciliation = commitments(keys, sealed)
    rows = record_rows(connection, request.cohort_id)
    same = (
        existing["namespace_id"] == request.target_namespace
        and existing["source_kind"] == request.source_name
        and existing["snapshot_digest"] == request.snapshot_digest
        and existing["discovery_digest"] == request.discovery_manifest_digest
        and existing["scope_digest"] == request.resolved_scope_digest
        and existing["record_sequence"] == str(len(sealed))
        and existing["record_set_digest"] == record_set
        and existing["transition_digest"] == transition_head
        and existing["reconciliation_digest"] == reconciliation
        and existing["import_state"] == _READY
        and existing["serving_state"] == _NON_SERVING
        and existing["cutover_state"] == _NON_ELIGIBLE
        and len(rows) == len(sealed)
        and all(
            row["object_digest"] == item.object_digest
            and row["revision_digest"] == item.revision_digest
            and row["watermark_digest"] == item.watermark_digest
            and row["tombstone_state"] == item.tombstone_state
            and row["payload_digest"] == item.payload_digest
            for row, item in zip(rows, sealed, strict=True)
        )
    )
    if not same:
        raise SnapshotImportStoreError("conflicting snapshot import identity")
    require_history(connection, keys, request.cohort_id, existing, rows)
