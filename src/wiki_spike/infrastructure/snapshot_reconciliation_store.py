"""Atomic SQL commitments for certified snapshot reconciliation."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Protocol

from wiki_spike.infrastructure.lifecycle_db import UnitOfWork
from wiki_spike.infrastructure.snapshot_import_seal import ImportKeys, SealedRecord
from wiki_spike.infrastructure.snapshot_import_sql import (
    SnapshotImportStoreError,
    cohort_row,
    now_utc,
    require_connection,
    require_exact,
)
from wiki_spike.memory_core.second_brain_complete_snapshot import (
    CompleteSnapshotCertificateV1,
    SnapshotDisposition,
    SnapshotReconciliationV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.snapshot_import import SnapshotImportRequestV1
from wiki_spike.memory_core.snapshot_import_result import (
    ImportedRecordPayloadV1,
    SnapshotImportReceiptV1,
)


class ReconciliationPersistenceCommand(Protocol):
    request: SnapshotImportRequestV1
    previous_snapshot_digest: str
    payloads: tuple[ImportedRecordPayloadV1, ...]
    reconciliation: SnapshotReconciliationV1
    certificate: CompleteSnapshotCertificateV1
    receipt: SnapshotImportReceiptV1


@dataclass(frozen=True, slots=True)
class ReconciliationExactCheck:
    connection: sqlite3.Connection
    keys: ImportKeys
    command: ReconciliationPersistenceCommand
    sealed: tuple[SealedRecord, ...]


def reconciliation_digest(reconciliation: SnapshotReconciliationV1) -> str:
    """Commit the complete ordered reconciliation result without source bodies."""
    return canonical_ledger_digest(
        "snapshot-reconciliation-commit-v1",
        {
            "items": [
                {
                    "native_id": item.native_id,
                    "disposition": item.disposition.value,
                    "keyed_dedupe_ref": item.keyed_dedupe_ref,
                    "previous_revision": item.previous_revision,
                    "current_revision": item.current_revision,
                    "reason": item.reason,
                }
                for item in reconciliation.items
            ],
            "provenance_edge_removals": [
                {
                    "source_name": edge.source_name,
                    "native_id": edge.native_id,
                    "keyed_dedupe_ref": edge.keyed_dedupe_ref,
                    "reason": edge.reason,
                }
                for edge in reconciliation.provenance_edge_removals
            ],
            "expected_count": str(reconciliation.expected_count),
            "accounted_count": str(reconciliation.accounted_count),
            "disposition_counts": {
                disposition.value: str(reconciliation.disposition_counts[disposition])
                for disposition in SnapshotDisposition
            },
        },
    )


def checkpoint_row(
    connection: sqlite3.Connection,
    cohort_id: str,
) -> sqlite3.Row | None:
    return require_connection(connection).execute(
        "SELECT * FROM snapshot_reconciliation_checkpoint WHERE cohort_id=?",
        (cohort_id,),
    ).fetchone()


def insert_reconciliation(
    connection: sqlite3.Connection,
    command: ReconciliationPersistenceCommand,
) -> None:
    digest = reconciliation_digest(command.reconciliation)
    counts = command.reconciliation.disposition_counts
    recorded_at = now_utc()
    connection.execute(
        "INSERT INTO snapshot_reconciliation_commit VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            command.request.cohort_id,
            command.previous_snapshot_digest,
            command.request.snapshot_digest,
            command.certificate.certificate_digest,
            digest,
            str(counts[SnapshotDisposition.QUARANTINED]),
            str(counts[SnapshotDisposition.TOMBSTONED]),
            str(len(command.reconciliation.provenance_edge_removals)),
            "COMMITTED",
            recorded_at,
        ),
    )
    unit = UnitOfWork(connection)
    _ = unit.append_event(unit.event_chain_head(), "SNAPSHOT_RECONCILED", digest)
    unit.insert_outbox("SNAPSHOT_RECONCILED", digest)
    connection.execute(
        "INSERT INTO snapshot_reconciliation_checkpoint VALUES (?,?,?,?,?,?)",
        (
            command.request.cohort_id,
            f"snapshot-reconciliation:{digest}",
            digest,
            command.receipt.receipt_digest,
            "COMMITTED",
            recorded_at,
        ),
    )


def require_reconciliation_exact(
    check: ReconciliationExactCheck,
) -> SnapshotImportReceiptV1:
    command = check.command
    existing = cohort_row(check.connection, command.request.cohort_id)
    if existing is None:
        raise SnapshotImportStoreError("conflicting snapshot reconciliation identity")
    require_exact(check.connection, check.keys, command.request, check.sealed, existing)
    digest = reconciliation_digest(command.reconciliation)
    counts = command.reconciliation.disposition_counts
    commit = require_connection(check.connection).execute(
        "SELECT * FROM snapshot_reconciliation_commit WHERE cohort_id=?",
        (command.request.cohort_id,),
    ).fetchone()
    checkpoint = checkpoint_row(check.connection, command.request.cohort_id)
    exact = (
        commit is not None
        and checkpoint is not None
        and commit["previous_snapshot_digest"] == command.previous_snapshot_digest
        and commit["current_snapshot_digest"] == command.request.snapshot_digest
        and commit["certificate_digest"] == command.certificate.certificate_digest
        and commit["reconciliation_digest"] == digest
        and commit["quarantined_sequence"]
        == str(counts[SnapshotDisposition.QUARANTINED])
        and commit["tombstoned_sequence"] == str(counts[SnapshotDisposition.TOMBSTONED])
        and commit["edge_removal_sequence"]
        == str(len(command.reconciliation.provenance_edge_removals))
        and commit["commit_state"] == "COMMITTED"
        and checkpoint["checkpoint_ref"] == f"snapshot-reconciliation:{digest}"
        and checkpoint["reconciliation_digest"] == digest
        and checkpoint["receipt_digest"] == command.receipt.receipt_digest
        and checkpoint["checkpoint_state"] == "COMMITTED"
    )
    if not exact:
        raise SnapshotImportStoreError("conflicting snapshot reconciliation identity")
    return command.receipt
