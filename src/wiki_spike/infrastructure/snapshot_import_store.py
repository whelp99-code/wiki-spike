"""Encrypted snapshot import adapter bound to one LifecycleDatabase + CAS pair."""
from __future__ import annotations

import sqlite3

from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedCASError,
    EncryptedContentStore,
)
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile import VerifiedPersistenceProfile
from wiki_spike.infrastructure.snapshot_import_seal import (
    SealedRecord,
    SnapshotSealError,
    derive_import_keys,
    open_record,
    seal_record,
)
from wiki_spike.infrastructure.snapshot_import_sql import (
    SnapshotImportStoreError,
    cohort_row,
    insert_import,
    record_rows,
    require_connection,
    require_exact,
    require_history,
)
from wiki_spike.infrastructure.snapshot_reconciliation_store import (
    ReconciliationExactCheck,
    ReconciliationPersistenceCommand,
    checkpoint_row,
    insert_reconciliation,
    require_reconciliation_exact,
)
from wiki_spike.memory_core.snapshot_import import SnapshotImportRequestV1
from wiki_spike.memory_core.snapshot_import_result import (
    ImportedRecordPayloadV1,
    RestoredSnapshotRecordV1,
    RestoredSnapshotV1,
    SnapshotImportReceiptV1,
)


class LifecycleSnapshotImportStore:
    """Persist opaque import commitments into the caller's LifecycleDatabase."""

    def __init__(
        self,
        database: LifecycleDatabase,
        cas: EncryptedContentStore,
        persistence_profile: VerifiedPersistenceProfile,
        encryption_key: bytes,
    ) -> None:
        if type(database) is not LifecycleDatabase:
            raise SnapshotImportStoreError("an exact LifecycleDatabase is required")
        if type(cas) is not EncryptedContentStore:
            raise SnapshotImportStoreError("an exact EncryptedContentStore is required")
        if type(persistence_profile) is not VerifiedPersistenceProfile:
            raise SnapshotImportStoreError("verified persistence profile is required")
        if type(encryption_key) is not bytes or len(encryption_key) != 32:
            raise SnapshotImportStoreError("encryption key must be exactly 32 bytes")
        self._database = database
        self._cas = cas
        self._profile = persistence_profile
        self._keys = derive_import_keys(encryption_key)
        self._require_binding()

    def persist_import(
        self,
        request: SnapshotImportRequestV1,
        payloads: tuple[ImportedRecordPayloadV1, ...],
    ) -> None:
        self._require_binding()
        sealed = tuple(
            seal_record(
                self._keys,
                payload,
                str(index),
                request.cohort_id,
                request.snapshot_digest,
                request.discovery_manifest_digest,
                request.target_namespace,
            )
            for index, payload in enumerate(payloads)
        )
        connection = require_connection(self._database.con)
        existing = cohort_row(connection, request.cohort_id)
        if existing is not None:
            require_exact(connection, self._keys, request, sealed, existing)
            return
        refs = tuple(self._cas.put(item.envelope) for item in sealed)
        try:
            with self._database.unit_of_work() as unit:
                self._insert(unit._con, request, sealed, refs)
        except sqlite3.IntegrityError as exc:
            current = cohort_row(require_connection(self._database.con), request.cohort_id)
            if current is None:
                raise SnapshotImportStoreError("conflicting snapshot import identity") from exc
            require_exact(require_connection(self._database.con), self._keys, request, sealed, current)

    def persist_reconciliation(
        self,
        command: ReconciliationPersistenceCommand,
    ) -> SnapshotImportReceiptV1:
        """Persist import, reconciliation, checkpoint, event, and outbox atomically."""
        self._require_binding()
        sealed = tuple(
            seal_record(
                self._keys,
                payload,
                str(index),
                command.request.cohort_id,
                command.request.snapshot_digest,
                command.request.discovery_manifest_digest,
                command.request.target_namespace,
            )
            for index, payload in enumerate(command.payloads)
        )
        connection = require_connection(self._database.con)
        checkpoint = checkpoint_row(connection, command.request.cohort_id)
        if checkpoint is not None:
            return require_reconciliation_exact(
                ReconciliationExactCheck(connection, self._keys, command, sealed)
            )
        refs = tuple(self._cas.put(item.envelope) for item in sealed)
        try:
            with self._database.unit_of_work() as unit:
                if checkpoint_row(unit._con, command.request.cohort_id) is not None:
                    return require_reconciliation_exact(
                        ReconciliationExactCheck(unit._con, self._keys, command, sealed)
                    )
                if cohort_row(unit._con, command.request.cohort_id) is not None:
                    raise SnapshotImportStoreError("conflicting snapshot reconciliation identity")
                self._insert(unit._con, command.request, sealed, refs)
                insert_reconciliation(unit._con, command)
        except sqlite3.IntegrityError:
            if checkpoint_row(connection, command.request.cohort_id) is None:
                raise
            try:
                return require_reconciliation_exact(
                    ReconciliationExactCheck(connection, self._keys, command, sealed)
                )
            except SnapshotImportStoreError as conflict:
                raise SnapshotImportStoreError(
                    "conflicting snapshot reconciliation identity"
                ) from conflict
        return command.receipt

    def restore_import(self, cohort_id: str) -> RestoredSnapshotV1:
        self._require_binding()
        connection = require_connection(self._database.con)
        request_row = cohort_row(connection, cohort_id)
        if request_row is None:
            raise SnapshotImportStoreError("restore mismatch: cohort is missing")
        rows = record_rows(connection, cohort_id)
        if str(len(rows)) != request_row["record_sequence"]:
            raise SnapshotImportStoreError("restore mismatch: record count")
        require_history(connection, self._keys, cohort_id, request_row, rows)
        restored = tuple(self._open_row(cohort_id, request_row, row) for row in rows)
        if str(len(restored)) != request_row["record_sequence"]:
            raise SnapshotImportStoreError("restore mismatch: record count")
        return RestoredSnapshotV1(restored)

    def record_count(self, cohort_id: str) -> int:
        self._require_binding()
        row = require_connection(self._database.con).execute(
            "SELECT COUNT(*) FROM snapshot_import_record WHERE cohort_id=?",
            (cohort_id,),
        ).fetchone()
        return int(row[0]) if row is not None else 0

    def _require_binding(self) -> None:
        if type(self._database) is not LifecycleDatabase:
            raise SnapshotImportStoreError("an exact LifecycleDatabase is required")
        if type(self._cas) is not EncryptedContentStore:
            raise SnapshotImportStoreError("an exact EncryptedContentStore is required")
        if not self._profile.is_authorized_for(self._database, self._cas):
            raise SnapshotImportStoreError("persistence profile does not bind these components")
        if self._database.con is None:
            raise SnapshotImportStoreError("an initialized LifecycleDatabase is required")

    def _insert(
        self,
        connection: sqlite3.Connection,
        request: SnapshotImportRequestV1,
        sealed: tuple[SealedRecord, ...],
        refs: tuple[str, ...],
    ) -> None:
        insert_import(connection, self._keys, request, sealed, refs)

    def _open_row(
        self,
        cohort_id: str,
        request_row: sqlite3.Row,
        row: sqlite3.Row,
    ) -> RestoredSnapshotRecordV1:
        try:
            envelope = self._cas.get(row["content_ref"])
        except EncryptedCASError as exc:
            raise SnapshotImportStoreError("restore mismatch: missing or corrupt object") from exc
        sealed = SealedRecord(
            row["record_sequence"],
            row["object_digest"],
            row["revision_digest"],
            row["watermark_digest"],
            row["tombstone_state"],
            row["payload_digest"],
            envelope,
        )
        try:
            opened = open_record(
                self._keys,
                envelope,
                sealed,
                cohort_id,
                request_row["snapshot_digest"],
                request_row["discovery_digest"],
                request_row["namespace_id"],
            )
        except SnapshotSealError as exc:
            raise SnapshotImportStoreError(str(exc)) from exc
        return RestoredSnapshotRecordV1(
            opened.native_id,
            opened.revision,
            opened.watermark,
            opened.tombstone,
            opened.content,
        )
