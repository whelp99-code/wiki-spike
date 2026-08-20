"""Dedicated private SQLite export authorization nonce store."""
from __future__ import annotations

import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import final

from wiki_spike.infrastructure.export_authorization_nonce_backup import (
    backup_nonce_store,
    restore_nonce_store,
)
from wiki_spike.infrastructure.export_authorization_nonce_decode import run_sql
from wiki_spike.infrastructure.export_authorization_nonce_fs import (
    precreate_private_db,
    require_existing_sqlite,
    sidecar_snapshot,
    verify_sidecars,
)
from wiki_spike.infrastructure.export_authorization_nonce_schema import (
    CONSUMED,
    NonceStoreState,
    apply_connection_pragmas,
    apply_created_pragmas,
    apply_v1,
    quick_check,
    read_metadata,
    require_pragmas,
    validate_schema,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization import parse_utc
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


@final
class SqliteExportAuthorizationNonceStore:
    """Append-only CONSUMED nonce store. Fail closed. No repair."""

    _path: Path
    _con: sqlite3.Connection
    _digest_nonce: Callable[[str], str]

    def __init__(
        self,
        path: Path,
        *,
        digest_nonce: Callable[[str], str] = export_authorization_nonce_digest,
        allow_create: bool = True,
    ) -> None:
        self._path = path
        self._digest_nonce = digest_nonce
        if allow_create:
            created = precreate_private_db(path)
            if not created:
                require_existing_sqlite(path)
        else:
            require_existing_sqlite(path)
            created = False
        preexisting = sidecar_snapshot(path)
        try:
            self._con = sqlite3.connect(str(path), isolation_level=None)
        except sqlite3.DatabaseError as exc:
            raise UnifiedDbExportError("authorization nonce store is corrupt") from exc
        try:
            if created:
                apply_created_pragmas(self._con)
            else:
                apply_connection_pragmas(self._con)
            run_sql(self._con, "BEGIN IMMEDIATE")
            quick_check(self._con)
            if created:
                apply_v1(self._con)
            validate_schema(self._con)
            _ = read_metadata(self._con)
            if not created:
                require_pragmas(self._con)
            run_sql(self._con, "COMMIT")
            verify_sidecars(path, preexisting)
        except sqlite3.DatabaseError as exc:
            if self._con.in_transaction:
                run_sql(self._con, "ROLLBACK")
            self._con.close()
            raise UnifiedDbExportError("authorization nonce store is corrupt") from exc
        except UnifiedDbExportError:
            if self._con.in_transaction:
                run_sql(self._con, "ROLLBACK")
            self._con.close()
            raise

    def close(self) -> None:
        self._con.close()

    def reserve_and_consume(
        self,
        *,
        authorization_id: str,
        nonce: str,
        authorization_digest: str,
        authorization_issued_at: str,
    ) -> None:
        try:
            issued = parse_utc(authorization_issued_at, "authorization_issued_at")
        except InvalidContractValue as exc:
            raise UnifiedDbExportError(str(exc)) from exc
        digest = self._digest_nonce(nonce)
        preexisting = sidecar_snapshot(self._path)
        try:
            run_sql(self._con, "BEGIN IMMEDIATE")
            quick_check(self._con)
            validate_schema(self._con)
            state, floor = read_metadata(self._con)
            floor_at = parse_utc(floor, "authorization_floor_at")
            run_sql(
                self._con,
                (
                    "INSERT INTO export_nonce_consumption ("
                    + "nonce_digest, authorization_id, authorization_digest, "
                    + "authorization_issued_at, consumption_state) VALUES (?, ?, ?, ?, ?)"
                ),
                (
                    digest,
                    authorization_id,
                    authorization_digest,
                    authorization_issued_at,
                    CONSUMED,
                ),
            )
            run_sql(self._con, "COMMIT")
        except sqlite3.IntegrityError as exc:
            run_sql(self._con, "ROLLBACK")
            raise UnifiedDbExportError("authorization nonce was already consumed") from exc
        except sqlite3.OperationalError as exc:
            if self._con.in_transaction:
                run_sql(self._con, "ROLLBACK")
            detail = str(exc).lower()
            if "locked" in detail:
                raise UnifiedDbExportError("authorization nonce store is locked") from exc
            raise UnifiedDbExportError("authorization nonce store is corrupt") from exc
        verify_sidecars(self._path, preexisting)
        if state == NonceStoreState.RESTORE_QUARANTINED:
            raise UnifiedDbExportError("authorization nonce store is quarantined")
        if state == NonceStoreState.ACTIVE and issued < floor_at:
            raise UnifiedDbExportError(
                "authorization nonce is below the authorization floor"
            )

    def backup(self, destination: Path) -> None:
        backup_nonce_store(self._path, destination)

    @classmethod
    def restore(cls, backup: Path, destination: Path) -> None:
        restore_nonce_store(backup, destination)

    def activate_restored(self, authorization_floor_at: str) -> None:
        floor = parse_utc(authorization_floor_at, "authorization_floor_at")
        stamped = floor.strftime("%Y-%m-%dT%H:%M:%SZ")
        run_sql(self._con, "BEGIN IMMEDIATE")
        quick_check(self._con)
        validate_schema(self._con)
        state, _current = read_metadata(self._con)
        if state != NonceStoreState.RESTORE_QUARANTINED:
            run_sql(self._con, "ROLLBACK")
            raise UnifiedDbExportError("authorization nonce store is not quarantined")
        run_sql(
            self._con,
            (
                "UPDATE export_nonce_store_metadata SET store_state = ?, "
                + "authorization_floor_at = ?"
            ),
            (NonceStoreState.ACTIVE.value, stamped),
        )
        run_sql(self._con, "COMMIT")
