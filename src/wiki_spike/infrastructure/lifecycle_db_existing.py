"""Existing-only read admission for Mac production lifecycle status."""
from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path

from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, LifecycleDbError
from wiki_spike.infrastructure.lifecycle_db_existing_decode import (
    expected_schema_shape,
    query_three,
    schema_shape,
)

_OPAQUE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
)


@dataclass(frozen=True, slots=True)
class ExistingLifecycleStatus:
    workspace_ref: str
    capability_ref: str
    authority_epoch: str
    authority_state: str
    migration_state: str
    migration_digest: str
    migration_recorded_at: str
    ready: bool


class ExistingLifecycleDatabase(LifecycleDatabase):
    """LifecycleDatabase admitted with an immutable main-file fingerprint."""

    existing_read_fingerprint: tuple[int, int, int, int, int, int]

    def __init__(
        self,
        path: Path,
        fingerprint: tuple[int, int, int, int, int, int],
    ) -> None:
        super().__init__(path)
        self.existing_read_fingerprint = fingerprint


def _refuse(message: str) -> LifecycleDbError:
    return LifecycleDbError(f"existing lifecycle database {message}")


def _require_no_symlink_ancestor(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise _refuse(f"path is missing: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _refuse(f"path would follow a symlink: {current}")


def _validate_main_file(path: Path) -> os.stat_result:
    _require_no_symlink_ancestor(path)
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise _refuse("file is unavailable") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise _refuse("path is not a regular file")
    if metadata.st_uid != os.getuid():
        raise _refuse("owner is invalid")
    if metadata.st_nlink != 1:
        raise _refuse("hard-linked files are forbidden")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise _refuse("mode must be 0600")
    if metadata.st_size == 0:
        raise _refuse("schema is absent")
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            raise _refuse("requires a clean WAL checkpoint")
    return metadata


def _fingerprint(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def open_existing_lifecycle_database(path: Path) -> ExistingLifecycleDatabase:
    """Open a clean, exact-schema database without creation or WAL activity."""
    before = _validate_main_file(path)
    connection: sqlite3.Connection | None = None
    try:
        uri = Path(os.path.abspath(path)).as_uri() + "?mode=ro&immutable=1"
        connection = sqlite3.connect(uri, uri=True, isolation_level=None)
        _ = connection.execute("PRAGMA query_only=ON")
        _ = connection.execute("PRAGMA foreign_keys=ON")
        _ = connection.execute("PRAGMA trusted_schema=OFF")
        _ = connection.execute("PRAGMA busy_timeout=5000")
        if schema_shape(connection) != expected_schema_shape():
            raise _refuse("schema does not match")
        after = os.lstat(path)
        if _fingerprint(after) != _fingerprint(before):
            raise _refuse("file metadata changed during open")
    except (OSError, sqlite3.DatabaseError):
        if connection is not None:
            connection.close()
        raise _refuse("schema cannot be read") from None
    except LifecycleDbError:
        if connection is not None:
            connection.close()
        raise
    database = ExistingLifecycleDatabase(path, _fingerprint(before))
    database.con = connection
    return database


def inspect_existing_serving_ready(
    database: ExistingLifecycleDatabase,
    workspace_ref: str,
) -> ExistingLifecycleStatus:
    """Read ACTIVE and SERVING_READY in one deferred immutable transaction."""
    if (
        not workspace_ref
        or len(workspace_ref) > 256
        or any(character not in _OPAQUE_CHARS for character in workspace_ref)
    ):
        raise LifecycleDbError("invalid workspace ref")
    connection = database.con
    if connection is None:
        raise LifecycleDbError("existing lifecycle database is closed")
    fingerprint = database.existing_read_fingerprint
    if _fingerprint(_validate_main_file(database.db_path)) != fingerprint:
        raise LifecycleDbError("existing lifecycle database changed since open")
    _ = connection.execute("BEGIN")
    try:
        authority = query_three(
            connection,
            "_ws_authority_cap",
            (
                "SELECT _ws_authority_cap("
                "authority_state,authority_epoch,capability_ref) "
                "FROM ledger_authority WHERE workspace_ref=?"
            ),
            workspace_ref,
        )
        migration = query_three(
            connection,
            "_ws_migration_cap",
            (
                "SELECT _ws_migration_cap("
                "migration_state,migration_digest,recorded_at) "
                "FROM ledger_migration WHERE workspace_ref=? "
                "ORDER BY recorded_at DESC,migration_ref DESC LIMIT 1"
            ),
            workspace_ref,
        )
        _ = connection.execute("COMMIT")
        if _fingerprint(_validate_main_file(database.db_path)) != fingerprint:
            raise LifecycleDbError("existing lifecycle database changed since open")
    except Exception:
        if connection.in_transaction:
            _ = connection.execute("ROLLBACK")
        raise
    if not authority:
        raise LifecycleDbError("lifecycle authority is absent")
    authority_state, authority_epoch, capability_ref = authority[0]
    if authority_state != "ACTIVE":
        raise LifecycleDbError("lifecycle authority is not ACTIVE")
    if not migration:
        raise LifecycleDbError("lifecycle migration is absent")
    migration_state, migration_digest, recorded_at = migration[0]
    if migration_state != "SERVING_READY":
        raise LifecycleDbError("lifecycle migration is not SERVING_READY")
    return ExistingLifecycleStatus(
        workspace_ref=workspace_ref,
        capability_ref=capability_ref,
        authority_epoch=authority_epoch,
        authority_state=authority_state,
        migration_state=migration_state,
        migration_digest=migration_digest,
        migration_recorded_at=recorded_at,
        ready=True,
    )
