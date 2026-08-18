"""Create-only backup and restore-to-new-file for the nonce store."""
from __future__ import annotations

import os
import secrets
import sqlite3
from pathlib import Path

from wiki_spike.infrastructure.export_authorization_nonce_decode import run_sql
from wiki_spike.infrastructure.export_authorization_nonce_fs import (
    create_exclusive_file,
    fsync_file,
    fsync_parent,
    path_exists,
    require_private_db,
    require_private_directory,
    unlink_if_present,
)
from wiki_spike.infrastructure.export_authorization_nonce_schema import (
    NonceStoreState,
    apply_created_pragmas,
    quick_check,
    read_metadata,
    validate_schema,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    reject_symlink_components,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def _connect(path: Path) -> sqlite3.Connection:
    try:
        return sqlite3.connect(str(path), isolation_level=None)
    except sqlite3.DatabaseError as exc:
        raise UnifiedDbExportError("authorization nonce store is corrupt") from exc


def _validated_copy(source: sqlite3.Connection, destination: Path) -> None:
    target = _connect(destination)
    try:
        source.backup(target)
        apply_created_pragmas(target)
        run_sql(target, "BEGIN IMMEDIATE")
        quick_check(target)
        validate_schema(target)
        run_sql(target, "COMMIT")
    except sqlite3.DatabaseError as exc:
        target.close()
        raise UnifiedDbExportError("authorization nonce store is corrupt") from exc
    target.close()


def backup_nonce_store(source: Path, destination: Path) -> None:
    require_private_db(source)
    reject_symlink_components(destination)
    if path_exists(destination):
        raise UnifiedDbExportError("output already exists; overwrite refused")
    tmp = destination.parent / f".{destination.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        create_exclusive_file(tmp)
        source_con = _connect(source)
        try:
            _validated_copy(source_con, tmp)
        finally:
            source_con.close()
        fsync_file(tmp)
        try:
            os.link(tmp, destination)
        except FileExistsError as exc:
            raise UnifiedDbExportError("output already exists; overwrite refused") from exc
        fsync_parent(destination.parent)
    finally:
        unlink_if_present(tmp)


def restore_nonce_store(backup: Path, destination: Path) -> None:
    require_private_db(backup)
    reject_symlink_components(destination)
    if path_exists(destination):
        raise UnifiedDbExportError("output already exists; overwrite refused")
    require_private_directory(destination.parent)
    tmp = destination.parent / f".{destination.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        create_exclusive_file(tmp)
        source = _connect(backup)
        try:
            _validated_copy(source, tmp)
        finally:
            source.close()
        target = _connect(tmp)
        try:
            apply_created_pragmas(target)
            run_sql(target, "BEGIN IMMEDIATE")
            run_sql(
                target,
                "UPDATE export_nonce_store_metadata SET store_state = ?",
                (NonceStoreState.RESTORE_QUARANTINED.value,),
            )
            validate_schema(target)
            state, _floor = read_metadata(target)
            if state != NonceStoreState.RESTORE_QUARANTINED:
                raise UnifiedDbExportError("authorization nonce store is corrupt")
            run_sql(target, "COMMIT")
        finally:
            target.close()
        fsync_file(tmp)
        try:
            os.link(tmp, destination)
        except FileExistsError as exc:
            raise UnifiedDbExportError("output already exists; overwrite refused") from exc
        fsync_parent(destination.parent)
    finally:
        unlink_if_present(tmp)
