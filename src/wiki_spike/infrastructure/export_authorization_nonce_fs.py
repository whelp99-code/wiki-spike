"""Private-path admission for the export authorization nonce store."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from wiki_spike.infrastructure.local_snapshot_package_writer import (
    reject_symlink_components,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_FILE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_SIDECARS = ("-wal", "-shm")
_FILE_MODE = 0o600
_DIR_MODE = 0o700
_SQLITE_MAGIC = b"SQLite format 3\x00"
_MIN_DB = 100


def require_private_directory(path: Path) -> None:
    reject_symlink_components(path)
    try:
        meta = os.lstat(path)
    except OSError as exc:
        raise UnifiedDbExportError("authorization nonce store directory is invalid") from exc
    mode = stat.S_IMODE(meta.st_mode)
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise UnifiedDbExportError("authorization nonce store directory is invalid")
    if meta.st_uid != os.getuid() or mode != _DIR_MODE:
        raise UnifiedDbExportError("authorization nonce store permissions are invalid")


def path_exists(path: Path) -> bool:
    try:
        _ = os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def unlink_if_present(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return


def ensure_private_dir(path: Path) -> None:
    reject_symlink_components(path)
    if not path_exists(path):
        os.mkdir(path, _DIR_MODE)
        os.chmod(path, _DIR_MODE)
    require_private_directory(path)


def _require_private_regular(meta: os.stat_result) -> None:
    mode = stat.S_IMODE(meta.st_mode)
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise UnifiedDbExportError("symlink store path refused")
    if meta.st_nlink != 1:
        raise UnifiedDbExportError("authorization nonce store hardlink refused")
    if meta.st_uid != os.getuid() or mode != _FILE_MODE:
        raise UnifiedDbExportError("authorization nonce store permissions are invalid")


def require_private_db(path: Path) -> None:
    reject_symlink_components(path)
    try:
        meta = os.lstat(path)
    except OSError as exc:
        raise UnifiedDbExportError("authorization nonce store file is invalid") from exc
    _require_private_regular(meta)


def require_existing_sqlite(path: Path) -> None:
    require_private_db(path)
    descriptor = os.open(
        path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        header = os.read(descriptor, 16)
        size = os.fstat(descriptor).st_size
    finally:
        os.close(descriptor)
    if size < _MIN_DB or header != _SQLITE_MAGIC:
        raise UnifiedDbExportError("authorization nonce store is corrupt")


def precreate_private_db(path: Path) -> bool:
    reject_symlink_components(path)
    require_private_directory(path.parent)
    try:
        meta = os.lstat(path)
    except FileNotFoundError:
        descriptor = os.open(path, _FILE_FLAGS, _FILE_MODE)
        try:
            os.fchmod(descriptor, _FILE_MODE)
        finally:
            os.close(descriptor)
        return True
    _require_private_regular(meta)
    return False


def sidecar_snapshot(path: Path) -> frozenset[str]:
    found: set[str] = set()
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        try:
            _ = os.lstat(side)
        except FileNotFoundError:
            continue
        found.add(suffix)
    return frozenset(found)


def verify_sidecars(path: Path, preexisting: frozenset[str]) -> None:
    for suffix in _SIDECARS:
        side = path.with_name(path.name + suffix)
        try:
            meta = os.lstat(side)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
            raise UnifiedDbExportError("authorization nonce store sidecar is unsafe")
        if meta.st_uid != os.getuid():
            raise UnifiedDbExportError("authorization nonce store permissions are invalid")
        if suffix not in preexisting:
            os.chmod(side, _FILE_MODE)
            continue
        if stat.S_IMODE(meta.st_mode) != _FILE_MODE:
            raise UnifiedDbExportError("authorization nonce store permissions are invalid")


def fsync_parent(directory: Path) -> None:
    descriptor = os.open(directory, _DIR_FLAGS)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_exclusive_file(path: Path) -> None:
    reject_symlink_components(path)
    try:
        _ = os.lstat(path)
    except FileNotFoundError:
        descriptor = os.open(path, _FILE_FLAGS, _FILE_MODE)
        try:
            os.fchmod(descriptor, _FILE_MODE)
        finally:
            os.close(descriptor)
        return
    raise UnifiedDbExportError("output already exists; overwrite refused")
