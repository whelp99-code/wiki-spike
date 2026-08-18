"""Create-only atomic publication of public authorization artifacts."""
from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path

from wiki_spike.infrastructure.local_snapshot_package_writer import (
    reject_symlink_components,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _unlink(path: Path) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        return


def _fsync_parent(directory: Path) -> None:
    descriptor = os.open(directory, _DIR_FLAGS)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_exclusive_bytes(destination: Path, content: bytes) -> None:
    """Write content to destination only if it does not already exist."""
    dest = destination
    reject_symlink_components(dest)
    try:
        _ = os.lstat(dest)
    except FileNotFoundError:
        pass
    else:
        raise UnifiedDbExportError("output already exists; overwrite refused")
    parent = dest.parent
    try:
        parent_meta = os.lstat(parent)
    except OSError as exc:
        raise UnifiedDbExportError("output parent must be an existing directory") from exc
    if stat.S_ISLNK(parent_meta.st_mode) or not stat.S_ISDIR(parent_meta.st_mode):
        raise UnifiedDbExportError("output parent must be an existing directory")
    tmp = parent / f".{dest.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    try:
        descriptor = os.open(tmp, _FILE_FLAGS, 0o600)
    except OSError as exc:
        raise UnifiedDbExportError("output cannot be created safely") from exc
    try:
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        os.close(descriptor)
        _unlink(tmp)
        raise UnifiedDbExportError("output write failed") from exc
    os.close(descriptor)
    try:
        os.link(tmp, dest)
    except FileExistsError as exc:
        _unlink(tmp)
        raise UnifiedDbExportError("output already exists; overwrite refused") from exc
    except OSError as exc:
        _unlink(tmp)
        raise UnifiedDbExportError("output publish failed") from exc
    _unlink(tmp)
    try:
        _fsync_parent(parent)
    except OSError as exc:
        _unlink(dest)
        raise UnifiedDbExportError("output parent durability failed") from exc
