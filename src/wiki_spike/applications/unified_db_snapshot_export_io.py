"""Bounded O_NOFOLLOW|O_NONBLOCK package and fixture reads."""
from __future__ import annotations

import os
import stat
from pathlib import Path

from wiki_spike.infrastructure.local_snapshot_package_writer import (
    reject_symlink_components,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

HARD_CAP = 1048576
_FILE_FLAGS = (
    os.O_RDONLY
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | getattr(os, "O_CLOEXEC", 0)
)
_DIR_FLAGS = (
    os.O_RDONLY
    | os.O_DIRECTORY
    | os.O_NOFOLLOW
    | os.O_NONBLOCK
    | getattr(os, "O_CLOEXEC", 0)
)


def _read_exact(descriptor: int, size: int) -> bytes:
    chunks = bytearray()
    remaining = size
    while remaining:
        block = os.read(descriptor, remaining)
        if not block:
            raise UnifiedDbExportError("short package read")
        chunks.extend(block)
        remaining -= len(block)
    extra = os.read(descriptor, 1)
    if extra:
        raise UnifiedDbExportError("trailing package bytes")
    return bytes(chunks)


def read_regular(
    dir_fd: int,
    name: str,
    expected_mode: int,
    budget: int,
) -> tuple[bytes, int]:
    preview = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if stat.S_ISLNK(preview.st_mode):
        raise UnifiedDbExportError("symlink metadata path refused")
    descriptor = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    try:
        seen = os.fstat(descriptor)
        if (seen.st_dev, seen.st_ino, seen.st_mode, seen.st_size) != (
            preview.st_dev,
            preview.st_ino,
            preview.st_mode,
            preview.st_size,
        ):
            raise UnifiedDbExportError("package path swapped during open")
        if not stat.S_ISREG(seen.st_mode):
            raise UnifiedDbExportError("special package file refused")
        if (seen.st_mode & 0o777) != expected_mode:
            raise UnifiedDbExportError("package file mode refused")
        if seen.st_size > HARD_CAP or seen.st_size > budget:
            raise UnifiedDbExportError("package metadata exceeds 1048576")
        return _read_exact(descriptor, seen.st_size), budget - seen.st_size
    finally:
        os.close(descriptor)


def open_directory(dir_fd: int, name: str, expected_mode: int) -> int:
    preview = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    if stat.S_ISLNK(preview.st_mode):
        raise UnifiedDbExportError("symlink payload directory refused")
    descriptor = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    seen = os.fstat(descriptor)
    if (seen.st_dev, seen.st_ino, seen.st_mode) != (
        preview.st_dev,
        preview.st_ino,
        preview.st_mode,
    ):
        os.close(descriptor)
        raise UnifiedDbExportError("package path swapped during open")
    if not stat.S_ISDIR(seen.st_mode) or (seen.st_mode & 0o777) != expected_mode:
        os.close(descriptor)
        raise UnifiedDbExportError("package directory mode refused")
    return descriptor


def open_root(path: str) -> int:
    root = Path(path)
    reject_symlink_components(root)
    descriptor = os.open(root, _DIR_FLAGS)
    seen = os.fstat(descriptor)
    if stat.S_ISLNK(seen.st_mode) or not stat.S_ISDIR(seen.st_mode):
        os.close(descriptor)
        raise UnifiedDbExportError("package root must be a regular directory")
    if (seen.st_mode & 0o777) != 0o500:
        os.close(descriptor)
        raise UnifiedDbExportError("package root mode refused")
    return descriptor


def read_bounded_path(path: Path, cap: int) -> bytes:
    reject_symlink_components(path)
    preview = os.lstat(path)
    if stat.S_ISLNK(preview.st_mode):
        raise UnifiedDbExportError("symlink fixture path refused")
    descriptor = os.open(path, _FILE_FLAGS)
    try:
        seen = os.fstat(descriptor)
        if (seen.st_dev, seen.st_ino, seen.st_mode, seen.st_size) != (
            preview.st_dev,
            preview.st_ino,
            preview.st_mode,
            preview.st_size,
        ):
            raise UnifiedDbExportError("fixture path swapped during open")
        if not stat.S_ISREG(seen.st_mode):
            raise UnifiedDbExportError("fixture must be a regular file")
        if seen.st_size > cap:
            raise UnifiedDbExportError("fixture input exceeds 1048576")
        return _read_exact(descriptor, seen.st_size)
    finally:
        os.close(descriptor)
