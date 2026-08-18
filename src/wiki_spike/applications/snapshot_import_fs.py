"""Descriptor-based source file admission for snapshot import."""
from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_CHUNK = 65536


class SnapshotSourceFsError(ValueError):
    """A source path could not be opened without following a link or escape."""


@dataclass(frozen=True, slots=True)
class OpenSourceFile:
    """An O_NOFOLLOW file descriptor held until the importer finishes reading."""

    fd: int
    metadata: os.stat_result

    def close(self) -> None:
        os.close(self.fd)


def open_source_file(root: Path, relative_path: str) -> OpenSourceFile:
    """Open a regular file under root using openat(O_NOFOLLOW) for every component."""
    parts = tuple(part for part in relative_path.split("/") if part)
    if not parts:
        raise SnapshotSourceFsError("source path escape detected")
    root_fd = os.open(root, _DIR_FLAGS)
    parent_fd = root_fd
    try:
        for part in parts[:-1]:
            preview = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(preview.st_mode):
                raise SnapshotSourceFsError(f"symlink source path refused: {relative_path}")
            if not stat.S_ISDIR(preview.st_mode):
                raise SnapshotSourceFsError(f"special source file refused: {relative_path}")
            child_fd = os.open(part, _DIR_FLAGS, dir_fd=parent_fd)
            if parent_fd != root_fd:
                os.close(parent_fd)
            parent_fd = child_fd
        preview = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(preview.st_mode):
            raise SnapshotSourceFsError(f"symlink source path refused: {relative_path}")
        if not stat.S_ISREG(preview.st_mode):
            raise SnapshotSourceFsError(f"special source file refused: {relative_path}")
        file_fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=parent_fd)
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.EPERM}:
            raise SnapshotSourceFsError(f"symlink source path refused: {relative_path}") from exc
        raise SnapshotSourceFsError(
            f"source mutation observed before import: {relative_path}"
        ) from exc
    finally:
        if parent_fd != root_fd and parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)
    try:
        metadata = os.fstat(file_fd)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise SnapshotSourceFsError(f"special source file refused: {relative_path}")
    except (OSError, SnapshotSourceFsError):
        os.close(file_fd)
        raise
    return OpenSourceFile(file_fd, metadata)


def read_exact(opened: OpenSourceFile, expected: int, limit: int) -> bytes:
    """Read to EOF, rejecting short reads, growth, and overflow."""
    if expected > limit:
        raise SnapshotSourceFsError("source content exceeds the import bound")
    chunks = bytearray()
    while True:
        block = os.read(opened.fd, min(_CHUNK, limit - len(chunks) + 1))
        if not block:
            break
        chunks.extend(block)
        if len(chunks) > expected or len(chunks) > limit:
            raise SnapshotSourceFsError("source content exceeds the import bound")
    if len(chunks) != expected:
        raise SnapshotSourceFsError("source mutation observed before import")
    if os.read(opened.fd, 1):
        raise SnapshotSourceFsError("source mutation observed before import")
    after = os.fstat(opened.fd)
    if (
        opened.metadata.st_dev,
        opened.metadata.st_ino,
        opened.metadata.st_mode,
        opened.metadata.st_size,
        opened.metadata.st_mtime_ns,
    ) != (after.st_dev, after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns):
        raise SnapshotSourceFsError("source mutation observed before import")
    return bytes(chunks)
