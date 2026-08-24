"""Descriptor admission for explicitly approved absolute source roots."""
from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

DIRECTORY_OPEN_FLAGS: Final = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


@dataclass(frozen=True, slots=True)
class SafeSourceFilesystemError(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


def descriptor_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def assert_same(before: os.stat_result, after: os.stat_result, relative_path: str) -> None:
    if descriptor_identity(before) != descriptor_identity(after):
        raise SafeSourceFilesystemError(f"source mutation observed: {relative_path}")


def assert_source_owner_mode(metadata: os.stat_result, relative_path: str) -> None:
    if metadata.st_uid != os.getuid():
        raise SafeSourceFilesystemError(f"source owner refused: {relative_path}")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise SafeSourceFilesystemError(f"source mode refused: {relative_path}")


def translate_os_error(exc: OSError, relative_path: str) -> SafeSourceFilesystemError:
    if exc.errno in {errno.ELOOP, errno.EMLINK}:
        return SafeSourceFilesystemError(f"symlink source path refused: {relative_path}")
    return SafeSourceFilesystemError(f"source mutation observed: {relative_path}")


def open_approved_root(root: Path, approved_roots: frozenset[str]) -> tuple[int, os.stat_result]:
    """Walk an approved absolute root from `/` without following any component."""
    canonical = os.path.abspath(root)
    if canonical not in approved_roots:
        raise SafeSourceFilesystemError("source root is not approved")
    anchor_fd = os.open(os.sep, DIRECTORY_OPEN_FLAGS)
    current_fd = anchor_fd
    parts = Path(canonical).parts[1:]
    try:
        for index, part in enumerate(parts):
            component = os.sep + os.path.join(*parts[: index + 1])
            preview = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            if stat.S_ISLNK(preview.st_mode):
                raise SafeSourceFilesystemError(f"source root symlink component refused: {component}")
            if not stat.S_ISDIR(preview.st_mode):
                raise SafeSourceFilesystemError(f"source root component is not a directory: {component}")
            child_fd = os.open(part, DIRECTORY_OPEN_FLAGS, dir_fd=current_fd)
            try:
                assert_same(preview, os.fstat(child_fd), component)
            except SafeSourceFilesystemError:
                os.close(child_fd)
                raise
            if current_fd != anchor_fd:
                os.close(current_fd)
            current_fd = child_fd
        metadata = os.fstat(current_fd)
        assert_source_owner_mode(metadata, ".")
        if current_fd != anchor_fd:
            os.close(anchor_fd)
        return current_fd, metadata
    except OSError as exc:
        if current_fd != anchor_fd:
            os.close(current_fd)
        os.close(anchor_fd)
        if exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.EACCES}:
            raise SafeSourceFilesystemError("source root does not exist or is inaccessible") from exc
        raise translate_os_error(exc, ".") from exc
    except SafeSourceFilesystemError:
        if current_fd != anchor_fd:
            os.close(current_fd)
        os.close(anchor_fd)
        raise
