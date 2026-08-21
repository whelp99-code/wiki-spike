"""Atomic no-overwrite local snapshot package writer."""
from __future__ import annotations

import ctypes
import errno
import os
import shutil
import stat
import sys
from pathlib import Path, PurePosixPath
from typing import cast

from wiki_spike.memory_core.unified_db_snapshot_export import (
    PackageDurabilityUncertain,
    UnifiedDbExportError,
)

_RENAME_EXCL = 0x00000004
_RENAME_NOREPLACE = 1
_AT_FDCWD = -100

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | os.O_NOFOLLOW
    | getattr(os, "O_CLOEXEC", 0)
)


def _seal_tree(root: Path) -> None:
    files: list[Path] = []
    dirs: list[Path] = [root]
    pending = [root]
    while pending:
        current = pending.pop()
        with os.scandir(current) as iterator:
            children = list(iterator)
        for child in children:
            path = Path(child.path)
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                raise UnifiedDbExportError("symlink package path refused")
            if stat.S_ISDIR(metadata.st_mode):
                dirs.append(path)
                pending.append(path)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise UnifiedDbExportError("special package file refused")
            files.append(path)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    for path in files:
        descriptor = os.open(path, flags)
        try:
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)
    for path in reversed(dirs):
        descriptor = os.open(path, _DIR_FLAGS)
        try:
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o500)
        finally:
            os.close(descriptor)


def _restore_writable(root: Path) -> None:
    for current, dirnames, filenames in os.walk(root):
        os.chmod(current, 0o700)
        for name in dirnames + filenames:
            os.chmod(Path(current) / name, 0o700)


def reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise UnifiedDbExportError("symlink ancestor refused")


def _private_dir(path: Path) -> None:
    os.mkdir(path, 0o700)
    os.chmod(path, 0o700)
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise UnifiedDbExportError("package directory must be a private regular directory")


class LocalSnapshotPackageWriter:
    def start(self, destination: str) -> str:
        dest = Path(destination)
        reject_symlink_components(dest)
        if dest.exists():
            raise UnifiedDbExportError("output already exists; overwrite refused")
        parent = dest.parent
        try:
            parent_meta = os.lstat(parent)
        except OSError as exc:
            raise UnifiedDbExportError("output parent must be an existing directory") from exc
        if stat.S_ISLNK(parent_meta.st_mode) or not stat.S_ISDIR(parent_meta.st_mode):
            raise UnifiedDbExportError("output parent must be an existing directory")
        staging = parent / f".{dest.name}.{os.getpid()}.tmp"
        if staging.exists():
            raise UnifiedDbExportError("staging directory already exists")
        _private_dir(staging)
        _private_dir(staging / "payload")
        return str(staging)

    def write_file(self, staging_root: str, relative_path: str, content: bytes) -> None:
        parts = PurePosixPath(relative_path).parts
        if (
            not parts
            or PurePosixPath(relative_path).is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
        ):
            raise UnifiedDbExportError("package path must be a canonical relative POSIX path")
        root = Path(staging_root)
        root_fd = os.open(root, _DIR_FLAGS)
        parent_fd = root_fd
        try:
            for part in parts[:-1]:
                preview = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(preview.st_mode) or not stat.S_ISDIR(preview.st_mode):
                    raise UnifiedDbExportError("package path escape refused")
                child_fd = os.open(part, _DIR_FLAGS, dir_fd=parent_fd)
                if parent_fd != root_fd:
                    os.close(parent_fd)
                parent_fd = child_fd
            file_fd = os.open(parts[-1], _FILE_FLAGS, 0o600, dir_fd=parent_fd)
        except OSError as exc:
            raise UnifiedDbExportError("package file cannot be created safely") from exc
        finally:
            if parent_fd != root_fd:
                os.close(parent_fd)
            os.close(root_fd)
        try:
            os.fchmod(file_fd, 0o600)
            metadata = os.fstat(file_fd)
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise UnifiedDbExportError("package file must be a regular non-symlink file")
            offset = 0
            while offset < len(content):
                offset += os.write(file_fd, content[offset:])
            os.fsync(file_fd)
        finally:
            os.close(file_fd)

    def commit(
        self,
        staging_root: str,
        destination: str,
        receipt_relative_path: str,
        receipt: bytes,
        receipt_digest: str,
    ) -> None:
        dest = Path(destination)
        if dest.exists():
            self.abort(staging_root)
            raise UnifiedDbExportError("output already exists; overwrite refused")
        try:
            self._write_receipt(staging_root, receipt_relative_path, receipt)
            self._seal(Path(staging_root))
            self._exclusive_rename(staging_root, str(dest))
        except (OSError, UnifiedDbExportError) as exc:
            self.abort(staging_root)
            if isinstance(exc, UnifiedDbExportError):
                raise
            raise UnifiedDbExportError("package publish failed") from exc
        try:
            self._fsync_parent(dest)
        except OSError as exc:
            raise PackageDurabilityUncertain(str(dest), receipt_digest) from exc

    def _write_receipt(
        self, staging_root: str, relative_path: str, receipt: bytes
    ) -> None:
        self.write_file(staging_root, relative_path, receipt)

    def _seal(self, staging: Path) -> None:
        _seal_tree(staging)

    def _exclusive_rename(self, source: str, destination: str) -> None:
        if sys.platform == "darwin":
            library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            proto = ctypes.CFUNCTYPE(
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_char_p,
                ctypes.c_uint,
            )
            renamex = proto(("renamex_np", library))
            outcome = cast(
                int,
                renamex(
                    os.fsencode(source),
                    os.fsencode(destination),
                    _RENAME_EXCL,
                ),
            )
        elif sys.platform == "linux":
            library = ctypes.CDLL(None, use_errno=True)
            try:
                renameat2 = library.renameat2
            except AttributeError as exc:
                raise UnifiedDbExportError(
                    "exclusive publish is unsupported on this platform"
                ) from exc
            renameat2.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            renameat2.restype = ctypes.c_int
            outcome = cast(
                int,
                renameat2(
                    _AT_FDCWD,
                    os.fsencode(source),
                    _AT_FDCWD,
                    os.fsencode(destination),
                    _RENAME_NOREPLACE,
                ),
            )
        else:
            raise UnifiedDbExportError(
                "exclusive publish is unsupported on this platform"
            )
        if outcome != 0:
            code = ctypes.get_errno()
            if code == errno.EEXIST:
                raise UnifiedDbExportError("output already exists; overwrite refused")
            raise OSError(code, os.strerror(code))

    def _fsync_parent(self, dest: Path) -> None:
        descriptor = os.open(dest.parent, _DIR_FLAGS)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def abort(self, staging_root: str) -> None:
        staging = Path(staging_root)
        if not staging.name.startswith("."):
            raise UnifiedDbExportError("refusing to abort a non-private staging path")
        if staging.exists():
            _restore_writable(staging)
            shutil.rmtree(staging)
