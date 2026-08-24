"""Bounded, read-only filesystem access beneath explicitly approved roots."""
from __future__ import annotations

import logging
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import TracebackType
from typing import Final

from wiki_spike.infrastructure.safe_source_root import (
    DIRECTORY_OPEN_FLAGS,
    SafeSourceFilesystemError,
    assert_same,
    assert_source_owner_mode,
    open_approved_root,
    translate_os_error,
)

_FILE_FLAGS: Final = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_CHUNK: Final = 65_536
_DENIED_SUFFIXES: Final = frozenset(
    {".cer", ".crt", ".der", ".key", ".keychain", ".keychain-db", ".p12", ".p7b", ".p7c", ".pem", ".pfx"}
)
_DENIED_NAMES: Final = frozenset({".netrc", "cookies", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "known_hosts"})
_SENSITIVE_WORD: Final = re.compile(
    r"(?:^|[._\-/])(?:access[-_]?token|auth[-_]?token|cookie|credential|private[-_]?key|refresh[-_]?token|secret|session|token)s?(?:[._\-/]|$)"
)
_REASONING_NAME: Final = re.compile(r"(?:^|[._\-/])(?:chain[-_]?of[-_]?thought|cot|hidden[-_]?reasoning)(?:[._\-/]|$)")
_LOGGER: Final = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SourceFilesystemLimits:
    max_entries: int = 10_000
    max_files: int = 5_000
    max_depth: int = 32
    max_file_bytes: int = 67_108_864
    max_total_bytes: int = 268_435_456

    def __post_init__(self) -> None:
        if min(self.max_entries, self.max_files, self.max_file_bytes, self.max_total_bytes) < 1 or self.max_depth < 0:
            raise SafeSourceFilesystemError("source filesystem limits must be positive")


@dataclass(frozen=True, slots=True)
class SourceFileMetadata:
    relative_path: str
    metadata: os.stat_result


@dataclass(frozen=True, slots=True)
class PinnedSourceFile:
    """A read-only descriptor pinned to metadata observed during admission."""

    fd: int
    relative_path: str
    metadata: os.stat_result
    max_bytes: int

    def __enter__(self) -> PinnedSourceFile:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        os.close(self.fd)

    def read(self) -> bytes:
        """Read to EOF and reject growth, truncation, or metadata drift."""
        before = os.fstat(self.fd)
        assert_same(self.metadata, before, self.relative_path)
        if before.st_size > self.max_bytes:
            raise SafeSourceFilesystemError("source file bytes exceeds the resource budget")
        chunks = bytearray()
        while True:
            block = os.read(self.fd, min(_CHUNK, self.max_bytes - len(chunks) + 1))
            if not block:
                break
            chunks.extend(block)
            if len(chunks) > before.st_size or len(chunks) > self.max_bytes:
                raise SafeSourceFilesystemError("source file bytes exceeds the resource budget")
        if len(chunks) != before.st_size or os.read(self.fd, 1):
            raise SafeSourceFilesystemError(f"source mutation observed during read: {self.relative_path}")
        assert_same(before, os.fstat(self.fd), self.relative_path)
        return bytes(chunks)


def is_denied_source_path(relative_path: str) -> bool:
    """Return whether a relative path belongs to a closed sensitive class."""
    lowered = relative_path.casefold()
    parts = tuple(part for part in lowered.split("/") if part)
    return (
        any(part == ".ssh" or "keychain" in part for part in parts)
        or any(part in _DENIED_NAMES for part in parts)
        or any(part == ".env" or part.startswith(".env.") for part in parts)
        or any(Path(part).suffix in _DENIED_SUFFIXES for part in parts)
        or _SENSITIVE_WORD.search(lowered) is not None
        or _REASONING_NAME.search(lowered) is not None
    )


class SafeSourceFilesystem:
    """Read-only descriptor client constrained to an explicit root allowlist."""

    def __init__(self, approved_roots: tuple[Path, ...], limits: SourceFilesystemLimits | None = None) -> None:
        if not approved_roots:
            raise SafeSourceFilesystemError("at least one approved source root is required")
        self._approved = frozenset(os.path.abspath(root) for root in approved_roots)
        self._limits = limits or SourceFilesystemLimits()

    def _open_root(self, root: Path) -> tuple[int, os.stat_result]:
        return open_approved_root(root, self._approved)

    def scan(self, root: Path) -> tuple[SourceFileMetadata, ...]:
        """Scan bounded metadata through no-follow descriptors without retaining every file FD."""
        root_fd, root_metadata = self._open_root(root)
        entries: list[SourceFileMetadata] = []
        entry_count = 0
        total_bytes = 0

        def walk(directory_fd: int, prefix: str, depth: int) -> None:
            nonlocal entry_count, total_bytes
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError as exc:
                raise translate_os_error(exc, prefix or ".") from exc
            for name in names:
                relative = f"{prefix}/{name}" if prefix else name
                entry_count += 1
                if entry_count > self._limits.max_entries:
                    raise SafeSourceFilesystemError("source entries exceed the resource budget")
                if is_denied_source_path(relative):
                    _LOGGER.warning("deny-class source path skipped: %s", relative)
                    continue
                try:
                    preview = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISLNK(preview.st_mode):
                        raise SafeSourceFilesystemError(f"symlink source path refused: {relative}")
                    assert_source_owner_mode(preview, relative)
                    if stat.S_ISDIR(preview.st_mode):
                        if name == ".git":
                            continue
                        if depth >= self._limits.max_depth:
                            raise SafeSourceFilesystemError("source depth exceeds the resource budget")
                        child_fd = os.open(name, DIRECTORY_OPEN_FLAGS, dir_fd=directory_fd)
                        try:
                            assert_same(preview, os.fstat(child_fd), relative)
                            walk(child_fd, relative, depth + 1)
                        finally:
                            os.close(child_fd)
                        continue
                    if not stat.S_ISREG(preview.st_mode):
                        raise SafeSourceFilesystemError(f"special source file refused: {relative}")
                    if preview.st_nlink != 1:
                        raise SafeSourceFilesystemError(f"hardlink source file refused: {relative}")
                    if len(entries) >= self._limits.max_files:
                        raise SafeSourceFilesystemError("source file count exceeds the resource budget")
                    if preview.st_size > self._limits.max_file_bytes:
                        raise SafeSourceFilesystemError("source file bytes exceeds the resource budget")
                    total_bytes += preview.st_size
                    if total_bytes > self._limits.max_total_bytes:
                        raise SafeSourceFilesystemError("source aggregate bytes exceed the resource budget")
                    file_fd = os.open(name, _FILE_FLAGS, dir_fd=directory_fd)
                    try:
                        assert_same(preview, os.fstat(file_fd), relative)
                    finally:
                        os.close(file_fd)
                    entries.append(SourceFileMetadata(relative, preview))
                except OSError as exc:
                    raise translate_os_error(exc, relative) from exc

        try:
            walk(root_fd, "", 0)
            assert_same(root_metadata, os.fstat(root_fd), ".")
            return tuple(sorted(entries, key=lambda entry: entry.relative_path))
        finally:
            os.close(root_fd)

    def open_file(self, root: Path, relative_path: str) -> PinnedSourceFile:
        """Open one canonical regular file with no-follow checks on every component."""
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or pure.as_posix() != relative_path or any(part in {"", ".", ".."} for part in pure.parts):
            raise SafeSourceFilesystemError("source path escape detected")
        if is_denied_source_path(relative_path):
            raise SafeSourceFilesystemError(f"deny-class source path refused: {relative_path}")
        root_fd, _root_metadata = self._open_root(root)
        parent_fd = root_fd
        try:
            for part in pure.parts[:-1]:
                preview = os.stat(part, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(preview.st_mode):
                    raise SafeSourceFilesystemError(f"symlink source path refused: {relative_path}")
                if not stat.S_ISDIR(preview.st_mode):
                    raise SafeSourceFilesystemError(f"special source file refused: {relative_path}")
                assert_source_owner_mode(preview, relative_path)
                child_fd = os.open(part, DIRECTORY_OPEN_FLAGS, dir_fd=parent_fd)
                assert_same(preview, os.fstat(child_fd), relative_path)
                if parent_fd != root_fd:
                    os.close(parent_fd)
                parent_fd = child_fd
            preview = os.stat(pure.name, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(preview.st_mode):
                raise SafeSourceFilesystemError(f"symlink source path refused: {relative_path}")
            if not stat.S_ISREG(preview.st_mode):
                raise SafeSourceFilesystemError(f"special source file refused: {relative_path}")
            assert_source_owner_mode(preview, relative_path)
            if preview.st_nlink != 1:
                raise SafeSourceFilesystemError(f"hardlink source file refused: {relative_path}")
            if preview.st_size > self._limits.max_file_bytes:
                raise SafeSourceFilesystemError("source file bytes exceeds the resource budget")
            file_fd = os.open(pure.name, _FILE_FLAGS, dir_fd=parent_fd)
            assert_same(preview, os.fstat(file_fd), relative_path)
            return PinnedSourceFile(file_fd, relative_path, preview, self._limits.max_file_bytes)
        except OSError as exc:
            raise translate_os_error(exc, relative_path) from exc
        finally:
            if parent_fd != root_fd:
                os.close(parent_fd)
            os.close(root_fd)

    def read_file(self, opened: PinnedSourceFile) -> bytes:
        """Read an admitted descriptor under this client's byte limit."""
        if opened.max_bytes != self._limits.max_file_bytes:
            raise SafeSourceFilesystemError("source descriptor belongs to another filesystem authority")
        return opened.read()
