"""Fail-closed metadata-only filesystem discovery for approved source roots."""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from wiki_spike.memory_core.source_discovery import (
    SourceDiscoveryEntryV1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
    path_digest,
)

_ALLOWED_SUFFIXES: Final = frozenset(
    {
        ".md",
        ".json",
        ".jsonl",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".csv",
        ".parquet",
        ".yaml",
        ".yml",
        ".toml",
    }
)
_DENIED_SUFFIXES: Final = frozenset(
    {
        ".pem",
        ".key",
        ".p7b",
        ".p7c",
        ".p12",
        ".pfx",
        ".cer",
        ".crt",
        ".der",
        ".keychain",
        ".keychain-db",
    }
)
_DENIED_NAMES: Final = frozenset(
    {
        ".netrc",
        "cookies",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "known_hosts",
    }
)
_SENSITIVE_WORD: Final = re.compile(
    "(?:^|[._\\-/])(?:access[-_]?token|auth[-_]?token|cookie|credential|"
    + "private[-_]?key|refresh[-_]?token|secret|session|token)s?(?:[._\\-/]|$)"
)
_REASONING_NAME: Final = re.compile(
    "(?:^|[._\\-/])(?:chain[-_]?of[-_]?thought|cot|hidden[-_]?reasoning)"
    + "(?:[._\\-/]|$)"
)


class SourceDiscoveryError(ValueError):
    """Discovery refused because filesystem safety could not be proven."""


@dataclass(frozen=True, slots=True)
class _ObservedPath:
    path: Path
    relative_path: str
    metadata: os.stat_result


def _deny_class(relative_path: str) -> bool:
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


def _metadata_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )


def _scan_tree(
    root: Path, request: SourceDiscoveryRequestV1
) -> tuple[tuple[SourceDiscoveryEntryV1, ...], tuple[_ObservedPath, ...]]:
    entries: list[SourceDiscoveryEntryV1] = []
    observed: list[_ObservedPath] = []
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = sorted(iterator, key=lambda child: child.name)
        except OSError as exc:
            raise SourceDiscoveryError("source scan error while listing a directory") from exc
        for child in children:
            candidate = Path(child.path)
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError as exc:
                raise SourceDiscoveryError("source path escape detected") from exc
            if os.path.commonpath((str(root), str(candidate.absolute()))) != str(root):
                raise SourceDiscoveryError("source path escape detected")
            if _deny_class(relative):
                raise SourceDiscoveryError(f"deny-class source path refused: {relative}")
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SourceDiscoveryError(f"source scan error for metadata path: {relative}") from exc
            observed.append(_ObservedPath(candidate, relative, metadata))
            if stat.S_ISLNK(metadata.st_mode):
                raise SourceDiscoveryError(f"symlink source path refused: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                pending.append(candidate)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceDiscoveryError(f"special source file refused: {relative}")
            suffix = candidate.suffix.casefold()
            if not suffix or suffix not in _ALLOWED_SUFFIXES:
                raise SourceDiscoveryError(f"unsupported source file suffix: {relative}")
            size = str(metadata.st_size)
            mtime = str(metadata.st_mtime_ns)
            mode = str(metadata.st_mode)
            entry = SourceDiscoveryEntryV1(
                relative, "file", size, mtime, mode, "0" * 64
            )
            entries.append(
                replace(entry, path_digest=path_digest(request.source_name, entry))
            )
    return tuple(sorted(entries, key=lambda entry: entry.relative_path)), tuple(observed)


def _verify_unchanged(root: Path, root_before: os.stat_result, observed: tuple[_ObservedPath, ...]) -> None:
    for item in observed:
        try:
            current = os.stat(item.path, follow_symlinks=False)
        except OSError as exc:
            raise SourceDiscoveryError(
                f"source mutation observed during scan: {item.relative_path}"
            ) from exc
        if _metadata_changed(item.metadata, current):
            raise SourceDiscoveryError(
                f"source mutation observed during scan: {item.relative_path}"
            )
    try:
        root_after = os.stat(root, follow_symlinks=False)
    except OSError as exc:
        raise SourceDiscoveryError("source root mutation observed during scan") from exc
    if _metadata_changed(root_before, root_after):
        raise SourceDiscoveryError("source root mutation observed during scan")


def discover_source(request: SourceDiscoveryRequestV1) -> SourceDiscoveryManifestV1:
    """Discover approved regular files without opening any source body."""
    source_root = Path(request.source_root)
    try:
        unresolved_metadata = os.lstat(source_root)
    except OSError as exc:
        raise SourceDiscoveryError("source root does not exist or is inaccessible") from exc
    if stat.S_ISLNK(unresolved_metadata.st_mode):
        raise SourceDiscoveryError("source root symlink refused")
    try:
        root = source_root.resolve(strict=True)
        root_before = os.stat(root, follow_symlinks=False)
    except (OSError, RuntimeError) as exc:
        raise SourceDiscoveryError("source root cannot be resolved safely") from exc
    if not stat.S_ISDIR(root_before.st_mode):
        raise SourceDiscoveryError("source root must be a directory")
    entries, observed = _scan_tree(root, request)
    _verify_unchanged(root, root_before, observed)
    return SourceDiscoveryManifestV1.create(request, entries)
