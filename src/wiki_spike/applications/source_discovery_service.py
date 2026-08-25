"""Fail-closed metadata-only filesystem discovery for approved source roots."""
from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Final

from wiki_spike.infrastructure.safe_source_filesystem import (
    SafeSourceFilesystem,
    SafeSourceFilesystemError,
)
from wiki_spike.infrastructure.safe_source_filesystem import (
    is_denied_source_path as _is_denied_source_path,
)
from wiki_spike.memory_core.second_brain_complete_snapshot import (
    CompleteSnapshotCertificateV1,
)
from wiki_spike.memory_core.source_discovery import (
    SourceDiscoveryEntryV1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
    path_digest,
)

_ALLOWED_SUFFIXES: Final = frozenset(
    {".csv", ".db", ".json", ".jsonl", ".md", ".parquet", ".sqlite", ".sqlite3", ".toml", ".yaml", ".yml"}
)


class SourceDiscoveryError(ValueError):
    """Discovery refused because filesystem safety could not be proven."""


@dataclass(frozen=True, slots=True)
class CertifiedSourceDiscoveryV1:
    """A complete manifest and the certificate issued by the same closed scan."""

    manifest: SourceDiscoveryManifestV1
    certificate: CompleteSnapshotCertificateV1


def is_denied_source_path(relative_path: str) -> bool:
    """Return True when a relative path is in a closed deny class."""
    return _is_denied_source_path(relative_path)


def is_allowed_source_suffix(relative_path: str) -> bool:
    """Return True when the file suffix is an approved discovery/import type."""
    suffix = Path(relative_path).suffix.casefold()
    return bool(suffix) and suffix in _ALLOWED_SUFFIXES


def discover_certified_source(
    request: SourceDiscoveryRequestV1,
    filesystem: SafeSourceFilesystem | None = None,
) -> CertifiedSourceDiscoveryV1:
    """Return a certificate only after the metadata scan and mutation check close."""
    manifest = discover_source(request, filesystem)
    return CertifiedSourceDiscoveryV1(manifest, CompleteSnapshotCertificateV1.issue(manifest))


def discover_source(
    request: SourceDiscoveryRequestV1,
    filesystem: SafeSourceFilesystem | None = None,
) -> SourceDiscoveryManifestV1:
    """Discover approved regular files without reading any source body."""
    root = Path(request.source_root)
    client = filesystem or SafeSourceFilesystem((root,))
    try:
        scanned = client.scan(root, reject_denied=True)
    except SafeSourceFilesystemError as exc:
        raise SourceDiscoveryError(str(exc)) from exc
    entries: list[SourceDiscoveryEntryV1] = []
    for item in scanned:
        if not is_allowed_source_suffix(item.relative_path):
            raise SourceDiscoveryError(f"unsupported source file suffix: {item.relative_path}")
        metadata = item.metadata
        entry = SourceDiscoveryEntryV1(
            item.relative_path,
            "file",
            str(metadata.st_size),
            str(metadata.st_mtime_ns),
            str(metadata.st_mode),
            "0" * 64,
        )
        entries.append(replace(entry, path_digest=path_digest(request.source_name, entry)))
    return SourceDiscoveryManifestV1.create(request, tuple(entries))
