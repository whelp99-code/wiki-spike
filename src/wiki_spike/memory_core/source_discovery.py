"""Closed metadata-only source-discovery contracts."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePath, PurePosixPath
from typing import TYPE_CHECKING, Final, Literal

from .contracts import JsonValue, canonical_bytes
from .errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)

if TYPE_CHECKING:
    from .second_brain_complete_snapshot import CompleteSnapshotCertificateV1

SOURCE_DISCOVERY_REQUEST_V1: Final = "second-brain-source-discovery-request-v1"
SOURCE_DISCOVERY_ENTRY_V1: Final = "second-brain-source-discovery-entry-v1"
SOURCE_DISCOVERY_MANIFEST_V1: Final = "second-brain-source-discovery-manifest-v1"
SourceName = Literal["me-wiki", "unified-db", "legacy Mem0/RAG"]

_DECIMAL: Final = re.compile(r"^(0|[1-9][0-9]*)$")
_DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_FIELDS: Final = frozenset({"request_version", "source_name", "source_root"})
_ENTRY_FIELDS: Final = frozenset(
    {"relative_path", "kind", "size_bytes", "mtime_ns", "mode", "path_digest"}
)
_MANIFEST_FIELDS: Final = frozenset(
    {
        "manifest_version",
        "request_version",
        "source_name",
        "source_root",
        "entry_count",
        "body_reads",
        "entries",
        "manifest_digest",
    }
)


def _strict(data: Mapping[str, JsonValue], fields: frozenset[str]) -> None:
    unknown = set(data) - fields
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    missing = fields - set(data)
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")


def _string(value: JsonValue, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _decimal(value: JsonValue, field: str) -> str:
    parsed = _string(value, field)
    if _DECIMAL.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a canonical decimal string")
    return parsed


def _source_name(value: JsonValue) -> SourceName:
    approved: dict[str, SourceName] = {
        "me-wiki": "me-wiki",
        "unified-db": "unified-db",
        "legacy Mem0/RAG": "legacy Mem0/RAG",
    }
    if not isinstance(value, str):
        raise InvalidContractValue("source_name is not an approved discovery source")
    try:
        return approved[value]
    except KeyError as exc:
        raise InvalidContractValue("source_name is not an approved discovery source") from exc


def _relative_path(value: JsonValue) -> str:
    path = _string(value, "relative_path")
    pure = PurePosixPath(path)
    if (
        pure.is_absolute()
        or "\\" in path
        or path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise InvalidContractValue("relative_path must be a canonical relative POSIX path")
    return path


def path_digest(
    source_name: SourceName, entry: SourceDiscoveryEntryV1
) -> str:
    """Bind a source identity to path and lstat metadata, never file bytes."""
    body: dict[str, JsonValue] = {
        "source_name": source_name,
        "relative_path": entry.relative_path,
        "kind": entry.kind,
        "size_bytes": entry.size_bytes,
        "mtime_ns": entry.mtime_ns,
        "mode": entry.mode,
    }
    domain = f"{SOURCE_DISCOVERY_ENTRY_V1}\0".encode()
    return sha256(domain + canonical_bytes(body)).hexdigest()


@dataclass(frozen=True, slots=True)
class SourceDiscoveryRequestV1:
    request_version: str
    source_name: SourceName
    source_root: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> SourceDiscoveryRequestV1:
        _strict(data, _REQUEST_FIELDS)
        version = _string(data["request_version"], "request_version")
        if version != SOURCE_DISCOVERY_REQUEST_V1:
            raise UnsupportedContractVersion(f"unsupported request_version: {version!r}")
        root = _string(data["source_root"], "source_root")
        if not PurePath(root).is_absolute():
            raise InvalidContractValue("source_root must be a non-empty absolute path string")
        return cls(version, _source_name(data["source_name"]), root)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "request_version": self.request_version,
            "source_name": self.source_name,
            "source_root": self.source_root,
        }


@dataclass(frozen=True, slots=True)
class SourceDiscoveryEntryV1:
    relative_path: str
    kind: str
    size_bytes: str
    mtime_ns: str
    mode: str
    path_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue], *, source_name: SourceName
    ) -> SourceDiscoveryEntryV1:
        _strict(data, _ENTRY_FIELDS)
        relative = _relative_path(data["relative_path"])
        kind = _string(data["kind"], "kind")
        if kind != "file":
            raise InvalidContractValue("kind must be file")
        size = _decimal(data["size_bytes"], "size_bytes")
        mtime = _decimal(data["mtime_ns"], "mtime_ns")
        mode = _decimal(data["mode"], "mode")
        digest = _string(data["path_digest"], "path_digest")
        if _DIGEST.fullmatch(digest) is None:
            raise InvalidContractValue("path_digest must be a lowercase SHA-256 digest")
        parsed = cls(relative, kind, size, mtime, mode, digest)
        if digest != path_digest(source_name, parsed):
            raise InvalidContractValue("path_digest does not bind source path metadata")
        return parsed

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "relative_path": self.relative_path,
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "mtime_ns": self.mtime_ns,
            "mode": self.mode,
            "path_digest": self.path_digest,
        }


@dataclass(frozen=True, slots=True)
class SourceDiscoveryManifestV1:
    manifest_version: str
    request_version: str
    source_name: SourceName
    source_root: str
    entry_count: str
    body_reads: str
    entries: tuple[SourceDiscoveryEntryV1, ...]
    manifest_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> SourceDiscoveryManifestV1:
        _strict(data, _MANIFEST_FIELDS)
        request = SourceDiscoveryRequestV1.from_mapping(
            {
                "request_version": data["request_version"],
                "source_name": data["source_name"],
                "source_root": data["source_root"],
            }
        )
        version = _string(data["manifest_version"], "manifest_version")
        if version != SOURCE_DISCOVERY_MANIFEST_V1:
            raise UnsupportedContractVersion(f"unsupported manifest_version: {version!r}")
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise InvalidContractValue("entries must be an array")
        entries = tuple(
            SourceDiscoveryEntryV1.from_mapping(item, source_name=request.source_name)
            for item in raw_entries
            if isinstance(item, Mapping)
        )
        if len(entries) != len(raw_entries):
            raise InvalidContractValue("every entry must be an object")
        paths = tuple(entry.relative_path for entry in entries)
        if paths != tuple(sorted(paths)) or len(set(paths)) != len(paths):
            raise InvalidContractValue("entries must have unique lexically sorted paths")
        count = _decimal(data["entry_count"], "entry_count")
        if count != str(len(entries)):
            raise InvalidContractValue("entry_count does not match entries")
        body_reads = _decimal(data["body_reads"], "body_reads")
        if body_reads != "0":
            raise InvalidContractValue("body_reads must be 0")
        digest = _string(data["manifest_digest"], "manifest_digest")
        if _DIGEST.fullmatch(digest) is None:
            raise InvalidContractValue("manifest_digest must be a lowercase SHA-256 digest")
        manifest = cls(
            version,
            request.request_version,
            request.source_name,
            request.source_root,
            count,
            body_reads,
            entries,
            digest,
        )
        if digest != manifest.computed_digest():
            raise InvalidContractValue("manifest_digest does not bind manifest fields")
        return manifest

    @classmethod
    def create(
        cls,
        request: SourceDiscoveryRequestV1,
        entries: tuple[SourceDiscoveryEntryV1, ...],
    ) -> SourceDiscoveryManifestV1:
        provisional = cls(
            SOURCE_DISCOVERY_MANIFEST_V1,
            request.request_version,
            request.source_name,
            request.source_root,
            str(len(entries)),
            "0",
            entries,
            "0" * 64,
        )
        return cls.from_mapping(provisional.to_mapping() | {
            "manifest_digest": provisional.computed_digest()
        })

    def complete_snapshot_certificate(self) -> CompleteSnapshotCertificateV1:
        """Certify only a manifest emitted after the scanner's mutation checks."""
        from .second_brain_complete_snapshot import CompleteSnapshotCertificateV1

        return CompleteSnapshotCertificateV1.issue(self)

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["manifest_digest"]
        domain = f"{SOURCE_DISCOVERY_MANIFEST_V1}\0".encode()
        return sha256(domain + canonical_bytes(body)).hexdigest()

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "manifest_version": self.manifest_version,
            "request_version": self.request_version,
            "source_name": self.source_name,
            "source_root": self.source_root,
            "entry_count": self.entry_count,
            "body_reads": self.body_reads,
            "entries": [entry.to_mapping() for entry in self.entries],
            "manifest_digest": self.manifest_digest,
        }
