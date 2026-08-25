"""Deterministic, fail-closed reconciliation for certified complete snapshots."""
from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Final

from .contracts import JsonValue
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import import BoundedSnapshotV1, SnapshotRecordV1
from .source_discovery import SourceDiscoveryManifestV1, SourceName

COMPLETE_SNAPSHOT_CERTIFICATE_V1: Final = "second-brain-complete-snapshot-certificate-v1"
_SOURCE_ROOT_DIGEST_DOMAIN: Final = b"second-brain-complete-snapshot-source-root/v1\0"


def source_root_digest(source_root: str) -> str:
    """Opaque one source root under the certificate-specific digest domain."""
    return sha256(_SOURCE_ROOT_DIGEST_DOMAIN + source_root.encode("utf-8")).hexdigest()


class SnapshotDisposition(StrEnum):
    """Closed conservation outcomes for one native source identity."""

    ACCEPTED = "ACCEPTED"
    UPDATED = "UPDATED"
    DUPLICATE = "DUPLICATE"
    TOMBSTONED = "TOMBSTONED"
    QUARANTINED = "QUARANTINED"


class SnapshotReconciliationError(ValueError):
    """Reconciliation failed before any deletion inference was possible."""

    reason: str

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class CompleteSnapshotCertificateV1:
    """Body-free proof that one discovery manifest closed without scan failure."""

    certificate_version: str
    source_name: SourceName
    source_root_digest: str
    manifest_digest: str
    entry_paths: tuple[str, ...]
    completion: str
    certificate_digest: str

    @classmethod
    def issue(cls, manifest: SourceDiscoveryManifestV1) -> CompleteSnapshotCertificateV1:
        """Issue only from a closed manifest produced after mutation checks pass."""
        paths = tuple(entry.relative_path for entry in manifest.entries)
        body: dict[str, JsonValue] = {
            "certificate_version": COMPLETE_SNAPSHOT_CERTIFICATE_V1,
            "source_name": manifest.source_name,
            "source_root_digest": source_root_digest(manifest.source_root),
            "manifest_digest": manifest.manifest_digest,
            "entry_paths": list(paths),
            "completion": "COMPLETE",
        }
        return cls(
            COMPLETE_SNAPSHOT_CERTIFICATE_V1,
            manifest.source_name,
            source_root_digest(manifest.source_root),
            manifest.manifest_digest,
            paths,
            "COMPLETE",
            canonical_ledger_digest("complete-snapshot-certificate-v1", body),
        )

    def __post_init__(self) -> None:
        if self.certificate_version != COMPLETE_SNAPSHOT_CERTIFICATE_V1:
            raise SnapshotReconciliationError("complete-snapshot certificate version is unsupported")
        if self.completion != "COMPLETE":
            raise SnapshotReconciliationError("complete-snapshot certificate must fail closed")
        if len(self.source_root_digest) != 64 or any(character not in "0123456789abcdef" for character in self.source_root_digest):
            raise SnapshotReconciliationError("complete-snapshot source root digest is invalid")
        if self.entry_paths != tuple(sorted(self.entry_paths)) or len(set(self.entry_paths)) != len(self.entry_paths):
            raise SnapshotReconciliationError("complete-snapshot certificate paths are not canonical")
        if self.certificate_digest != self.computed_digest():
            raise SnapshotReconciliationError("complete-snapshot certificate digest mismatch")

    def computed_digest(self) -> str:
        return canonical_ledger_digest(
            "complete-snapshot-certificate-v1",
            {
                "certificate_version": self.certificate_version,
                "source_name": self.source_name,
                "source_root_digest": self.source_root_digest,
                "manifest_digest": self.manifest_digest,
                "entry_paths": list(self.entry_paths),
                "completion": self.completion,
            },
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        """Serialize the body-free certificate without its transient absolute root."""
        return {
            "certificate_version": self.certificate_version,
            "source_name": self.source_name,
            "source_root_digest": self.source_root_digest,
            "manifest_digest": self.manifest_digest,
            "entry_paths": list(self.entry_paths),
            "completion": self.completion,
            "certificate_digest": self.certificate_digest,
        }

    def assert_manifest(self, manifest: SourceDiscoveryManifestV1) -> None:
        """Reject rebinding a certificate to another scan or source scope."""
        expected = CompleteSnapshotCertificateV1.issue(manifest)
        if self != expected:
            raise SnapshotReconciliationError("complete-snapshot certificate does not bind the manifest")


@dataclass(frozen=True, slots=True)
class SnapshotReconciliationItemV1:
    native_id: str
    disposition: SnapshotDisposition
    keyed_dedupe_ref: str | None
    previous_revision: str | None
    current_revision: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class ProvenanceEdgeRemovalV1:
    """Remove one source edge without deleting shared canonical content."""

    source_name: SourceName
    native_id: str
    keyed_dedupe_ref: str
    reason: str = "COMPLETE_SNAPSHOT_ABSENCE"


@dataclass(frozen=True, slots=True)
class SnapshotReconciliationV1:
    items: tuple[SnapshotReconciliationItemV1, ...]
    provenance_edge_removals: tuple[ProvenanceEdgeRemovalV1, ...]
    expected_count: int
    accounted_count: int
    disposition_counts: Mapping[SnapshotDisposition, int]

    def __hash__(self) -> int:
        counts = tuple((disposition, self.disposition_counts[disposition]) for disposition in SnapshotDisposition)
        return hash((self.items, self.provenance_edge_removals, self.expected_count, self.accounted_count, counts))


def _same_revision_payload(previous: SnapshotRecordV1, current: SnapshotRecordV1) -> bool:
    return (
        previous.tombstone,
        previous.relative_path,
        previous.content_digest,
        previous.keyed_dedupe_ref,
    ) == (
        current.tombstone,
        current.relative_path,
        current.content_digest,
        current.keyed_dedupe_ref,
    )


def _semantic_payload(record: SnapshotRecordV1) -> tuple[str, str] | None:
    if record.tombstone or record.keyed_dedupe_ref is None or record.content_digest is None:
        return None
    return record.keyed_dedupe_ref, record.content_digest


def _current_disposition(
    previous: SnapshotRecordV1 | None,
    current: SnapshotRecordV1,
    duplicate_semantics: frozenset[tuple[str, str]],
) -> tuple[SnapshotDisposition, str]:
    if previous is not None and previous.revision == current.revision:
        if _same_revision_payload(previous, current):
            return SnapshotDisposition.DUPLICATE, "IDENTICAL_REVISION_REPLAY"
        return SnapshotDisposition.QUARANTINED, "REVISION_COLLISION"
    if current.tombstone:
        return SnapshotDisposition.TOMBSTONED, "EXPLICIT_SOURCE_TOMBSTONE"
    if previous is None:
        if _semantic_payload(current) in duplicate_semantics:
            return SnapshotDisposition.DUPLICATE, "KEYED_PAYLOAD_DUPLICATE"
        return SnapshotDisposition.ACCEPTED, "NEW_NATIVE_IDENTITY"
    return SnapshotDisposition.UPDATED, "NEW_REVISION"


def _item_for_current(
    previous: SnapshotRecordV1 | None,
    current: SnapshotRecordV1,
    duplicate_semantics: frozenset[tuple[str, str]],
) -> SnapshotReconciliationItemV1:
    disposition, reason = _current_disposition(previous, current, duplicate_semantics)
    return SnapshotReconciliationItemV1(
        current.native_id,
        disposition,
        current.keyed_dedupe_ref,
        None if previous is None else previous.revision,
        current.revision,
        reason,
    )


def reconcile_snapshot(
    previous: BoundedSnapshotV1,
    current: BoundedSnapshotV1,
    certificate: CompleteSnapshotCertificateV1 | None,
    current_manifest: SourceDiscoveryManifestV1 | None = None,
) -> SnapshotReconciliationV1:
    """Conserve native identities and infer absence only under an exact certified manifest."""
    if previous.source_name != current.source_name or previous.native_namespace != current.native_namespace:
        raise SnapshotReconciliationError("snapshot source scope mismatch")
    live_paths = tuple(sorted(record.relative_path for record in current.records if record.relative_path is not None))
    certified_complete = certificate is not None
    if certificate is not None:
        if current_manifest is None:
            raise SnapshotReconciliationError("complete-snapshot certificate requires its current manifest")
        certificate.assert_manifest(current_manifest)
        if current_manifest.source_name != current.source_name or certificate.entry_paths != live_paths:
            raise SnapshotReconciliationError("complete-snapshot certificate does not bind current live paths")

    prior = {record.native_id: record for record in previous.records}
    incoming = {record.native_id: record for record in current.records}
    prior_semantics = frozenset(value for record in previous.records if (value := _semantic_payload(record)) is not None)
    seen_current: set[tuple[str, str]] = set()
    items: list[SnapshotReconciliationItemV1] = []
    removals: list[ProvenanceEdgeRemovalV1] = []
    for native_id in sorted(set(prior) | set(incoming)):
        old, new = prior.get(native_id), incoming.get(native_id)
        if new is None:
            disposition = SnapshotDisposition.TOMBSTONED if certified_complete else SnapshotDisposition.QUARANTINED
            reason = "COMPLETE_SNAPSHOT_ABSENCE" if certified_complete else "UNCERTIFIED_ABSENCE"
            items.append(SnapshotReconciliationItemV1(native_id, disposition, old.keyed_dedupe_ref if old else None, old.revision if old else None, None, reason))
            if certified_complete and old is not None and old.keyed_dedupe_ref is not None:
                removals.append(ProvenanceEdgeRemovalV1(current.source_name, native_id, old.keyed_dedupe_ref))
            continue
        duplicate_semantics = prior_semantics | frozenset(seen_current)
        item = _item_for_current(old, new, duplicate_semantics)
        items.append(item)
        semantic = _semantic_payload(new)
        if semantic is not None:
            seen_current.add(semantic)
        if item.disposition is SnapshotDisposition.TOMBSTONED and old is not None and old.keyed_dedupe_ref is not None:
            removals.append(ProvenanceEdgeRemovalV1(current.source_name, native_id, old.keyed_dedupe_ref, "EXPLICIT_SOURCE_TOMBSTONE"))

    counts = Counter(item.disposition for item in items)
    closed_counts = {disposition: counts[disposition] for disposition in SnapshotDisposition}
    accounted = sum(closed_counts.values())
    if accounted != len(items):
        raise SnapshotReconciliationError("snapshot disposition conservation failed")
    return SnapshotReconciliationV1(
        tuple(items),
        tuple(removals),
        len(set(prior) | set(incoming)),
        accounted,
        MappingProxyType(closed_counts),
    )
