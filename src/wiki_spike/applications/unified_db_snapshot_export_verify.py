"""Offline fixture-package verify and fixture-file admission."""
from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    read_bounded_path,
)
from wiki_spike.applications.unified_db_snapshot_export_tree import (
    assert_root_allowlist,
    open_package_root,
    read_payload_tree_at,
    read_root_file,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import CoreContractError
from wiki_spike.memory_core.snapshot_import import BoundedSnapshotV1
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_bind import package_digest
from wiki_spike.memory_core.unified_db_snapshot_export_evidence import (
    UnifiedDbExportEvidenceV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_fixture import (
    UnifiedDbExportFixtureV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object
from wiki_spike.memory_core.unified_db_snapshot_export_manifest import PayloadManifestV1
from wiki_spike.memory_core.unified_db_snapshot_export_proof import (
    FixtureReadResultV1,
    UnifiedDbReadSafetyProofV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)


def load_export_fixture(path: Path) -> FixtureReadResultV1:
    raw = read_bounded_path(path, HARD_CAP)
    fixture = UnifiedDbExportFixtureV1.from_mapping(decode_json_object(raw.decode("utf-8")))
    opening = _proof(fixture, "OPENING")
    closing = _proof(fixture, "CLOSING")
    return FixtureReadResultV1(
        fixture.rows,
        opening,
        closing,
        fixture.cursors,
        fixture.fixture_id,
        fixture.fixture_digest,
        fixture.row_set_digest,
    )


def _proof(fixture: UnifiedDbExportFixtureV1, phase: str) -> UnifiedDbReadSafetyProofV1:
    from wiki_spike.memory_core.second_brain_ledger_contracts import (
        canonical_ledger_digest,
    )

    body: dict[str, JsonValue] = {
        "proof_version": "second-brain-unified-db-export-read-safety-proof-v1",
        "phase": phase,
        "isolation": "SERIALIZABLE",
        "read_only": True,
        "deferrable": True,
        "writer_count": "0",
        "db_commitment": fixture.db_commitment,
        "catalog_commitment": fixture.catalog_commitment,
        "source_commitment": fixture.source_commitment,
        "data_root_commitment": fixture.data_root_commitment,
    }
    return UnifiedDbReadSafetyProofV1.from_mapping(
        body
        | {
            "proof_digest": canonical_ledger_digest(
                "unified-db-export-read-safety-proof-v1",
                body,
            )
        }
    )


def verify_export_package(package_root: str) -> UnifiedDbExportReceiptV1:
    root_fd = open_package_root(package_root)
    try:
        assert_root_allowlist(root_fd)
        budget = HARD_CAP
        receipt_map, budget = _decode(root_fd, "receipt.json", budget)
        evidence_map, budget = _decode(root_fd, "evidence.json", budget)
        snapshot_map, budget = _decode(root_fd, "bounded-snapshot.json", budget)
        manifest_map, budget = _decode(root_fd, "payload-manifest.json", budget)
        opening_map, budget = _decode(root_fd, "opening-proof.json", budget)
        closing_map, budget = _decode(root_fd, "closing-proof.json", budget)
        receipt = UnifiedDbExportReceiptV1.from_mapping(receipt_map)
        evidence = UnifiedDbExportEvidenceV1.from_mapping(evidence_map)
        snapshot = BoundedSnapshotV1.from_mapping(snapshot_map)
        manifest = PayloadManifestV1.from_mapping(manifest_map)
        opening = UnifiedDbReadSafetyProofV1.from_mapping(opening_map)
        closing = UnifiedDbReadSafetyProofV1.from_mapping(closing_map)
        payload, _budget = read_payload_tree_at(root_fd, budget)
    except (OSError, CoreContractError) as exc:
        raise UnifiedDbExportError("package contracts cannot be verified") from exc
    finally:
        os.close(root_fd)
    return _join(receipt, evidence, snapshot, manifest, opening, closing, payload)


def _decode(root_fd: int, name: str, budget: int) -> tuple[dict[str, JsonValue], int]:
    data, remaining = read_root_file(root_fd, name, budget)
    parsed = decode_json_object(data.decode("utf-8"))
    if canonical_bytes(parsed) + b"\n" != data:
        raise UnifiedDbExportError("package metadata is not canonical")
    return parsed, remaining


def _join(
    receipt: UnifiedDbExportReceiptV1,
    evidence: UnifiedDbExportEvidenceV1,
    snapshot: BoundedSnapshotV1,
    manifest: PayloadManifestV1,
    opening: UnifiedDbReadSafetyProofV1,
    closing: UnifiedDbReadSafetyProofV1,
    payload: dict[str, bytes],
) -> UnifiedDbExportReceiptV1:
    live = {record.relative_path for record in snapshot.records if record.relative_path}
    if set(payload) != live or live != {entry.relative_path for entry in manifest.entries}:
        raise UnifiedDbExportError("extra or missing payload files")
    files: list[tuple[str, bytes]] = []
    total = 0
    for record in snapshot.records:
        if record.relative_path is None:
            continue
        content = payload[record.relative_path]
        if sha256(content).hexdigest() != record.content_digest:
            raise UnifiedDbExportError("payload digest mismatch")
        files.append((record.relative_path, content))
        total += len(content)
    expected = package_digest(
        snapshot.snapshot_digest,
        tuple(files),
        receipt.profile_digest,
        receipt.plan_digest,
        manifest.manifest_digest,
        receipt.cursor_map_digest,
    )
    tombs = str(sum(1 for record in snapshot.records if record.tombstone))
    lives = str(len(snapshot.records) - int(tombs))
    if (
        expected != receipt.package_digest
        or evidence.package_digest != receipt.package_digest
        or receipt.evidence_digest != evidence.evidence_digest
        or receipt.snapshot_digest != snapshot.snapshot_digest
        or evidence.snapshot_digest != snapshot.snapshot_digest
        or receipt.payload_manifest_digest != manifest.manifest_digest
        or evidence.payload_manifest_digest != manifest.manifest_digest
        or receipt.cursor_map_digest != evidence.cursor_map_digest
        or receipt.record_count != evidence.record_count
        or receipt.record_count != str(len(snapshot.records))
        or receipt.live_record_count != evidence.live_record_count
        or receipt.live_record_count != lives
        or receipt.tombstone_count != evidence.tombstone_count
        or receipt.tombstone_count != tombs
        or receipt.byte_count != evidence.byte_count
        or receipt.byte_count != str(total)
        or receipt.opening_proof_digest != opening.proof_digest
        or evidence.opening_proof_digest != opening.proof_digest
        or receipt.closing_proof_digest != closing.proof_digest
        or evidence.closing_proof_digest != closing.proof_digest
        or opening.phase != "OPENING"
        or closing.phase != "CLOSING"
        or snapshot.snapshot_watermark != receipt.cursor_map_digest
    ):
        raise UnifiedDbExportError("package digest mismatch")
    return receipt
