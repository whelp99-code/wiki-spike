from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.second_brain.unified_db_export_support import (
    authority,
    bound_reader,
    load_mapping,
    plan_for,
    profile,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
    verify_export_package,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_evidence import (
    UnifiedDbExportEvidenceV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_proof import (
    UnifiedDbReadSafetyProofV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)


def _export(dest: Path) -> None:
    exported = profile()
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    )
    _ = service.export_fixture(authority(), exported, plan_for(exported), str(dest))


def _writable(path: Path) -> None:
    os.chmod(path, 0o700 if path.is_dir() else 0o600)


def test_verify_joins_receipt_evidence_proofs_and_counts(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _export(dest)
    receipt = UnifiedDbExportReceiptV1.from_mapping(load_mapping(dest / "receipt.json"))
    evidence = UnifiedDbExportEvidenceV1.from_mapping(load_mapping(dest / "evidence.json"))
    opening = UnifiedDbReadSafetyProofV1.from_mapping(
        load_mapping(dest / "opening-proof.json")
    )
    closing = UnifiedDbReadSafetyProofV1.from_mapping(
        load_mapping(dest / "closing-proof.json")
    )
    discovery = load_mapping(dest / "payload-manifest.json")
    snapshot = load_mapping(dest / "bounded-snapshot.json")
    assert receipt.payload_manifest_digest == discovery["manifest_digest"]
    assert evidence.payload_manifest_digest == discovery["manifest_digest"]
    assert receipt.snapshot_digest == snapshot["snapshot_digest"]
    assert evidence.snapshot_digest == snapshot["snapshot_digest"]
    assert receipt.record_count == evidence.record_count == "3"
    assert receipt.live_record_count == evidence.live_record_count == "2"
    assert receipt.tombstone_count == evidence.tombstone_count == "1"
    assert receipt.byte_count == evidence.byte_count
    assert receipt.opening_proof_digest == opening.proof_digest
    assert receipt.closing_proof_digest == closing.proof_digest
    assert evidence.opening_proof_digest == opening.proof_digest
    assert evidence.closing_proof_digest == closing.proof_digest
    assert receipt.source_unchanged is True
    assert evidence.source_unchanged is True
    assert receipt.plaintext_leaked is False
    assert evidence.plaintext_leaked is False
    assert receipt.native_identity_leaked is False
    assert evidence.native_identity_leaked is False
    forbidden = {"body", "native_id", "relative_path", "watermark", "path"}
    assert forbidden.isdisjoint(receipt.to_mapping())
    assert forbidden.isdisjoint(evidence.to_mapping())
    assert forbidden.isdisjoint(opening.to_mapping())
    verified = verify_export_package(str(dest))
    assert verified.receipt_digest == receipt.receipt_digest


def test_verify_rejects_extra_payload_and_symlink_payload_dir(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _export(dest)
    _writable(dest)
    _writable(dest / "payload")
    extra = dest / "payload" / "zzzz-extra.json"
    _ = extra.write_text("{}", encoding="utf-8")
    os.chmod(extra, 0o400)
    os.chmod(dest / "payload", 0o500)
    os.chmod(dest, 0o500)
    with pytest.raises(UnifiedDbExportError, match="extra|payload"):
        _ = verify_export_package(str(dest))

    clean = tmp_path / "clean"
    _export(clean)
    _writable(clean)
    payload = clean / "payload"
    _writable(payload)
    moved = tmp_path / "moved-payload"
    _ = payload.rename(moved)
    payload.symlink_to(moved)
    os.chmod(clean, 0o500)
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _ = verify_export_package(str(clean))


def test_export_start_rejects_symlink_ancestor_before_staging(tmp_path: Path) -> None:
    real = tmp_path / "real"
    nested = real / "nested"
    nested.mkdir(parents=True)
    before = {path.name for path in nested.iterdir()}
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    dest = alias / "nested" / "pkg"
    writer = LocalSnapshotPackageWriter()
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _ = writer.start(str(dest))
    assert not dest.exists()
    assert {path.name for path in nested.iterdir()} == before
    exported = profile()
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=writer,
    )
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _ = service.export_fixture(
            authority(), exported, plan_for(exported), str(dest)
        )
    assert not dest.exists()
    assert {path.name for path in nested.iterdir()} == before


def test_verify_rejects_ancestor_symlink_substitution(tmp_path: Path) -> None:
    dest = tmp_path / "real" / "pkg"
    dest.parent.mkdir()
    _export(dest)
    alias = tmp_path / "alias"
    alias.symlink_to(dest.parent)
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _ = verify_export_package(str(alias / "pkg"))
