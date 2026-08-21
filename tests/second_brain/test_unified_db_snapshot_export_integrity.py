from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import override

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
    load_export_fixture,
    verify_export_package,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_snapshot_export import (
    PackageDurabilityUncertain,
    UnifiedDbExportError,
)
from wiki_spike.memory_core.unified_db_snapshot_export_evidence import (
    UnifiedDbExportEvidenceV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)


def _export(dest: Path) -> UnifiedDbExportReceiptV1:
    exported = profile()
    return UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    ).export_fixture(authority(), exported, plan_for(exported), str(dest))


def _unlock(path: Path) -> None:
    mode = 0o700 if path.is_dir() else 0o600
    os.chmod(path, mode)


def test_receipt_binds_evidence_digest_and_count_probe_fails(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    receipt = _export(dest)
    evidence = UnifiedDbExportEvidenceV1.from_mapping(load_mapping(dest / "evidence.json"))
    assert receipt.evidence_digest == evidence.evidence_digest
    _unlock(dest)
    _unlock(dest / "evidence.json")
    tampered = evidence.to_mapping()
    tampered["live_record_count"] = "9"
    body = {key: value for key, value in tampered.items() if key != "evidence_digest"}
    tampered["evidence_digest"] = canonical_ledger_digest(
        "unified-db-export-evidence-v1",
        body,
    )
    _ = (dest / "evidence.json").write_bytes(canonical_bytes(tampered) + b"\n")
    os.chmod(dest / "evidence.json", 0o400)
    os.chmod(dest, 0o500)
    with pytest.raises(UnifiedDbExportError, match="evidence|digest|count"):
        _ = verify_export_package(str(dest))
    loaded = UnifiedDbExportReceiptV1.from_mapping(load_mapping(dest / "receipt.json"))
    assert loaded.receipt_digest == receipt.receipt_digest


def test_parent_fsync_failure_leaves_verifiable_package(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    exported = profile()

    class Faulty(LocalSnapshotPackageWriter):
        @override
        def _fsync_parent(self, dest: Path) -> None:
            raise OSError("parent fsync failed")

    with pytest.raises(PackageDurabilityUncertain, match="PUBLISHED_DURABILITY_UNCERTAIN"):
        _ = UnifiedDbSnapshotExportService(
            reader=bound_reader(),
            writer=Faulty(),
        ).export_fixture(authority(), exported, plan_for(exported), str(dest))
    assert dest.is_dir()
    leftovers = [path for path in dest.parent.iterdir() if path.name.startswith(".")]
    assert leftovers == []
    verified = verify_export_package(str(dest))
    assert verified.receipt_digest != ""
    with pytest.raises(UnifiedDbExportError, match="overwrite"):
        _ = UnifiedDbSnapshotExportService(
            reader=bound_reader(),
            writer=LocalSnapshotPackageWriter(),
        ).export_fixture(authority(), exported, plan_for(exported), str(dest))


def test_unsupported_platform_publish_does_not_overwrite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "pkg"
    raced = tmp_path / "raced"
    monkeypatch.setattr(sys, "platform", "win32")
    writer = LocalSnapshotPackageWriter()
    staging = writer.start(str(dest))
    writer.write_file(staging, "bounded-snapshot.json", b"{}\n")
    with pytest.raises(UnifiedDbExportError, match="unsupported"):
        writer.commit(staging, str(dest), "receipt.json", b"{}\n", "0" * 64)
    assert not dest.exists()
    assert not Path(staging).exists()
    staging = writer.start(str(raced))
    raced.mkdir()
    marker = raced / "keep"
    _ = marker.write_text("original", encoding="utf-8")
    with pytest.raises(UnifiedDbExportError, match="unsupported|overwrite"):
        writer.commit(staging, str(raced), "receipt.json", b"{}\n", "0" * 64)
    assert marker.read_text(encoding="utf-8") == "original"
    assert not Path(staging).exists()


def test_verify_rejects_mode_tamper(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    os.chmod(dest, 0o700)
    with pytest.raises(UnifiedDbExportError, match="mode"):
        _ = verify_export_package(str(dest))
    os.chmod(dest, 0o500)
    os.chmod(dest / "payload", 0o700)
    with pytest.raises(UnifiedDbExportError, match="mode"):
        _ = verify_export_package(str(dest))
    os.chmod(dest / "payload", 0o500)
    os.chmod(dest / "receipt.json", 0o600)
    with pytest.raises(UnifiedDbExportError, match="mode"):
        _ = verify_export_package(str(dest))
    os.chmod(dest / "receipt.json", 0o400)
    os.chmod(dest / "payload" / "00000000.json", 0o600)
    with pytest.raises(UnifiedDbExportError, match="mode"):
        _ = verify_export_package(str(dest))


def test_fifo_and_oversized_reads_fail_closed_without_blocking(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    _unlock(dest)
    fifo = dest / "opening-proof.json"
    os.chmod(fifo, 0o600)
    fifo.unlink()
    os.mkfifo(fifo)
    os.chmod(fifo, 0o400)
    os.chmod(dest, 0o500)
    with pytest.raises(UnifiedDbExportError):
        _ = verify_export_package(str(dest))
    fixture = tmp_path / "fixture.fifo"
    os.mkfifo(fixture)
    with pytest.raises(UnifiedDbExportError):
        _ = load_export_fixture(fixture)
    huge = tmp_path / "huge.json"
    descriptor = os.open(huge, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        _ = os.lseek(descriptor, 1048576, os.SEEK_SET)
        _ = os.write(descriptor, b"x")
    finally:
        os.close(descriptor)
    with pytest.raises(UnifiedDbExportError, match="1048576|bound|size"):
        _ = load_export_fixture(huge)
