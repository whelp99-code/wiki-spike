from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from tests.second_brain.unified_db_export_support import (
    EVIDENCE,
    SCHEMA_DIR,
    authority,
    bound_reader,
    load_mapping,
    plan_for,
    profile,
    proof,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
    verify_export_package,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def _export(dest: Path) -> None:
    exported = profile()
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(),
        writer=LocalSnapshotPackageWriter(),
    )
    _ = service.export_fixture(authority(), exported, plan_for(exported), str(dest))


def test_package_is_atomic_private_and_receipt_last(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _export(dest)
    assert stat.S_ISDIR(os.lstat(dest).st_mode)
    assert not stat.S_ISLNK(os.lstat(dest).st_mode)
    assert (os.lstat(dest).st_mode & 0o777) == 0o500
    payload = dest / "payload"
    assert (os.lstat(payload).st_mode & 0o777) == 0o500
    for relative in (
        "payload/00000000.json",
        "payload/00000001.json",
        "bounded-snapshot.json",
        "payload-manifest.json",
        "opening-proof.json",
        "closing-proof.json",
        "evidence.json",
        "receipt.json",
    ):
        meta = os.lstat(dest / relative)
        assert stat.S_ISREG(meta.st_mode)
        assert not stat.S_ISLNK(meta.st_mode)
        assert (meta.st_mode & 0o777) == 0o400
    with pytest.raises(OSError):
        _ = (dest / "payload" / "00000000.json").write_bytes(b"x")
    with pytest.raises(OSError):
        _ = (dest / "extra.json").write_text("no", encoding="utf-8")
    with pytest.raises(UnifiedDbExportError, match="overwrite"):
        _export(dest)


def test_verify_rejects_tampered_payload_and_missing_receipt(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _export(dest)
    payload = dest / "payload" / "00000000.json"
    os.chmod(payload, 0o600)
    _ = payload.write_bytes(payload.read_bytes() + b"x")
    os.chmod(payload, 0o400)
    with pytest.raises(UnifiedDbExportError, match="digest|tamper|rehash"):
        _ = verify_export_package(str(dest))
    clean = tmp_path / "clean"
    _export(clean)
    os.chmod(clean, 0o700)
    os.chmod(clean / "receipt.json", 0o600)
    (clean / "receipt.json").unlink()
    with pytest.raises(UnifiedDbExportError):
        _ = verify_export_package(str(clean))


def test_package_digest_is_deterministic_for_same_fixture(tmp_path: Path) -> None:
    first = tmp_path / "a"
    second = tmp_path / "b"
    _export(first)
    _export(second)
    left = load_mapping(first / "receipt.json")
    right = load_mapping(second / "receipt.json")
    assert left["snapshot_digest"] == right["snapshot_digest"]
    assert left["package_digest"] == right["package_digest"]


def test_schemas_and_committed_evidence_are_body_free() -> None:
    exported = profile()
    for name, payload in (
        ("unified-db-export-profile-v1.schema.json", exported.to_mapping()),
        (
            "unified-db-export-plan-v1.schema.json",
            plan_for(exported).to_mapping(),
        ),
        (
            "unified-db-export-proof-v1.schema.json",
            proof("OPENING").to_mapping(),
        ),
    ):
        text = (SCHEMA_DIR / name).read_text(encoding="utf-8")
        assert '"additionalProperties": false' in text
        for key in payload:
            assert f'"{key}"' in text
    evidence = load_mapping(EVIDENCE)
    assert evidence["body_reads_in_evidence"] == "0"
    assert evidence["source_mutation"] is False
    assert evidence["import_invoked"] is False
    assert evidence["serving_promotion"] is False
    assert evidence["cutover_eligible"] is False
    assert evidence["state"] == "FIXTURE_EXPORTED_NOT_AUTHORIZED"
    forbidden = {"body", "native_id", "relative_path", "watermark", "path"}
    assert forbidden.isdisjoint(evidence)
