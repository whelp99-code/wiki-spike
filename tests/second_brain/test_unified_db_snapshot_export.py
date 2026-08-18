from __future__ import annotations

import ast
import os
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from tests.second_brain.unified_db_export_support import (
    ALPHA,
    BETA,
    EXPORT_PY,
    authority,
    bound_reader,
    make_fixture,
    plan_for,
    profile,
    proof,
    row,
    standard_rows,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    StaticUnifiedDbFixtureReader,
    UnifiedDbSnapshotExportService,
    verify_export_package,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.snapshot_import import BoundedSnapshotV1
from wiki_spike.memory_core.unified_db_snapshot_export import (
    UnifiedDbExportError,
    UnifiedDbExportRowV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_evidence import (
    UnifiedDbExportEvidenceV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object
from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
    UnifiedDbExportProfileV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)


def _mapping(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def _service(
    rows: tuple[UnifiedDbExportRowV1, ...] | None = None,
) -> UnifiedDbSnapshotExportService:
    chosen = standard_rows() if rows is None else rows
    return UnifiedDbSnapshotExportService(
        reader=bound_reader(chosen),
        writer=LocalSnapshotPackageWriter(),
    )


def test_profile_rejects_unknown_missing_raw_number_and_live_flags() -> None:
    exported = profile()
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbExportProfileV1.from_mapping(exported.to_mapping() | {"extra": "no"})
    missing = exported.to_mapping()
    del missing["operation"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = UnifiedDbExportProfileV1.from_mapping(missing)
    broken: dict[str, object] = dict(exported.to_mapping())
    broken["max_records"] = 2
    with pytest.raises(InvalidContractValue, match="canonical"):
        _ = UnifiedDbExportProfileV1.from_mapping(
            cast(Mapping[str, JsonValue], broken)
        )
    for field in (
        "import_requested",
        "serve_requested",
        "promote_requested",
        "cutover_requested",
    ):
        flagged = exported.to_mapping()
        flagged[field] = True
        with pytest.raises(InvalidContractValue):
            _ = UnifiedDbExportProfileV1.from_mapping(flagged)


def test_fixture_authority_cannot_call_live_export(tmp_path: Path) -> None:
    service = _service()
    token = authority()
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, b"postgresql://localhost:5433/unified")
    os.close(write_fd)
    with pytest.raises(UnifiedDbExportError, match="fixture-only authority cannot call live export"):
        service.export_live(token, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover.startswith(b"postgresql://")
    dest = tmp_path / "live-out"
    with pytest.raises(UnifiedDbExportError, match="executable mapping and signed authority"):
        service.export_live(object(), dsn_fd=None)
    assert not dest.exists()


def test_fixture_export_validates_safety_and_writes_body_free_receipt(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "pkg"
    exported = profile()
    planned = plan_for(exported)
    receipt = _service().export_fixture(authority(), exported, planned, str(dest))
    snapshot = BoundedSnapshotV1.from_mapping(_mapping(dest / "bounded-snapshot.json"))
    discovery = _mapping(dest / "payload-manifest.json")
    evidence = UnifiedDbExportEvidenceV1.from_mapping(_mapping(dest / "evidence.json"))
    loaded = UnifiedDbExportReceiptV1.from_mapping(_mapping(dest / "receipt.json"))
    live = {record.relative_path for record in snapshot.records if record.relative_path}
    raw_entries = discovery["entries"]
    assert isinstance(raw_entries, list)
    live_manifest: set[str] = set()
    for item in raw_entries:
        if isinstance(item, dict):
            relative = item.get("relative_path")
            if isinstance(relative, str):
                live_manifest.add(relative)
    assert live == live_manifest
    assert live == {"00000000.json", "00000001.json"}
    assert (dest / "payload" / "00000000.json").read_bytes() == ALPHA
    assert (dest / "payload" / "00000001.json").read_bytes() == BETA
    assert receipt == loaded
    assert receipt.state == "FIXTURE_EXPORTED_NOT_AUTHORIZED"
    assert receipt.body_reads_in_evidence == "0"
    assert receipt.source_mutation is False
    assert receipt.source_unchanged is True
    assert receipt.import_invoked is False
    assert receipt.serving_promotion is False
    assert receipt.cutover_eligible is False
    assert receipt.plaintext_leaked is False
    assert receipt.native_identity_leaked is False
    assert receipt.live_record_count == "2"
    assert receipt.tombstone_count == "1"
    forbidden = {"body", "native_id", "relative_path", "watermark", "path"}
    assert forbidden.isdisjoint(receipt.to_mapping())
    assert forbidden.isdisjoint(evidence.to_mapping())
    assert evidence.body_reads_in_evidence == "0"
    verified = verify_export_package(str(dest))
    assert verified.package_digest == receipt.package_digest


def test_service_rejects_before_publication_on_mismatch(tmp_path: Path) -> None:
    dest = tmp_path / "bad"
    exported = profile(max_records="1")
    planned = plan_for(exported)
    with pytest.raises(UnifiedDbExportError, match="max_records"):
        _ = _service().export_fixture(authority(), exported, planned, str(dest))
    assert not dest.exists()
    assert not list(tmp_path.glob(".*"))
    writers = proof("OPENING")
    opening = writers.to_mapping()
    opening["writer_count"] = "1"
    from wiki_spike.memory_core.second_brain_ledger_contracts import (
        canonical_ledger_digest,
    )

    body = {key: value for key, value in opening.items() if key != "proof_digest"}
    opening["proof_digest"] = canonical_ledger_digest(
        "unified-db-export-read-safety-proof-v1",
        body,
    )
    from wiki_spike.memory_core.unified_db_snapshot_export_proof import (
        UnifiedDbReadSafetyProofV1,
    )

    fixture = make_fixture()
    dirty = StaticUnifiedDbFixtureReader(
        standard_rows(),
        UnifiedDbReadSafetyProofV1.from_mapping(opening),
        proof("CLOSING"),
        fixture.cursors,
        fixture.fixture_id,
        fixture.fixture_digest,
        fixture.row_set_digest,
    )
    service = UnifiedDbSnapshotExportService(
        reader=dirty,
        writer=LocalSnapshotPackageWriter(),
    )
    with pytest.raises(UnifiedDbExportError, match="writer"):
        _ = service.export_fixture(authority(), profile(), plan_for(profile()), str(tmp_path / "writers"))
    assert not (tmp_path / "writers").exists()


def test_duplicate_identity_and_inferred_absence_fail_closed(tmp_path: Path) -> None:
    exported = profile()
    dup = (row("alpha", ALPHA, "cursor-alpha"), row("alpha", ALPHA, "cursor-other"))
    planned = plan_for(exported, dup)
    with pytest.raises(UnifiedDbExportError, match="unique"):
        _ = _service(dup).export_fixture(authority(), exported, planned, str(tmp_path / "dup"))
    extra = profile(allowlist=("notes", "memories"))
    with pytest.raises(UnifiedDbExportError, match="allowlist"):
        _ = _service().export_fixture(
            authority(),
            extra,
            plan_for(extra),
            str(tmp_path / "allow"),
        )


def test_exporter_modules_have_no_live_or_importer_imports() -> None:
    forbidden = {
        "psycopg",
        "psycopg2",
        "asyncpg",
        "pg8000",
        "socket",
        "http",
        "urllib",
        "requests",
        "wiki_spike.applications.source_import_service",
        "wiki_spike.memory_core.snapshot_import_ports",
    }
    for path in EXPORT_PY:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".")[0] for alias in node.names)
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.add(node.module.split(".")[0])
        assert forbidden.isdisjoint(imported)
        text = path.read_text(encoding="utf-8")
        assert "/Users/jmpark/unified-db/data" not in text
        assert "type: ignore" not in text
        assert "noqa" not in text
