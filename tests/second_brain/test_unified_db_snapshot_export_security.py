from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import override

import jsonschema
import pytest

from tests.second_brain.unified_db_export_support import (
    ALPHA,
    BETA,
    EVIDENCE,
    GONE,
    SCHEMA_DIR,
    authority,
    bound_reader,
    load_mapping,
    plan_for,
    profile,
    proof,
    row,
    standard_rows,
)
from wiki_spike.applications.unified_db_snapshot_export_handoff import (
    bridge_snapshot_import_handoff,
)
from wiki_spike.applications.unified_db_snapshot_export_service import (
    UnifiedDbSnapshotExportService,
    verify_export_package,
)
from wiki_spike.infrastructure.local_snapshot_package_writer import (
    LocalSnapshotPackageWriter,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.snapshot_import import BoundedSnapshotV1
from wiki_spike.memory_core.unified_db_snapshot_export import (
    UnifiedDbExportError,
    UnifiedDbExportRowV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_bind import bind_native_id
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object
from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
    UnifiedDbExportProfileV1,
)


def _validate_schema(path: Path, instance: Mapping[str, JsonValue]) -> None:
    schema = decode_json_object(path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=dict(instance), schema=schema)


def _export(
    dest: Path,
    rows: tuple[UnifiedDbExportRowV1, ...] | None = None,
    exported: UnifiedDbExportProfileV1 | None = None,
) -> object:
    chosen = standard_rows() if rows is None else rows
    exported = profile() if exported is None else exported
    return UnifiedDbSnapshotExportService(
        reader=bound_reader(chosen),
        writer=LocalSnapshotPackageWriter(),
    ).export_fixture(authority(), exported, plan_for(exported, chosen), str(dest))


def test_payload_manifest_is_package_relative_and_bytes_are_deterministic(
    tmp_path: Path,
) -> None:
    first = tmp_path / "a" / "pkg"
    second = tmp_path / "b" / "pkg"
    first.parent.mkdir()
    second.parent.mkdir()
    _ = _export(first)
    _ = _export(second)
    assert not (first / "discovery-manifest.json").exists()
    manifest = load_mapping(first / "payload-manifest.json")
    assert "source_root" not in manifest
    assert "mtime_ns" not in str(manifest)
    assert "mode" not in str(manifest)
    names = sorted(path.relative_to(first).as_posix() for path in first.rglob("*") if path.is_file())
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes()
    receipt = load_mapping(first / "receipt.json")
    assert "payload_manifest_digest" in receipt
    assert "discovery_manifest_digest" not in receipt
    assert "cursor_map_digest" in receipt


def test_stable_identity_ignores_content_and_rejects_duplicates(tmp_path: Path) -> None:
    first_id = bind_native_id("notes", "alpha")
    second_id = bind_native_id("notes", "alpha")
    assert first_id == second_id
    dest = tmp_path / "pkg"
    receipt = _export(
        dest,
        rows=(
            row("alpha", b"v1", "w1", revision="1"),
            row("beta", BETA, "w2", revision="9"),
        ),
    )
    snapshot = BoundedSnapshotV1.from_mapping(load_mapping(dest / "bounded-snapshot.json"))
    assert snapshot.records[0].native_id == first_id
    later = tmp_path / "later"
    _ = _export(
        later,
        rows=(
            row("alpha", b"changed", "w9", revision="2"),
            row("beta", BETA, "w2", revision="9"),
        ),
    )
    later_snap = BoundedSnapshotV1.from_mapping(load_mapping(later / "bounded-snapshot.json"))
    assert later_snap.records[0].native_id == first_id
    assert later_snap.records[0].revision == "2"
    assert later_snap.records[0].content_digest != snapshot.records[0].content_digest
    with pytest.raises(UnifiedDbExportError, match="unique|identity"):
        _ = _export(
            tmp_path / "dup",
            rows=(
                row("alpha", ALPHA, "w1", revision="1"),
                row("alpha", b"other", "w2", revision="2"),
            ),
        )
    _ = receipt


def test_explicit_cursor_map_not_lexicographic_max(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    receipt = load_mapping(dest / "receipt.json")
    evidence = load_mapping(dest / "evidence.json")
    assert receipt["cursor_map_digest"] == evidence["cursor_map_digest"]
    assert "cursor-alpha" not in str(receipt)
    assert "cursor-gone" not in str(receipt)


def test_plan_rejects_substituted_fixture_rows(tmp_path: Path) -> None:
    exported = profile()
    planned = plan_for(exported)
    other = (
        row("alpha", ALPHA, "cursor-alpha"),
        row("beta", b"substituted", "cursor-beta"),
        row("gone", GONE, "cursor-gone", tombstone=True),
    )
    service = UnifiedDbSnapshotExportService(
        reader=bound_reader(other),
        writer=LocalSnapshotPackageWriter(),
    )
    with pytest.raises(UnifiedDbExportError, match="fixture"):
        _ = service.export_fixture(authority(), exported, planned, str(tmp_path / "bad"))


def test_aggregate_bound_is_independent_of_record_bound(tmp_path: Path) -> None:
    rows = standard_rows()
    from wiki_spike.memory_core.unified_db_snapshot_export_bounds import (
        aggregate_export_bytes,
    )

    exact = str(aggregate_export_bytes(rows))
    exported = profile(max_record_bytes="1048576", max_aggregate_bytes=exact)
    _ = _export(tmp_path / "exact", rows=rows, exported=exported)
    plus = profile(max_record_bytes="1048576", max_aggregate_bytes=str(int(exact) - 1))
    with pytest.raises(UnifiedDbExportError, match="aggregate"):
        _ = _export(tmp_path / "plus", rows=rows, exported=plus)


def test_bridge_fresh_discovery_not_stale_persisted_manifest(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    handoff = bridge_snapshot_import_handoff(
        str(dest),
        cohort_id="cohort-unified-db-001",
        resolved_scope_digest="a" * 64,
    )
    assert handoff.discovery.source_root == str((dest / "payload").resolve())
    assert handoff.snapshot.snapshot_digest == handoff.request.snapshot_digest
    assert handoff.request.discovery_manifest_digest == handoff.discovery.manifest_digest
    assert not (dest / "discovery-manifest.json").exists()


def test_verify_rejects_metadata_symlink_and_unlisted_root(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    os.chmod(dest, 0o700)
    target = dest / "receipt.json"
    os.chmod(target, 0o600)
    backup = tmp_path / "receipt.bak"
    _ = target.rename(backup)
    target.symlink_to(backup)
    os.chmod(dest, 0o500)
    with pytest.raises(UnifiedDbExportError, match="symlink"):
        _ = verify_export_package(str(dest))
    os.chmod(dest, 0o700)
    os.unlink(target)
    _ = backup.rename(target)
    os.chmod(target, 0o400)
    extra = dest / "discovery-manifest.json"
    _ = extra.write_text("{}", encoding="utf-8")
    os.chmod(extra, 0o400)
    os.chmod(dest, 0o500)
    with pytest.raises(UnifiedDbExportError, match="unlisted|allowlist|extra"):
        _ = verify_export_package(str(dest))


def test_schemas_use_draft_2020_12(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"
    _ = _export(dest)
    pairs = (
        ("unified-db-export-profile-v1.schema.json", profile().to_mapping()),
        ("unified-db-export-plan-v1.schema.json", plan_for(profile()).to_mapping()),
        ("unified-db-export-proof-v1.schema.json", proof("OPENING").to_mapping()),
        ("unified-db-export-receipt-v1.schema.json", load_mapping(dest / "receipt.json")),
        ("unified-db-export-evidence-v1.schema.json", load_mapping(dest / "evidence.json")),
        (
            "unified-db-export-payload-manifest-v1.schema.json",
            load_mapping(dest / "payload-manifest.json"),
        ),
        ("unified-db-export-conformance-v1.schema.json", load_mapping(EVIDENCE)),
    )
    for name, payload in pairs:
        _validate_schema(SCHEMA_DIR / name, payload)
        with pytest.raises(jsonschema.ValidationError):
            _validate_schema(SCHEMA_DIR / name, dict(payload) | {"extra": "no"})


def test_record_bound_plus_one_and_huge_tombstone_identity(tmp_path: Path) -> None:
    live = row("alpha", b"abcd", "w1", revision="1")
    exported = profile(max_record_bytes="4", max_aggregate_bytes="1048576")
    _ = _export(tmp_path / "exact-body", rows=(live,), exported=exported)
    huge = row("alpha", b"abcde", "w1", revision="1")
    with pytest.raises(UnifiedDbExportError, match="per-record"):
        _ = _export(tmp_path / "body-plus", rows=(huge,), exported=exported)
    tomb = row("alpha", b"x" * 200, "w" * 200, tombstone=True, revision="1")
    tight = profile(max_record_bytes="1", max_aggregate_bytes="200")
    with pytest.raises(UnifiedDbExportError, match="aggregate"):
        _ = _export(tmp_path / "tomb", rows=(tomb,), exported=tight)


def test_writer_faults_leave_no_package_or_staging(tmp_path: Path) -> None:
    dest = tmp_path / "pkg"

    class Faulty(LocalSnapshotPackageWriter):
        @override
        def _exclusive_rename(self, source: str, destination: str) -> None:
            raise OSError("rename failed")

    exported = profile()
    with pytest.raises(UnifiedDbExportError):
        _ = UnifiedDbSnapshotExportService(
            reader=bound_reader(),
            writer=Faulty(),
        ).export_fixture(authority(), exported, plan_for(exported), str(dest))
    assert not dest.exists()
    leftovers = [path for path in dest.parent.iterdir() if path.name.startswith(".")]
    assert leftovers == []
