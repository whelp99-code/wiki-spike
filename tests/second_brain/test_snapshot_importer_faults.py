from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import jsonschema
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.snapshot_importer_support import (
    SQLCIPHER_ARTIFACT,
    digest_of,
    discovery_of,
    import_request,
    import_service,
    persistence_profile,
    persistence_receipt,
    snapshot_from_records,
    snapshot_of,
    verified_persistence,
    write_pair,
)
from wiki_spike.applications.snapshot_import_fs import OpenSourceFile
from wiki_spike.applications.source_import_service import (
    SourceImportError,
    SourceImportService,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import (
    LifecycleDatabase,
    assert_no_plaintext_columns,
)
from wiki_spike.infrastructure.snapshot_import_seal import SealedRecord
from wiki_spike.infrastructure.snapshot_import_store import (
    LifecycleSnapshotImportStore,
    SnapshotImportStoreError,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import UnknownContractField
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.snapshot_import import (
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
    SnapshotRecordV1,
)
from wiki_spike.memory_core.snapshot_import_result import (
    SCOPE_AUTHORITY_NON_AUTHORITATIVE,
    ImportedRecordPayloadV1,
    SnapshotImportReceiptV1,
)
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryEntryV1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
    SourceName,
    path_digest,
)

_SCRIPT = Path("scripts/second_brain_snapshot_import.py")
_SCHEMA_DIR = Path("schemas/second-brain")
_EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/snapshot-import-conformance-v1.json"
)


def _forged_entry(
    root: Path, relative: str, source_name: SourceName = "me-wiki"
) -> SourceDiscoveryEntryV1:
    path = root / relative
    metadata = os.lstat(path)
    entry = SourceDiscoveryEntryV1(
        relative,
        "file",
        str(metadata.st_size),
        str(metadata.st_mtime_ns),
        str(metadata.st_mode),
        "0" * 64,
    )
    return replace(entry, path_digest=path_digest(source_name, entry))


def _forged_discovery(root: Path, relative: str) -> SourceDiscoveryManifestV1:
    request = SourceDiscoveryRequestV1.from_mapping(
        {
            "request_version": SOURCE_DISCOVERY_REQUEST_V1,
            "source_name": "me-wiki",
            "source_root": str(root.resolve()),
        }
    )
    return SourceDiscoveryManifestV1.create(request, (_forged_entry(root, relative),))


def _snapshot_for(root: Path, relative: str, native_id: str, content: bytes) -> BoundedSnapshotV1:
    return snapshot_from_records(
        [
            {
                "native_id": native_id,
                "revision": "1",
                "watermark": "w1",
                "tombstone": False,
                "relative_path": relative,
                "content_digest": digest_of(content),
            }
        ],
        "w1",
    )


def _require_connection(database: LifecycleDatabase) -> sqlite3.Connection:
    connection = database.con
    assert connection is not None
    return connection


def test_contracts_reject_unknown_fields_and_duplicate_identity(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    snapshot = snapshot_of(root)
    with pytest.raises(UnknownContractField):
        payload = import_request(root, digest_of("d"), snapshot).to_mapping()
        payload["unexpected"] = "field"
        _ = SnapshotImportRequestV1.from_mapping(payload)
    with pytest.raises(UnknownContractField):
        extra_snapshot = snapshot.to_mapping()
        extra_snapshot["extra"] = "1"
        _ = BoundedSnapshotV1.from_mapping(extra_snapshot)
    body = snapshot.to_mapping()
    del body["snapshot_digest"]
    raw_records = body["records"]
    assert isinstance(raw_records, list)
    body["records"] = [*raw_records, raw_records[0]]
    with pytest.raises(ValueError, match="duplicate"):
        _ = BoundedSnapshotV1.from_mapping(
            body | {"snapshot_digest": canonical_ledger_digest("bounded-source-snapshot-v1", body)}
        )
    with pytest.raises(ValueError, match="relative_path"):
        escaped: dict[str, JsonValue] = {
            "snapshot_version": "bounded-source-snapshot-v1",
            "source_name": "me-wiki",
            "native_namespace": "second-brain:import:me-wiki",
            "snapshot_watermark": "w",
            "records": [
                {
                    "native_id": "n",
                    "revision": "1",
                    "watermark": "w",
                    "tombstone": False,
                    "relative_path": "../escape.md",
                    "content_digest": "0" * 64,
                }
            ],
            "snapshot_digest": "0" * 64,
        }
        _ = BoundedSnapshotV1.from_mapping(escaped)


def test_import_rejects_deny_class_special_and_symlink_before_cas(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    _ = (root / "id_rsa").write_text("fake", encoding="utf-8")
    service, store, database, cas_root = import_service(tmp_path)
    discovery = _forged_discovery(root, "id_rsa")
    snapshot = _snapshot_for(root, "id_rsa", "secret", b"fake")
    request = import_request(root, discovery.manifest_digest, snapshot)
    with pytest.raises(SourceImportError, match="deny-class"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    assert not any(
        path.is_file() for path in cas_root.rglob("*") if "objects" in path.parts
    )

    fifo_root = tmp_path / "fifo"
    fifo_root.mkdir()
    os.mkfifo(fifo_root / "events.jsonl")
    fifo_discovery = _forged_discovery(fifo_root, "events.jsonl")
    fifo_snapshot = _snapshot_for(fifo_root, "events.jsonl", "fifo", b"")
    fifo_payload = import_request(
        fifo_root, fifo_discovery.manifest_digest, fifo_snapshot
    ).to_mapping()
    fifo_payload["cohort_id"] = "cohort-fifo-001"
    fifo_request = SnapshotImportRequestV1.from_mapping(fifo_payload)
    with pytest.raises(SourceImportError, match="special"):
        _ = service.import_snapshot(
            request=fifo_request, snapshot=fifo_snapshot, discovery=fifo_discovery
        )
    assert store.record_count(fifo_request.cohort_id) == 0

    linked = tmp_path / "linked"
    linked.mkdir()
    write_pair(linked)
    discovery = discovery_of(linked)
    snapshot = snapshot_of(linked)
    linked_payload = import_request(
        linked, discovery.manifest_digest, snapshot
    ).to_mapping()
    linked_payload["cohort_id"] = "cohort-symlink-001"
    request = SnapshotImportRequestV1.from_mapping(linked_payload)
    (linked / "alpha.md").unlink()
    (linked / "alpha.md").symlink_to(tmp_path / "outside.md")
    _ = (tmp_path / "outside.md").write_text("outside", encoding="utf-8")
    with pytest.raises(SourceImportError, match="symlink"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    database.close()


def test_import_rejects_ancestor_symlink_and_second_record_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    notes = root / "notes"
    notes.mkdir(parents=True)
    _ = (notes / "alpha.md").write_text("alpha plaintext", encoding="utf-8")
    _ = (root / "beta.json").write_text('{"beta":"plaintext"}', encoding="utf-8")
    discovery = discovery_of(root)
    snapshot = snapshot_from_records(
        [
            {
                "native_id": "note-alpha",
                "revision": "7",
                "watermark": "watermark-11",
                "tombstone": False,
                "relative_path": "notes/alpha.md",
                "content_digest": digest_of(b"alpha plaintext"),
            },
            {
                "native_id": "note-beta",
                "revision": "3",
                "watermark": "watermark-12",
                "tombstone": False,
                "relative_path": "beta.json",
                "content_digest": digest_of(b'{"beta":"plaintext"}'),
            },
        ],
        "watermark-12",
    )
    service, store, database, _cas = import_service(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    _ = (outside / "alpha.md").write_text("alpha plaintext", encoding="utf-8")
    notes.rename(tmp_path / "moved-notes")
    notes.symlink_to(outside, target_is_directory=True)
    request = import_request(root, discovery.manifest_digest, snapshot)
    with pytest.raises(SourceImportError, match="symlink"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0

    clean = tmp_path / "clean"
    clean.mkdir()
    write_pair(clean)
    discovery = discovery_of(clean)
    snapshot = snapshot_of(clean)
    mutate_payload = import_request(clean, discovery.manifest_digest, snapshot).to_mapping()
    mutate_payload["cohort_id"] = "cohort-mutate-002"
    request = SnapshotImportRequestV1.from_mapping(mutate_payload)
    second_root = tmp_path / "second"
    second_root.mkdir()
    service, store, database2, _cas = import_service(second_root)
    original = service._finish
    state = {"seen": 0}

    def mutate_second(
        record: SnapshotRecordV1,
        entry: SourceDiscoveryEntryV1 | None,
        handle: OpenSourceFile | None,
    ) -> ImportedRecordPayloadV1:
        if state["seen"] == 1:
            _ = (clean / "beta.json").write_text("mutated-during-read", encoding="utf-8")
        state["seen"] += 1
        return original(record, entry, handle)

    monkeypatch.setattr(service, "_finish", mutate_second)
    with pytest.raises(SourceImportError, match="mutation"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    database.close()
    database2.close()


def test_import_rejects_per_file_and_aggregate_bounds(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    database = LifecycleDatabase(tmp_path / "target.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    store = LifecycleSnapshotImportStore(
        database=database,
        cas=cas,
        persistence_profile=verified_persistence(database, cas),
        encryption_key=b"\x13" * 32,
    )
    tiny = SourceImportService(store=store, max_file_bytes=4)
    with pytest.raises(SourceImportError, match="exceeds"):
        _ = tiny.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    modest = SourceImportService(store=store, max_file_bytes=20)
    with pytest.raises(SourceImportError, match="aggregate"):
        _ = modest.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    database.close()


def test_import_rejects_snapshot_omitting_a_discovered_file(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = discovery_of(root)
    snapshot = snapshot_from_records(
        [
            {
                "native_id": "note-alpha",
                "revision": "7",
                "watermark": "watermark-11",
                "tombstone": False,
                "relative_path": "alpha.md",
                "content_digest": digest_of((root / "alpha.md").read_bytes()),
            }
        ],
        "watermark-11",
    )
    request = import_request(root, discovery.manifest_digest, snapshot)
    service, store, database, cas_root = import_service(tmp_path)
    with pytest.raises(SourceImportError, match="skipped reconciliation"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    assert not any(
        path.is_file() for path in cas_root.rglob("*") if "objects" in path.parts
    )
    database.close()


def test_offline_restore_and_mismatch_paths(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    service, store, database, cas_root = import_service(tmp_path)
    receipt = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert receipt.cutover_eligible is False
    assert receipt.scope_authority_state == SCOPE_AUTHORITY_NON_AUTHORITATIVE
    database.close()
    for child in root.iterdir():
        if child.is_file():
            child.unlink()
        else:
            os.rmdir(child)
    root.rmdir()
    database = LifecycleDatabase(tmp_path / "target.sqlite")
    database.initialize()
    cas = EncryptedContentStore(cas_root)
    store = LifecycleSnapshotImportStore(
        database=database,
        cas=cas,
        persistence_profile=verified_persistence(database, cas),
        encryption_key=b"\x13" * 32,
    )
    restored = SourceImportService(store=store, max_file_bytes=1024 * 1024).restore_snapshot(
        request.cohort_id
    )
    assert [record.native_id for record in restored.records] == [
        "note-alpha",
        "note-beta",
        "note-deleted",
    ]
    assert restored.records[0].content == b"alpha plaintext"

    wrong = LifecycleSnapshotImportStore(
        database=database,
        cas=cas,
        persistence_profile=verified_persistence(database, cas),
        encryption_key=b"\x14" * 32,
    )
    with pytest.raises(SnapshotImportStoreError, match="mismatch"):
        _ = wrong.restore_import(request.cohort_id)

    connection = _require_connection(database)
    rows = list(
        connection.execute(
            "SELECT record_sequence, content_ref FROM snapshot_import_record "
            "WHERE cohort_id=? ORDER BY CAST(record_sequence AS INTEGER)",
            (request.cohort_id,),
        )
    )
    first_ref, second_ref = rows[0][1], rows[1][1]
    _ = connection.execute(
        "UPDATE snapshot_import_record SET content_ref=? WHERE cohort_id=? AND record_sequence=?",
        (second_ref, request.cohort_id, rows[0][0]),
    )
    _ = connection.execute(
        "UPDATE snapshot_import_record SET content_ref=? WHERE cohort_id=? AND record_sequence=?",
        (first_ref, request.cohort_id, rows[1][0]),
    )
    with pytest.raises((SnapshotImportStoreError, SourceImportError), match="mismatch"):
        _ = store.restore_import(request.cohort_id)

    _ = connection.execute(
        "UPDATE snapshot_import_cohort SET record_sequence=? WHERE cohort_id=?",
        ("9", request.cohort_id),
    )
    with pytest.raises(SnapshotImportStoreError, match="count"):
        _ = store.restore_import(request.cohort_id)

    blob = cas_root / "objects" / first_ref
    blob.chmod(0o644)
    _ = blob.write_bytes(b"\x00" * 40)
    _ = connection.execute(
        "UPDATE snapshot_import_cohort SET record_sequence=? WHERE cohort_id=?",
        ("3", request.cohort_id),
    )
    _ = connection.execute(
        "UPDATE snapshot_import_record SET content_ref=? WHERE cohort_id=? AND record_sequence=?",
        (first_ref, request.cohort_id, rows[0][0]),
    )
    with pytest.raises(SnapshotImportStoreError, match="mismatch"):
        _ = store.restore_import(request.cohort_id)
    assert_no_plaintext_columns(connection)
    database.close()


def test_retry_exact_match_and_injected_sqlite_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    service, store, database, _cas = import_service(tmp_path)
    original = store._insert

    def boom(
        _connection: sqlite3.Connection,
        _request: SnapshotImportRequestV1,
        _sealed: tuple[SealedRecord, ...],
        _refs: tuple[str, ...],
    ) -> None:
        raise sqlite3.IntegrityError("injected")

    monkeypatch.setattr(store, "_insert", boom)
    with pytest.raises(SnapshotImportStoreError, match="conflicting"):
        _ = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert store.record_count(request.cohort_id) == 0
    monkeypatch.setattr(store, "_insert", original)
    first = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    second = service.import_snapshot(request=request, snapshot=snapshot, discovery=discovery)
    assert first.receipt_digest == second.receipt_digest
    assert store.record_count(request.cohort_id) == 3
    conflict_payload = request.to_mapping()
    conflict_payload["resolved_scope_digest"] = digest_of("other-scope")
    conflict = SnapshotImportRequestV1.from_mapping(conflict_payload)
    with pytest.raises(SnapshotImportStoreError, match="conflicting"):
        _ = service.import_snapshot(request=conflict, snapshot=snapshot, discovery=discovery)
    database.close()


def _cli_profile_files(tmp_path: Path) -> dict[str, Path]:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    receipt = persistence_receipt(profile, owner, approver)
    files = {
        "profile": tmp_path / "profile.json",
        "receipt": tmp_path / "receipt.json",
        "owner": tmp_path / "owner.pub",
        "approver": tmp_path / "approver.pub",
    }
    _ = files["profile"].write_bytes(canonical_bytes(profile.to_mapping()) + b"\n")
    _ = files["receipt"].write_bytes(canonical_bytes(receipt.to_mapping()) + b"\n")
    _ = files["owner"].write_text(owner.public_key().public_bytes_raw().hex(), encoding="ascii")
    _ = files["approver"].write_text(
        approver.public_key().public_bytes_raw().hex(), encoding="ascii"
    )
    return files


def test_cli_help_happy_key_fd_and_rejects_bad_input(tmp_path: Path) -> None:
    help_run = subprocess.run(
        [sys.executable, str(_SCRIPT), "--help"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert help_run.returncode == 0
    assert "--key-fd" in help_run.stdout
    assert "--keychain-service" in help_run.stdout

    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = discovery_of(root)
    snapshot = snapshot_of(root)
    request = import_request(root, discovery.manifest_digest, snapshot)
    files = _cli_profile_files(tmp_path)
    request_path = tmp_path / "request.json"
    snapshot_path = tmp_path / "snapshot.json"
    output_path = tmp_path / "out.json"
    database_path = tmp_path / "target.sqlite"
    cas_root = tmp_path / "cas"
    _ = request_path.write_bytes(canonical_bytes(request.to_mapping()) + b"\n")
    _ = snapshot_path.write_bytes(canonical_bytes(snapshot.to_mapping()) + b"\n")
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, b"\x13" * 32)
    os.close(write_fd)
    completed = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--request",
            str(request_path),
            "--snapshot",
            str(snapshot_path),
            "--database",
            str(database_path),
            "--cas-root",
            str(cas_root),
            "--output",
            str(output_path),
            "--profile",
            str(files["profile"]),
            "--profile-receipt",
            str(files["receipt"]),
            "--owner-public-key",
            str(files["owner"]),
            "--approver-public-key",
            str(files["approver"]),
            "--sqlcipher-artifact",
            str(SQLCIPHER_ARTIFACT),
            "--key-fd",
            str(read_fd),
        ],
        capture_output=True,
        check=False,
        pass_fds=(read_fd,),
    )
    os.close(read_fd)
    assert completed.returncode == 0, completed.stderr.decode()
    receipt = SnapshotImportReceiptV1.from_mapping(json.loads(output_path.read_text()))
    assert receipt.state == "READY_NON_SERVING"
    assert receipt.cutover_eligible is False
    assert completed.stdout == output_path.read_bytes()

    bad_output = tmp_path / "bad.json"
    _ = (root / "private.key").write_text("secret", encoding="utf-8")
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, b"\x13" * 32)
    os.close(write_fd)
    refused = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--request",
            str(request_path),
            "--snapshot",
            str(snapshot_path),
            "--database",
            str(tmp_path / "bad.sqlite"),
            "--cas-root",
            str(tmp_path / "bad-cas"),
            "--output",
            str(bad_output),
            "--profile",
            str(files["profile"]),
            "--profile-receipt",
            str(files["receipt"]),
            "--owner-public-key",
            str(files["owner"]),
            "--approver-public-key",
            str(files["approver"]),
            "--sqlcipher-artifact",
            str(SQLCIPHER_ARTIFACT),
            "--key-fd",
            str(read_fd),
        ],
        capture_output=True,
        check=False,
        pass_fds=(read_fd,),
    )
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"deny-class" in refused.stderr
    assert not bad_output.exists()
    assert not (tmp_path / "bad.sqlite").exists()


def test_schemas_and_body_free_evidence(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    snapshot = snapshot_of(root)
    request = import_request(root, digest_of("discovery"), snapshot)
    for name, payload in (
        ("bounded-snapshot-v1.schema.json", snapshot.to_mapping()),
        ("snapshot-import-request-v1.schema.json", request.to_mapping()),
    ):
        schema = json.loads((_SCHEMA_DIR / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator(schema).validate(payload)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(payload | {"extra": "no"})
    receipt_schema = json.loads(
        (_SCHEMA_DIR / "snapshot-import-receipt-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(receipt_schema)
    evidence = json.loads(_EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["body_reads_in_evidence"] == "0"
    assert evidence["cutover_eligible"] is False
    assert evidence["serving_promotion"] is False
    assert evidence["plaintext_persisted"] is False
    assert evidence["skipped_reconciliation"] is False
    forbidden = {"body", "plaintext", "content", "native_id", "relative_path"}
    assert forbidden.isdisjoint(evidence)
