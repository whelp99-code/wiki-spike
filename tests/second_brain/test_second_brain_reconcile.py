from __future__ import annotations

import copy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

import pytest

from test_stage3_ledger_persistence import (
    create_and_approve as stage3_create_and_approve,
    ref as stage3_ref,
    request as stage3_request,
    sign as stage3_sign,
    store as stage3_store,
    trust_for_request as stage3_trust_for_request,
)

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_cutover import (
    COHORT_MANIFEST_V1,
    MigrationCohortManifestV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core import second_brain_ledger_contracts as ledger_contracts
from wiki_spike.memory_core.second_brain_ledger_ports import (
    AtomicRecallSnapshotPort,
    ReconciliationCoverageV1,
    ReconciliationFindingV1,
    ReconciliationRequestV1,
    ReconciliationResultV1,
    ReconciliationVerifierPort,
)


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "second_brain_reconcile.py"
SPEC = importlib.util.spec_from_file_location("second_brain_reconcile_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
reconcile = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reconcile
SPEC.loader.exec_module(reconcile)


def _write_json(path: Path, data: dict[str, object]) -> str:
    raw = canonical_bytes(data)
    path.write_bytes(raw)
    return sha256(raw).hexdigest()


def _manifest(*, workspace_ref: str, sources: list[str], state: str) -> dict[str, object]:
    body: dict[str, object] = {
        "manifest_version": COHORT_MANIFEST_V1,
        "workspace_ref": workspace_ref,
        "cohort_state": state,
        "source_names": sources,
        "resolved_scope_digest": "3" * 64,
        "source_manifest_digest": "4" * 64,
    }
    return body | {
        "manifest_digest": canonical_ledger_digest("migration-cohort-manifest-v1", body)
    }


def _record() -> dict[str, object]:
    return {
        "native_id": "record-a",
        "revision": "1",
        "payload_sha256": "a" * 64,
        "tombstone": False,
        "dedupe_root_ref": "record-a",
        "citation": {"citation_ref": "citation:record-a", "citation_sha256": "b" * 64},
    }


def make_artifacts(tmp_path: Path) -> dict[str, object]:
    source_root = tmp_path / "source"
    backup_root = tmp_path / "backup"
    inputs = tmp_path / "inputs"
    source_root.mkdir()
    (backup_root / "objects").mkdir(parents=True)
    inputs.mkdir()
    payload = b"backup payload"
    backup_file = backup_root / "objects" / "record-a.bin"
    backup_file.write_bytes(payload)

    source = {
        "inventory_version": reconcile.SOURCE_INVENTORY_V1,
        "source_ref": "unified-db",
        "source_root": str(source_root),
        "records": [_record()],
    }
    cohort_record = copy.deepcopy(_record()) | {
        "disposition": "ACCEPTED",
        "reason_code": None,
    }
    workspace_ref = "workspace:" + "c" * 64
    cohort = {
        "inventory_version": reconcile.COHORT_INVENTORY_V1,
        "source_ref": "unified-db",
        "workspace_ref": workspace_ref,
        "records": [cohort_record],
    }
    manifest = _manifest(workspace_ref=workspace_ref, sources=["unified-db"], state="READY_NON_SERVING")

    source_path = inputs / "source.json"
    cohort_path = inputs / "cohort.json"
    manifest_path = inputs / "cohort-manifest.json"
    source_digest = _write_json(source_path, source)
    cohort_digest = _write_json(cohort_path, cohort)
    manifest_digest = _write_json(manifest_path, manifest)
    backup = {
        "backup_manifest_version": reconcile.BACKUP_MANIFEST_V1,
        "source_inventory_digest": source_digest,
        "cohort_inventory_digest": cohort_digest,
        "cohort_manifest_digest": manifest_digest,
        "backup_root": str(backup_root),
        "files": [
            {
                "relative_path": "objects/record-a.bin",
                "size": str(len(payload)),
                "sha256": sha256(payload).hexdigest(),
            }
        ],
    }
    backup_path = inputs / "backup-manifest.json"
    _write_json(backup_path, backup)
    return {
        "source_root": source_root,
        "backup_root": backup_root,
        "backup_file": backup_file,
        "source": source,
        "cohort": cohort,
        "manifest": manifest,
        "backup": backup,
        "source_path": source_path,
        "cohort_path": cohort_path,
        "manifest_path": manifest_path,
        "backup_path": backup_path,
        "source_digest": source_digest,
        "cohort_digest": cohort_digest,
        "manifest_file_digest": manifest_digest,
    }


def _validated(artifacts: dict[str, object]):
    source, source_digest = reconcile.load_source_inventory_document(artifacts["source_path"])
    cohort, cohort_digest = reconcile.load_cohort_inventory_document(artifacts["cohort_path"])
    reconcile.validate_inventory_conservation(source, cohort)
    binding = reconcile.parse_and_bind_cohort_manifest(artifacts["manifest_path"], cohort)
    backup, backup_digest = reconcile.load_backup_manifest_document(
        artifacts["backup_path"],
        source_inventory_digest=source_digest,
        cohort_inventory_digest=cohort_digest,
        cohort_manifest_digest=binding.canonical_file_digest,
    )
    return source, cohort, binding, backup, backup_digest


def test_slice_a_validates_closed_inventories_manifest_binding_and_exact_backup(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    source, cohort, binding, backup, backup_digest = _validated(artifacts)

    assert source.to_mapping() == artifacts["source"]
    assert cohort.to_mapping() == artifacts["cohort"]
    assert binding.canonical_file_digest == artifacts["manifest_file_digest"]
    assert binding.manifest_digest == artifacts["manifest"]["manifest_digest"]
    assert isinstance(binding.manifest, MigrationCohortManifestV1)
    assert backup_digest == sha256(canonical_bytes(artifacts["backup"])).hexdigest()
    assert reconcile.verify_backup_inventory(
        backup,
        source,
        input_paths=(
            artifacts["source_path"],
            artifacts["cohort_path"],
            artifacts["manifest_path"],
            artifacts["backup_path"],
        ),
    ) == backup.files

    all_documents = reconcile.validate_slice_a_documents(
        source_inventory_path=artifacts["source_path"],
        cohort_inventory_path=artifacts["cohort_path"],
        cohort_manifest_path=artifacts["manifest_path"],
        backup_manifest_path=artifacts["backup_path"],
        restore_path=str(tmp_path / "restore"),
        output_path=str(tmp_path / "output.json"),
    )
    assert all_documents[2] == binding


def test_source_and_cohort_schema_roles_are_closed_and_distinct(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    source = copy.deepcopy(artifacts["source"])
    cohort = copy.deepcopy(artifacts["cohort"])
    source["records"][0]["disposition"] = "ACCEPTED"
    with pytest.raises(reconcile.ReconciliationError, match="fields are wrong"):
        reconcile.validate_source_inventory(source)

    cohort["records"][0]["reason_code"] = "PAYLOAD_MISMATCH"
    with pytest.raises(reconcile.ReconciliationError, match="must be null"):
        reconcile.validate_cohort_inventory(cohort)


def test_reconciliation_dtos_are_hash_only_immutable_and_fail_closed() -> None:
    request = ReconciliationRequestV1(
        "second-brain-reconcile-v1", "a" * 64, "b" * 64, "c" * 64, "d" * 64
    )
    coverage = ReconciliationCoverageV1("2", "2", "1", "1")
    finding = ReconciliationFindingV1("PAYLOAD_MISMATCH", "e" * 64)

    assert request.source_inventory_digest == "a" * 64
    assert not hasattr(finding, "evidence_id")
    assert ReconciliationResultV1("PASS", False, False, ReconciliationCoverageV1("0", "0", "0", "0"), ())
    assert ReconciliationResultV1("QUARANTINED", True, False, coverage, (finding,))
    assert issubclass(ReconciliationVerifierPort, AtomicRecallSnapshotPort)
    with pytest.raises(ValueError, match="contradictory"):
        ReconciliationResultV1("PASS", True, False, coverage, ())


def test_slice_b_conserves_closed_evidence_to_a_hash_only_non_live_receipt(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    source, cohort, _, _, _ = _validated(artifacts)

    result, aggregates = reconcile.reconcile_inventory_conservation(source, cohort)
    repeated_result, repeated_aggregates = reconcile.reconcile_inventory_conservation(source, cohort)
    assert result.result == "PASS"
    assert result.no_import is False
    assert result.live_operation_authorized is False
    assert result.coverage == ReconciliationCoverageV1("1", "1", "1", "0")
    assert len(aggregates.to_mapping()) == 7
    assert all(len(value) == 64 for value in aggregates.to_mapping().values())
    assert repeated_result == result
    assert repeated_aggregates.to_mapping() == aggregates.to_mapping()

    output = tmp_path / "slice-b-receipt.json"
    receipt = reconcile.conserve_documents(
        source_inventory_path=artifacts["source_path"],
        cohort_inventory_path=artifacts["cohort_path"],
        cohort_manifest_path=artifacts["manifest_path"],
        backup_manifest_path=artifacts["backup_path"],
        output_path=output,
    )
    assert output.read_bytes() == canonical_bytes(receipt)
    assert reconcile.validate_reconciliation_receipt(receipt).to_mapping() == receipt
    assert receipt["receipt_sha256"] == sha256(
        canonical_bytes({key: value for key, value in receipt.items() if key != "receipt_sha256"})
    ).hexdigest()
    assert receipt["result"]["live_operation_authorized"] is False
    assert receipt["verification_mode"] == reconcile.CONSERVATION_ONLY
    assert receipt["recall_sample_digest"] is None
    assert receipt["isolated_restore_target_digest"] is None
    assert receipt["deterministic_recall_digest"] is None
    assert receipt["result"]["coverage"] == {
        "source_total": "1",
        "cohort_total": "1",
        "accepted_total": "1",
        "quarantined_total": "0",
    }
    rendered = output.read_text()
    assert canonical_bytes(receipt) == canonical_bytes(
        reconcile.reconciliation_receipt_mapping(
            reconcile.ReconciliationRequestV1(
                reconcile.RECONCILIATION_VERIFIER_V1,
                artifacts["source_digest"],
                artifacts["cohort_digest"],
                artifacts["manifest_file_digest"],
                sha256(canonical_bytes(artifacts["backup"])).hexdigest(),
            ),
            repeated_result,
            repeated_aggregates,
        )
    )
    raw_values = (
        str(artifacts["source_root"]),
        source.records[0].native_id,
        source.records[0].dedupe_root_ref,
        source.records[0].citation.citation_ref,
        source.records[0].citation.citation_sha256,
        source.records[0].payload_sha256,
    )
    assert all(value not in rendered for value in raw_values)


def test_authorized_verify_restores_and_binds_two_cited_recall_acquisitions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    artifacts = make_artifacts(tmp_path)
    stage3_root = tmp_path / "stage3"
    stage3_root.mkdir()
    database, cas, service, workspace = stage3_store(stage3_root)
    candidate = stage3_ref("candidate", "reconcile")
    stage3_create_and_approve(service, cas, candidate, "reconcile", workspace=workspace)
    request = stage3_request(workspace)

    cohort = copy.deepcopy(artifacts["cohort"])
    cohort["workspace_ref"] = workspace
    manifest = _manifest(workspace_ref=workspace, sources=["unified-db"], state="READY_NON_SERVING")
    _write_json(artifacts["cohort_path"], cohort)
    manifest_digest = _write_json(artifacts["manifest_path"], manifest)
    backup = copy.deepcopy(artifacts["backup"])
    backup["cohort_inventory_digest"] = sha256(canonical_bytes(cohort)).hexdigest()
    backup["cohort_manifest_digest"] = manifest_digest
    _write_json(artifacts["backup_path"], backup)

    sample_path = tmp_path / "recall-sample.json"
    _write_json(sample_path, {
        "recall_sample_version": reconcile.RECALL_SAMPLE_V1,
        "requests": [request.to_mapping()],
    })
    target = tmp_path / "isolated-restore"
    receipt = tmp_path / "receipt.json"

    class TypedPort:
        calls = 0

        def acquire_recall_snapshot(self, value):
            assert target.is_dir()
            assert (target / "objects" / "record-a.bin").read_bytes() == b"backup payload"
            assert sha256((target / "objects" / "record-a.bin").read_bytes()).hexdigest() == backup["files"][0]["sha256"]
            self.calls += 1
            return service.acquire(value)

    port = TypedPort()
    argv = [
        "verify", "--source-inventory", str(artifacts["source_path"]),
        "--cohort-inventory", str(artifacts["cohort_path"]),
        "--cohort-manifest", str(artifacts["manifest_path"]),
        "--backup-manifest", str(artifacts["backup_path"]),
        "--restore-target", str(target), "--recall-sample", str(sample_path),
        "--receipt", str(receipt),
    ]
    original_unlink = reconcile.os.unlink

    def fail_private_temp_cleanup(path, *args, **kwargs):
        if Path(path).name.startswith(".receipt.json."):
            raise OSError("injected private temporary cleanup failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(reconcile.os, "unlink", fail_private_temp_cleanup)
    assert reconcile.run_with_authority(
        argv, trust_authority=stage3_trust_for_request(request), recall_snapshots=port
    ) == 0
    assert port.calls == 2
    assert (target / "objects" / "record-a.bin").read_bytes() == b"backup payload"
    assert receipt.exists() and target.exists()
    document = json.loads(receipt.read_text())
    assert document["verification_mode"] == reconcile.RESTORE_RECALL_VERIFIED
    assert all(len(document[field]) == 64 for field in (
        "recall_sample_digest", "isolated_restore_target_digest", "deterministic_recall_digest",
    ))
    assert reconcile.validate_reconciliation_receipt(document).to_mapping() == document
    forged_target = tmp_path / "forged-authority-restore"
    forged_receipt = tmp_path / "forged-authority-receipt.json"
    forged_argv = argv[:-2] + ["--receipt", str(forged_receipt)]
    forged_argv[forged_argv.index("--restore-target") + 1] = str(forged_target)
    assert reconcile.run_with_authority(
        forged_argv,
        trust_authority=object.__new__(reconcile.RecallTrustAuthorityV2),
        recall_snapshots=port,
    ) == 2
    assert not forged_target.exists() and not forged_receipt.exists()
    non_port_target = tmp_path / "non-port-restore"
    non_port_receipt = tmp_path / "non-port-receipt.json"
    non_port_argv = argv[:-2] + ["--receipt", str(non_port_receipt)]
    non_port_argv[non_port_argv.index("--restore-target") + 1] = str(non_port_target)
    assert reconcile.run_with_authority(
        non_port_argv, trust_authority=stage3_trust_for_request(request), recall_snapshots=object()  # type: ignore[arg-type]
    ) == 2
    assert not non_port_target.exists() and not non_port_receipt.exists()

    def with_outputs(restore: Path | str, output: Path) -> list[str]:
        changed = argv[:-2] + ["--receipt", str(output)]
        changed[changed.index("--restore-target") + 1] = str(restore)
        return changed

    preexisting = tmp_path / "preexisting-restore"
    preexisting.mkdir()
    source_inside = artifacts["source_root"] / "restore-inside-source"
    backup_inside = artifacts["backup_root"] / "restore-inside-backup"
    symlink_target = tmp_path / "symlink-restore"
    symlink_target.symlink_to(tmp_path, target_is_directory=True)
    alias_target = str(tmp_path / "alias-parent" / ".." / "alias-restore")
    for restore in (preexisting, source_inside, backup_inside, symlink_target, alias_target):
        blocked_receipt = tmp_path / f"blocked-{len(str(restore))}.json"
        calls_before = port.calls
        assert reconcile.run_with_authority(
            with_outputs(restore, blocked_receipt),
            trust_authority=stage3_trust_for_request(request), recall_snapshots=port,
        ) == 2
        assert port.calls == calls_before and not blocked_receipt.exists()
    collision_receipt = tmp_path / "receipt-collision.json"
    collision_receipt.write_bytes(b"preexisting")
    calls_before = port.calls
    collision_target = tmp_path / "receipt-collision-restore"
    assert reconcile.run_with_authority(
        with_outputs(collision_target, collision_receipt),
        trust_authority=stage3_trust_for_request(request), recall_snapshots=port,
    ) == 2
    assert port.calls == calls_before and not collision_target.exists()
    assert collision_receipt.read_bytes() == b"preexisting"

    quarantined = copy.deepcopy(cohort)
    quarantined["records"][0]["disposition"] = "QUARANTINED"
    quarantined["records"][0]["reason_code"] = "PAYLOAD_MISMATCH"
    _write_json(artifacts["cohort_path"], quarantined)
    quarantined_backup = copy.deepcopy(backup)
    quarantined_backup["cohort_inventory_digest"] = sha256(canonical_bytes(quarantined)).hexdigest()
    _write_json(artifacts["backup_path"], quarantined_backup)
    quarantine_target = tmp_path / "quarantine-restore"
    quarantine_receipt = tmp_path / "quarantine-receipt.json"
    calls_before = port.calls
    assert reconcile.run_with_authority(
        with_outputs(quarantine_target, quarantine_receipt),
        trust_authority=stage3_trust_for_request(request), recall_snapshots=port,
    ) == 2
    assert port.calls == calls_before
    assert not quarantine_target.exists() and not quarantine_receipt.exists()

    _write_json(artifacts["cohort_path"], cohort)
    _write_json(artifacts["backup_path"], backup)

    class SecretPort:
        def acquire_recall_snapshot(self, value):
            raise RuntimeError("SECOND_BRAIN_SECRET_MARKER_SHOULD_NOT_ESCAPE")

    secret_target = tmp_path / "secret-failure-restore"
    secret_receipt = tmp_path / "secret-failure-receipt.json"
    secret_argv = argv[:-2] + ["--receipt", str(secret_receipt)]
    secret_argv[secret_argv.index("--restore-target") + 1] = str(secret_target)
    assert reconcile.run_with_authority(
        secret_argv, trust_authority=stage3_trust_for_request(request), recall_snapshots=SecretPort()
    ) == 2
    captured = capsys.readouterr()
    assert "SECOND_BRAIN_SECRET_MARKER_SHOULD_NOT_ESCAPE" not in captured.out + captured.err
    assert "AUTHORIZED_VERIFY_REJECTED" in captured.err
    assert not secret_target.exists() and not secret_receipt.exists()

    def hostile_wrapper(wrapper_request, snapshot):
        wrapper = object.__new__(reconcile.ValidatedRecallSnapshotAcquisitionV2)
        object.__setattr__(wrapper, "_request", wrapper_request)
        object.__setattr__(wrapper, "_snapshot", snapshot)
        return wrapper

    def port_failure(
        name: str, values: list[object], *, expected_calls: int, authority=None
    ) -> None:
        failure_target = tmp_path / f"{name}-restore"
        failure_receipt = tmp_path / f"{name}-receipt.json"

        class RestoreBoundHostilePort:
            calls = 0

            def acquire_recall_snapshot(self, value):
                assert failure_target.is_dir()
                assert (failure_target / "objects" / "record-a.bin").read_bytes() == b"backup payload"
                self.calls += 1
                return values[self.calls - 1]

        hostile_port = RestoreBoundHostilePort()
        assert reconcile.run_with_authority(
            with_outputs(failure_target, failure_receipt),
            trust_authority=authority or stage3_trust_for_request(request),
            recall_snapshots=hostile_port,
        ) == 2
        assert hostile_port.calls == expected_calls
        assert not failure_target.exists() and not failure_receipt.exists()

    valid_snapshot = service.acquire(request).snapshot
    # A raw snapshot is never a port acquisition wrapper, but the port observes
    # the restored bytes before the seam rejects it and rolls the target back.
    port_failure("raw-snapshot", [valid_snapshot], expected_calls=1)
    mismatched_request = stage3_request(workspace, transaction_cut="2")
    assert mismatched_request != request
    port_failure(
        "request-mismatch", [hostile_wrapper(mismatched_request, valid_snapshot)], expected_calls=1
    )

    def signed_snapshot_variant(*, projection: str | None = None, empty: bool = False):
        body = valid_snapshot.to_mapping()
        if empty:
            body["candidates"] = []
            body["citations"] = []
            body["conflicts"] = []
            body["unverified_conflicts"] = []
        if projection is not None:
            body["projection_digest"] = projection
        for field in (
            "snapshot_digest", "authority_commitment_digest", "pagination_commitment_digest",
            "selected_candidates_digest", "selected_citations_digest", "selected_conflicts_digest",
        ):
            del body[field]
        unsigned = ledger_contracts.make_recall_snapshot_v2(body)
        signed = unsigned.to_mapping()
        signed["snapshot_signature"] = stage3_sign(
            ledger_contracts.canonical_ledger_bytes(
                "snapshot-attestation-v2",
                {key: value for key, value in signed.items() if key not in {"snapshot_signature", "continuation"}},
            )
        )
        return ledger_contracts.RecallServeSnapshotV2.from_mapping(signed)

    alternate = signed_snapshot_variant(projection="e" * 64)
    first = reconcile.ValidatedRecallSnapshotAcquisitionV2(
        request, valid_snapshot, stage3_trust_for_request(request)
    )
    second = reconcile.ValidatedRecallSnapshotAcquisitionV2(
        request, alternate, stage3_trust_for_request(request)
    )
    port_failure("alternating-snapshots", [first, second], expected_calls=2)
    empty_snapshot = signed_snapshot_variant(empty=True)
    port_failure(
        "empty-snapshot",
        [reconcile.ValidatedRecallSnapshotAcquisitionV2(request, empty_snapshot, stage3_trust_for_request(request))],
        expected_calls=1,
    )
    uncited = signed_snapshot_variant()
    object.__setattr__(uncited, "citations", ())
    port_failure("uncited-tampered", [hostile_wrapper(request, uncited)], expected_calls=1)
    stale_authority = stage3_trust_for_request(request)
    object.__setattr__(stale_authority, "_RecallTrustAuthorityV2__clock", lambda: "2026-02-01T00:00:00Z")
    port_failure("stale-provenance", [first], expected_calls=1, authority=stale_authority)

    backup_bytes = (artifacts["backup_root"] / "objects" / "record-a.bin").read_bytes()
    original_fsync = reconcile.os.fsync
    original_directory_fsync = reconcile._fsync_directory
    file_fsync_target = tmp_path / "file-fsync-restore"
    file_fsync_receipt = tmp_path / "file-fsync-receipt.json"
    monkeypatch.setattr(reconcile, "_fsync_directory", lambda _: None)
    monkeypatch.setattr(reconcile.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("file fsync")))
    assert reconcile.run_with_authority(
        with_outputs(file_fsync_target, file_fsync_receipt),
        trust_authority=stage3_trust_for_request(request), recall_snapshots=port,
    ) == 2
    assert not file_fsync_target.exists() and not file_fsync_receipt.exists()
    assert (artifacts["backup_root"] / "objects" / "record-a.bin").read_bytes() == backup_bytes
    monkeypatch.setattr(reconcile.os, "fsync", original_fsync)
    monkeypatch.setattr(reconcile, "_fsync_directory", original_directory_fsync)

    directory_target = tmp_path / "directory-fsync-restore"
    directory_receipt = tmp_path / "directory-fsync-receipt.json"
    directory_calls = 0

    def fail_before_receipt_commit(directory: Path) -> None:
        nonlocal directory_calls
        directory_calls += 1
        if directory_calls == 5:
            raise OSError("directory fsync before receipt commit")
        original_directory_fsync(directory)

    monkeypatch.setattr(reconcile, "_fsync_directory", fail_before_receipt_commit)
    assert reconcile.run_with_authority(
        with_outputs(directory_target, directory_receipt),
        trust_authority=stage3_trust_for_request(request), recall_snapshots=port,
    ) == 2
    assert directory_calls >= 5
    assert not directory_target.exists() and not directory_receipt.exists()
    assert (artifacts["backup_root"] / "objects" / "record-a.bin").read_bytes() == backup_bytes
    database.close()
