from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
import subprocess
import sys

import pytest

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_ledger_ports import (
    ReconciliationCoverageV1,
    ReconciliationFindingV1,
    ReconciliationResultV1,
)

from test_second_brain_reconcile import (
    _manifest,
    _record,
    _validated,
    _write_json,
    make_artifacts,
    reconcile,
    stage3_ref,
    stage3_request,
)


@pytest.mark.parametrize("mutation", ("unknown", "missing"))
def test_inventory_root_unknown_and_missing_fields_are_rejected(tmp_path: Path, mutation: str) -> None:
    artifacts = make_artifacts(tmp_path)
    source = copy.deepcopy(artifacts["source"])
    if mutation == "unknown":
        source["unexpected"] = True
    else:
        del source["source_root"]
    with pytest.raises(reconcile.ReconciliationError, match="fields are wrong"):
        reconcile.validate_source_inventory(source)


def test_identity_order_duplicates_and_conservation_tampering_are_rejected(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    source = copy.deepcopy(artifacts["source"])
    source["records"] *= 2
    with pytest.raises(reconcile.ReconciliationError, match="duplicate"):
        reconcile.validate_source_inventory(source)

    source["records"] = [
        _record() | {"native_id": "z", "revision": "1"},
        _record() | {"native_id": "a", "revision": "1"},
    ]
    with pytest.raises(reconcile.ReconciliationError, match="sorted"):
        reconcile.validate_source_inventory(source)

    source_object = reconcile.validate_source_inventory(artifacts["source"])
    cohort = copy.deepcopy(artifacts["cohort"])
    cohort["records"][0]["payload_sha256"] = "f" * 64
    cohort_object = reconcile.validate_cohort_inventory(cohort)
    with pytest.raises(reconcile.ReconciliationError, match="conservation"):
        reconcile.validate_inventory_conservation(source_object, cohort_object)


def test_manifest_rejects_multi_source_wrong_source_workspace_and_serving_state(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    _, cohort, _, _, _ = _validated(artifacts)

    bad_multi = _manifest(
        workspace_ref=cohort.workspace_ref,
        sources=["unified-db", "other"],
        state="READY_NON_SERVING",
    )
    multi_path = tmp_path / "multi.json"
    multi_path.write_bytes(canonical_bytes(bad_multi))
    with pytest.raises(reconcile.ReconciliationError, match="invalid cohort manifest"):
        reconcile.parse_and_bind_cohort_manifest(multi_path, cohort)

    bad_source = _manifest(
        workspace_ref=cohort.workspace_ref,
        sources=["other"],
        state="READY_NON_SERVING",
    )
    source_path = tmp_path / "wrong-source.json"
    source_path.write_bytes(canonical_bytes(bad_source))
    with pytest.raises(reconcile.ReconciliationError, match="inventory source"):
        reconcile.parse_and_bind_cohort_manifest(source_path, cohort)

    bad_workspace = _manifest(
        workspace_ref="workspace:" + "d" * 64,
        sources=["unified-db"],
        state="READY_NON_SERVING",
    )
    workspace_path = tmp_path / "wrong-workspace.json"
    workspace_path.write_bytes(canonical_bytes(bad_workspace))
    with pytest.raises(reconcile.ReconciliationError, match="workspace_ref"):
        reconcile.parse_and_bind_cohort_manifest(workspace_path, cohort)

    serving = _manifest(
        workspace_ref=cohort.workspace_ref,
        sources=["unified-db"],
        state="ROUTE_SWITCHED_NO_MUTATION",
    )
    serving_path = tmp_path / "serving.json"
    serving_path.write_bytes(canonical_bytes(serving))
    with pytest.raises(reconcile.ReconciliationError, match="non-serving"):
        reconcile.parse_and_bind_cohort_manifest(serving_path, cohort)


@pytest.mark.parametrize("field,value", (("relative_path", "../outside"), ("size", "01"), ("sha256", "A" * 64)))
def test_backup_manifest_rejects_bad_file_contracts(tmp_path: Path, field: str, value: str) -> None:
    artifacts = make_artifacts(tmp_path)
    backup = copy.deepcopy(artifacts["backup"])
    backup["files"][0][field] = value
    with pytest.raises(reconcile.ReconciliationError):
        reconcile.validate_backup_manifest(
            backup,
            source_inventory_digest=artifacts["source_digest"],
            cohort_inventory_digest=artifacts["cohort_digest"],
            cohort_manifest_digest=artifacts["manifest_file_digest"],
        )


@pytest.mark.parametrize("attack", ("missing", "extra", "hash", "size", "symlink", "hardlink"))
def test_backup_inventory_rejects_missing_extra_mutated_and_linked_entries(tmp_path: Path, attack: str) -> None:
    artifacts = make_artifacts(tmp_path)
    source, _, _, backup, _ = _validated(artifacts)
    backup_root = artifacts["backup_root"]
    backup_file = artifacts["backup_file"]
    if attack == "missing":
        backup_file.unlink()
    elif attack == "extra":
        (backup_root / "extra.bin").write_bytes(b"extra")
    elif attack == "hash":
        backup_file.write_bytes(b"different same-size")
    elif attack == "size":
        backup_file.write_bytes(b"different size")
    elif attack == "symlink":
        backup_file.unlink()
        backup_file.symlink_to(artifacts["source_root"])
    else:
        os_link = backup_root / "objects" / "duplicate.bin"
        os_link.hardlink_to(backup_file)
    with pytest.raises(reconcile.ReconciliationError):
        reconcile.verify_backup_inventory(backup, source)


def test_backup_scan_rejects_mutation_during_streaming_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = make_artifacts(tmp_path)
    source, _, _, backup, _ = _validated(artifacts)
    original_read = reconcile.os.read
    changed = False

    def mutate_after_read(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed:
            changed = True
            artifacts["backup_file"].write_bytes(b"mutated after read")
        return chunk

    monkeypatch.setattr(reconcile.os, "read", mutate_after_read)
    with pytest.raises(reconcile.ReconciliationError, match="changed"):
        reconcile.verify_backup_inventory(backup, source)


def test_restore_detects_backup_mutation_and_removes_only_its_new_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifacts = make_artifacts(tmp_path)
    source, _, _, backup, _ = _validated(artifacts)
    files = reconcile.verify_backup_inventory(backup, source)
    target = tmp_path / "restore"
    original_read = reconcile.os.read
    changed = False

    def mutate_during_copy(descriptor: int, size: int) -> bytes:
        nonlocal changed
        chunk = original_read(descriptor, size)
        if chunk and not changed:
            changed = True
            artifacts["backup_file"].write_bytes(b"external backup mutation")
        return chunk

    monkeypatch.setattr(reconcile.os, "read", mutate_during_copy)
    with pytest.raises(reconcile.ReconciliationError, match="changed"):
        reconcile.restore_verified_backup_inventory(backup, files, target)
    assert not target.exists()
    assert artifacts["source_root"].is_dir()


def test_path_alias_and_backup_root_isolation_are_rejected(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    source, _, _, backup, _ = _validated(artifacts)
    alias = str(artifacts["source_root"] / ".." / "source")
    with pytest.raises(reconcile.ReconciliationError, match="canonical"):
        reconcile._canonical_absolute_path(alias, "alias")
    with pytest.raises(reconcile.ReconciliationError, match="isolated"):
        reconcile.verify_backup_inventory(backup, source, restore_path=str(artifacts["backup_root"] / "restore"))


def test_atomic_output_refuses_collision_rolls_back_fsync_failures_and_closes_fds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "receipt.json"
    reconcile.publish_canonical_json_atomic(output, {"receipt": "ok"})
    assert output.read_bytes() == canonical_bytes({"receipt": "ok"})
    with pytest.raises(reconcile.ReconciliationError, match="collision"):
        reconcile.publish_canonical_json_atomic(output, {"receipt": "again"})

    directory_sync_failure = tmp_path / "directory-sync-failure.json"
    monkeypatch.setattr(reconcile, "_fsync_directory", lambda _: (_ for _ in ()).throw(OSError("sync")))
    with pytest.raises(reconcile.ReconciliationError, match="atomically"):
        reconcile.publish_canonical_json_atomic(directory_sync_failure, {"receipt": "no"})
    assert not directory_sync_failure.exists()
    assert not list(tmp_path.glob(".directory-sync-failure.json.*.tmp"))


def test_atomic_file_fsync_failure_and_read_path_close_each_fd_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    failures = tmp_path / "file-sync-failure.json"
    original_fsync = reconcile.os.fsync
    monkeypatch.setattr(reconcile.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("file sync")))
    with pytest.raises(reconcile.ReconciliationError, match="atomically"):
        reconcile.publish_canonical_json_atomic(failures, {"receipt": "no"})
    assert not failures.exists()

    monkeypatch.setattr(reconcile.os, "fsync", original_fsync)
    close_calls: list[int] = []
    original_close = reconcile.os.close

    def count_close(descriptor: int) -> None:
        close_calls.append(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(reconcile.os, "close", count_close)
    read_path = tmp_path / "input.json"
    read_path.write_bytes(canonical_bytes({"input": "ok"}))
    reconcile._load_canonical_object(read_path, "input")
    assert len(close_calls) == 1


def test_dto_contradictions_and_cli_help_and_invalid_arguments_are_fail_closed(tmp_path: Path) -> None:
    coverage = ReconciliationCoverageV1("1", "1", "0", "1")
    finding = ReconciliationFindingV1("PAYLOAD_MISMATCH", "a" * 64)
    with pytest.raises(ValueError):
        ReconciliationCoverageV1("1", "2", "1", "1")
    with pytest.raises(ValueError):
        ReconciliationResultV1("QUARANTINED", False, False, coverage, (finding,))
    with pytest.raises(ValueError):
        ReconciliationResultV1("PASS", False, True, coverage, ())

    help_result = subprocess.run(
        [sys.executable, str(reconcile.__file__), "--help"], text=True, capture_output=True, check=False
    )
    verify_help = subprocess.run(
        [sys.executable, str(reconcile.__file__), "verify", "--help"], text=True, capture_output=True, check=False
    )
    invalid = subprocess.run(
        [sys.executable, str(reconcile.__file__), "verify", "--unknown"], text=True, capture_output=True, check=False
    )
    incomplete = subprocess.run(
        [sys.executable, str(reconcile.__file__), "verify"], text=True, capture_output=True, check=False
    )
    assert help_result.returncode == verify_help.returncode == 0
    assert invalid.returncode == incomplete.returncode == 2
    assert "required" in incomplete.stderr


def test_public_verify_exact_argv_is_authorityless_and_never_mutates(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    target = tmp_path / "restore"
    receipt = tmp_path / "receipt.json"
    sample = tmp_path / "sample.json"
    sample.write_bytes(canonical_bytes({
        "recall_sample_version": reconcile.RECALL_SAMPLE_V1,
        "requests": [],
    }))
    command = [
        sys.executable, str(reconcile.__file__), "verify",
        "--source-inventory", str(artifacts["source_path"]),
        "--cohort-inventory", str(artifacts["cohort_path"]),
        "--cohort-manifest", str(artifacts["manifest_path"]),
        "--backup-manifest", str(artifacts["backup_path"]),
        "--restore-target", str(target),
        "--recall-sample", str(sample),
        "--receipt", str(receipt),
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert result.returncode == 2
    assert "DEPLOYMENT_AUTHORITY_ABSENT" in result.stderr
    assert not target.exists() and not receipt.exists()
    assert "trust" not in subprocess.run(
        [sys.executable, str(reconcile.__file__), "verify", "--help"],
        text=True, capture_output=True, check=False,
    ).stdout.lower()


def test_public_conserve_quarantine_fails_and_redacts_native_identifiers(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    quarantined = copy.deepcopy(artifacts["cohort"])
    quarantined["records"][0]["disposition"] = "QUARANTINED"
    quarantined["records"][0]["reason_code"] = "PAYLOAD_MISMATCH"
    _write_json(artifacts["cohort_path"], quarantined)
    backup = copy.deepcopy(artifacts["backup"])
    backup["cohort_inventory_digest"] = sha256(canonical_bytes(quarantined)).hexdigest()
    _write_json(artifacts["backup_path"], backup)
    quarantine_output = tmp_path / "quarantine-receipt.json"
    command = [
        sys.executable, str(reconcile.__file__), "conserve",
        "--source-inventory", str(artifacts["source_path"]),
        "--cohort-inventory", str(artifacts["cohort_path"]),
        "--cohort-manifest", str(artifacts["manifest_path"]),
        "--backup-manifest", str(artifacts["backup_path"]),
        "--output", str(quarantine_output),
    ]
    quarantined_result = subprocess.run(command, text=True, capture_output=True, check=False)
    assert quarantined_result.returncode == 2
    assert quarantined_result.stdout == ""
    assert quarantined_result.stderr == "FAIL: CONSERVATION_REJECTED\n"
    assert json.loads(quarantine_output.read_text())["result"]["result"] == "QUARANTINED"

    marker = "SECOND_BRAIN_NATIVE_IDENTIFIER_MUST_NOT_ESCAPE"
    source = copy.deepcopy(artifacts["source"])
    cohort = copy.deepcopy(quarantined)
    source["records"][0]["native_id"] = marker
    cohort["records"][0]["native_id"] = marker
    cohort["records"][0]["citation"]["citation_ref"] = marker
    cohort["records"][0]["disposition"] = "ACCEPTED"
    cohort["records"][0]["reason_code"] = None
    _write_json(artifacts["source_path"], source)
    _write_json(artifacts["cohort_path"], cohort)
    redaction_backup = copy.deepcopy(backup)
    redaction_backup["source_inventory_digest"] = sha256(canonical_bytes(source)).hexdigest()
    redaction_backup["cohort_inventory_digest"] = sha256(canonical_bytes(cohort)).hexdigest()
    _write_json(artifacts["backup_path"], redaction_backup)
    redaction_output = tmp_path / "redaction-receipt.json"
    redacted = subprocess.run(
        command[:-1] + [str(redaction_output)], text=True, capture_output=True, check=False
    )
    assert redacted.returncode == 2
    assert redacted.stdout == ""
    assert redacted.stderr == "FAIL: RECONCILIATION_REJECTED\n"
    assert marker not in redacted.stdout + redacted.stderr
    assert not redaction_output.exists()


@pytest.mark.parametrize("attack", ("unknown", "missing", "workspace", "duplicate", "unsorted"))
def test_recall_sample_is_closed_workspace_bound_and_canonically_unique(
    tmp_path: Path, attack: str
) -> None:
    workspace = stage3_ref("workspace", "recall-sample")
    request = stage3_request(workspace, transaction_cut="1")
    body: dict[str, object] = {
        "recall_sample_version": reconcile.RECALL_SAMPLE_V1,
        "requests": [request.to_mapping()],
    }
    if attack == "unknown":
        body["raw_query"] = "SECOND_BRAIN_SECRET_MARKER"
    elif attack == "missing":
        del body["requests"]
    elif attack == "workspace":
        body["requests"] = [stage3_request(stage3_ref("workspace", "other"), transaction_cut="1").to_mapping()]
    elif attack == "duplicate":
        body["requests"] = [request.to_mapping(), request.to_mapping()]
    else:
        later = stage3_request(workspace, transaction_cut="2")
        body["requests"] = [
            item.to_mapping()
            for item in sorted((request, later), key=lambda item: canonical_bytes(item.to_mapping()), reverse=True)
        ]
    sample = tmp_path / f"{attack}.json"
    sample.write_bytes(canonical_bytes(body))
    with pytest.raises(reconcile.ReconciliationError):
        reconcile._load_recall_sample(sample, workspace)


def _inventory_pair(artifacts: dict[str, object], records: list[dict[str, object]]):
    source = copy.deepcopy(artifacts["source"])
    cohort = copy.deepcopy(artifacts["cohort"])
    source["records"] = copy.deepcopy(records)
    cohort["records"] = [
        record | {"disposition": "ACCEPTED", "reason_code": None} for record in copy.deepcopy(records)
    ]
    return source, cohort


def test_slice_b_rejects_lexical_order_but_preserves_numeric_history_gaps(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    lexical = [
        _record() | {"revision": "1"},
        _record() | {"revision": "10"},
        _record() | {"revision": "2"},
    ]
    source, _ = _inventory_pair(artifacts, lexical)
    with pytest.raises(reconcile.ReconciliationError, match="numeric revision"):
        reconcile.validate_source_inventory(source)

    gapped = [_record() | {"revision": "1"}, _record() | {"revision": "3"}]
    source, cohort = _inventory_pair(artifacts, gapped)
    result, _ = reconcile.reconcile_inventory_conservation(
        reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)
    )
    assert result.coverage == ReconciliationCoverageV1("2", "2", "2", "0")

    collapsed = copy.deepcopy(cohort)
    collapsed["records"][1]["revision"] = "2"
    with pytest.raises(reconcile.ReconciliationError, match="exactly the same identities"):
        reconcile.reconcile_inventory_conservation(
            reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(collapsed)
        )


def test_slice_b_rejects_cross_root_and_same_root_payload_collisions(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    cross_root = [
        _record() | {"revision": "1", "dedupe_root_ref": "root-a"},
        _record() | {"revision": "2", "dedupe_root_ref": "root-b"},
    ]
    source, cohort = _inventory_pair(artifacts, cross_root)
    with pytest.raises(reconcile.ReconciliationError, match="multiple roots"):
        reconcile.reconcile_inventory_conservation(
            reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)
        )

    root_payload_collision = [
        _record() | {"revision": "1", "dedupe_root_ref": "root-a", "payload_sha256": "a" * 64},
        _record() | {"revision": "2", "dedupe_root_ref": "root-a", "payload_sha256": "c" * 64},
    ]
    source, cohort = _inventory_pair(artifacts, root_payload_collision)
    with pytest.raises(reconcile.ReconciliationError, match="multiple payloads"):
        reconcile.reconcile_inventory_conservation(
            reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)
        )


def test_slice_b_quarantine_is_counted_hash_only_and_never_authorizes_live_operation(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)
    cohort = copy.deepcopy(artifacts["cohort"])
    cohort["records"][0]["disposition"] = "QUARANTINED"
    cohort["records"][0]["reason_code"] = "PAYLOAD_MISMATCH"
    result, aggregates = reconcile.reconcile_inventory_conservation(
        reconcile.validate_source_inventory(artifacts["source"]),
        reconcile.validate_cohort_inventory(cohort),
    )
    assert result.result == "QUARANTINED"
    assert result.no_import is True
    assert result.live_operation_authorized is False
    assert result.coverage == ReconciliationCoverageV1("1", "1", "0", "1")
    assert [(finding.rule_code, len(finding.evidence_sha256)) for finding in result.findings] == [
        ("PAYLOAD_MISMATCH", 64)
    ]
    assert len(aggregates.quarantine_bindings_sha256) == 64


@pytest.mark.parametrize("mutation", ("unknown", "missing", "tamper"))
def test_slice_b_receipt_is_closed_and_self_digest_bound(tmp_path: Path, mutation: str) -> None:
    artifacts = make_artifacts(tmp_path)
    receipt = reconcile.conserve_documents(
        source_inventory_path=artifacts["source_path"],
        cohort_inventory_path=artifacts["cohort_path"],
        cohort_manifest_path=artifacts["manifest_path"],
        backup_manifest_path=artifacts["backup_path"],
        output_path=tmp_path / "receipt.json",
    )
    changed = copy.deepcopy(receipt)
    if mutation == "unknown":
        changed["unexpected"] = True
        match = "fields are wrong"
    elif mutation == "missing":
        del changed["aggregate_digests"]
        match = "fields are wrong"
    else:
        changed["aggregate_digests"]["payloads_sha256"] = "f" * 64
        match = "self-digest mismatch"
    with pytest.raises(reconcile.ReconciliationError, match=match):
        reconcile.validate_reconciliation_receipt(changed)


def test_slice_b_aggregate_identity_and_citation_are_source_namespaced(tmp_path: Path) -> None:
    artifacts = make_artifacts(tmp_path)

    def inventory_pair(source_ref: str):
        source = copy.deepcopy(artifacts["source"])
        cohort = copy.deepcopy(artifacts["cohort"])
        source["source_ref"] = source_ref
        cohort["source_ref"] = source_ref
        return reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)

    result_a, aggregates_a = reconcile.reconcile_inventory_conservation(*inventory_pair("source-a"))
    result_b, aggregates_b = reconcile.reconcile_inventory_conservation(*inventory_pair("source-b"))
    assert result_a == result_b
    assert aggregates_a.identities_sha256 != aggregates_b.identities_sha256
    assert aggregates_a.citations_sha256 != aggregates_b.citations_sha256


def test_slice_b_citation_aggregate_binds_payload_and_quarantine_finding_binds_source_ref(
    tmp_path: Path,
) -> None:
    artifacts = make_artifacts(tmp_path)
    source = copy.deepcopy(artifacts["source"])
    cohort = copy.deepcopy(artifacts["cohort"])
    _, original_aggregates = reconcile.reconcile_inventory_conservation(
        reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)
    )

    source["records"][0]["payload_sha256"] = "c" * 64
    cohort["records"][0]["payload_sha256"] = "c" * 64
    _, changed_aggregates = reconcile.reconcile_inventory_conservation(
        reconcile.validate_source_inventory(source), reconcile.validate_cohort_inventory(cohort)
    )
    assert original_aggregates.citations_sha256 != changed_aggregates.citations_sha256

    mismatched_cohort = copy.deepcopy(cohort)
    mismatched_cohort["records"][0]["payload_sha256"] = "a" * 64
    with pytest.raises(reconcile.ReconciliationError, match="conservation"):
        reconcile.reconcile_inventory_conservation(
            reconcile.validate_source_inventory(source),
            reconcile.validate_cohort_inventory(mismatched_cohort),
        )

    def quarantined_finding(source_ref: str) -> str:
        q_source = copy.deepcopy(artifacts["source"])
        q_cohort = copy.deepcopy(artifacts["cohort"])
        q_source["source_ref"] = source_ref
        q_cohort["source_ref"] = source_ref
        q_cohort["records"][0]["disposition"] = "QUARANTINED"
        q_cohort["records"][0]["reason_code"] = "PAYLOAD_MISMATCH"
        result, _ = reconcile.reconcile_inventory_conservation(
            reconcile.validate_source_inventory(q_source), reconcile.validate_cohort_inventory(q_cohort)
        )
        return result.findings[0].evidence_sha256

    assert quarantined_finding("source-a") != quarantined_finding("source-b")
