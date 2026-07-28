from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import CapturePersistenceError, EncryptedCapturePersistence, LifecycleDatabase, fixture_capture_database
from wiki_spike.memory_core.second_brain_capture_contracts import CapturePersistenceAggregateV1, canonical_identity_body_digest

DEK = bytes(range(32))
PROFILES = (("Codex", "codex"), ("Claude/Memory Bank", "claude-memory-bank"), ("Git", "git"), ("Markdown", "markdown"))
TABLES = ("capture_scope", "capture_receipt", "capture_manifest", "capture_reconciliation", "capture_checkpoint", "migration_registration", "capture_cohort")


def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def ref(kind: str, value: str) -> str:
    return f"{kind}:{digest(value)}"


def bound(domain: str, value: dict, field: str) -> dict:
    value[field] = canonical_identity_body_digest(domain, {key: item for key, item in value.items() if key != field})
    return value


def aggregate(profile: str, domain: str, *, epoch: str = "1", previous: str | None = None, cohort_entries: list[dict] | None = None, cohort_label: str | None = None) -> CapturePersistenceAggregateV1:
    label = f"{domain}-{epoch}"
    scope = {"scope_version": "second-brain-source-scope-ref-v1", "source_profile": profile, "source_domain": domain, "source_ref": ref(f"{domain}-source", domain), "workspace_ref": ref("workspace", "stage2"), "scope_ref": ref(f"{domain}-scope", domain), "scope_epoch": "1"}
    receipt = {"receipt_version": "second-brain-capture-item-receipt-v1", "scope": scope, "scan_epoch": epoch, "capture_ref": ref("capture", label), "encrypted_content_ref": ref("encrypted-content", label), "encrypted_native_mapping_ref": ref("encrypted-native-mapping", label), "ciphertext_digest": digest("ciphertext-" + label), "disposition": "ACCEPTED"}
    manifest = bound("manifest-v1", {"manifest_version": "second-brain-capture-scan-manifest-v1", "scope": scope, "scan_epoch": epoch, "checkpoint_ref": previous or ref("checkpoint", "initial-" + label), "receipt_refs": [receipt["capture_ref"]], "manifest_ref": ref("manifest", label), "manifest_digest": ""}, "manifest_digest")
    reconciliation = bound("reconciliation-v1", {"reconciliation_version": "second-brain-capture-reconciliation-v1", "scope": scope, "scan_epoch": epoch, "manifest_ref": manifest["manifest_ref"], "reconciliation_ref": ref("reconciliation", label), "reconciliation_epoch": epoch, "completion": "COMPLETE", "outcome": "RECONCILED", "expected_receipt_count": "1", "accounted_receipt_count": "1", "disposition_counts": {"ACCEPTED": "1", "DUPLICATE": "0", "TOMBSTONE": "0", "SKIPPED": "0", "QUARANTINED": "0"}, "reconciliation_digest": ""}, "reconciliation_digest")
    checkpoint = bound("checkpoint-v1", {"checkpoint_version": "second-brain-scan-checkpoint-v1", "scope": scope, "scan_epoch": epoch, "checkpoint_ref": ref("checkpoint", label), "checkpoint_digest": "", "manifest_ref": manifest["manifest_ref"], "reconciliation_ref": reconciliation["reconciliation_ref"], "reconciliation_digest": reconciliation["reconciliation_digest"], "reconciliation_epoch": epoch, "reconciliation_completion": "COMPLETE", "reconciliation_outcome": "RECONCILED"}, "checkpoint_digest")
    registration = {"registration_version": "second-brain-migration-registration-v1", "migration_source": "unified-db", "migration_ref": ref("unified-db-migration", label), "migration_scope_ref": ref("unified-db-migration-scope", label), "scope": scope, "migration_epoch": epoch, "registration_ref": ref("migration-registration", label), "ciphertext_digest": digest("migration-" + label)}
    entry = {"source_domain": domain, "source_ref": scope["source_ref"], "registration_ref": registration["registration_ref"], "scope_ref": scope["scope_ref"], "manifest_ref": manifest["manifest_ref"], "reconciliation_ref": reconciliation["reconciliation_ref"], "reconciliation_epoch": epoch, "checkpoint_ref": checkpoint["checkpoint_ref"], "checkpoint_epoch": epoch}
    entry["ownership_binding"] = {"workspace_ref": scope["workspace_ref"], **{key: value for key, value in entry.items() if key != "source_domain"}}
    roster = cohort_entries or [entry]
    cohort = bound("cohort-v1", {"cohort_version": "second-brain-non-serving-capture-cohort-v1", "cohort_ref": ref("cohort", cohort_label or label), "final_workspace_ref": scope["workspace_ref"], "state": "NON_SERVING", "source_roster": roster, "cohort_digest": ""}, "cohort_digest")
    value = {"aggregate_version": "second-brain-capture-persistence-aggregate-v1", "scope": scope, "receipts": [receipt], "manifest": manifest, "registration": registration, "advance": {"advance_version": "second-brain-reconciled-checkpoint-advance-v1", "previous_checkpoint_ref": previous, "reconciliation": reconciliation, "checkpoint": checkpoint}, "cohort": cohort, "aggregate_digest": ""}
    return CapturePersistenceAggregateV1.from_mapping(bound("aggregate-v1", value, "aggregate_digest"))


def store(tmp_path: Path) -> tuple[LifecycleDatabase, EncryptedContentStore, EncryptedCapturePersistence]:
    database = fixture_capture_database(tmp_path / "fixture.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    return database, cas, EncryptedCapturePersistence(database, cas, DEK)


def test_four_source_capture_identities_are_atomic_encrypted_and_restart_idempotent(tmp_path: Path):
    database, cas, persistence = store(tmp_path)
    values = [aggregate(profile, domain) for profile, domain in PROFILES]
    for value in values:
        persistence.persist_capture_aggregate(value)
        persistence.persist_capture_aggregate(value)
    assert database.con.execute("SELECT COUNT(*) FROM capture_scope").fetchone()[0] == 4
    assert database.con.execute("SELECT COUNT(DISTINCT aggregate_handle) FROM capture_receipt").fetchone()[0] == 4
    handles = [row[0] for row in database.con.execute("SELECT aggregate_handle FROM capture_scope")]
    assert all(handle.startswith("encrypted-capture:") and cas.exists(handle.removeprefix("encrypted-capture:")) for handle in handles)
    database.close()
    reopened = fixture_capture_database(tmp_path / "fixture.sqlite")
    reopened.initialize()
    recovered = EncryptedCapturePersistence(reopened, cas, DEK)
    recovered.persist_capture_aggregate(values[0])
    assert reopened.con.execute("SELECT COUNT(*) FROM capture_receipt").fetchone()[0] == 4
    reopened.close()


@pytest.mark.parametrize("failure_call", range(1, 7))
def test_each_sqlite_phase_rolls_back_without_partial_rows_or_authoritative_cas_refs(tmp_path: Path, monkeypatch, failure_call: int):
    database, cas, persistence = store(tmp_path)
    original = persistence._insert_or_match
    calls = 0
    def fail_after_phase(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == failure_call:
            raise RuntimeError("phase failure")
        return original(*args, **kwargs)
    monkeypatch.setattr(persistence, "_insert_or_match", fail_after_phase)
    with pytest.raises(RuntimeError, match="phase failure"):
        persistence.persist_capture_aggregate(aggregate("Git", "git"))
    assert all(database.con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0 for table in TABLES)
    assert not database.con.execute("SELECT 1 FROM capture_scope WHERE aggregate_handle LIKE 'encrypted-capture:%'").fetchall()
    assert len(tuple(cas.objects.iterdir())) == 1  # CAS may retain only an unreferenced encrypted blob.
    database.close()
def test_identical_retry_after_sqlite_rollback_publishes_one_complete_aggregate(tmp_path: Path, monkeypatch):
    database, _, persistence = store(tmp_path)
    value = aggregate("Git", "git")
    original = persistence._insert_or_match
    failed = False

    def fail_once(*args, **kwargs):
        nonlocal failed
        if not failed:
            failed = True
            raise RuntimeError("rollback")
        return original(*args, **kwargs)

    monkeypatch.setattr(persistence, "_insert_or_match", fail_once)
    with pytest.raises(RuntimeError, match="rollback"):
        persistence.persist_capture_aggregate(value)
    monkeypatch.setattr(persistence, "_insert_or_match", original)
    persistence.persist_capture_aggregate(value)
    persistence.persist_capture_aggregate(value)
    assert database.con.execute("SELECT COUNT(*) FROM capture_scope").fetchone()[0] == 1
    assert database.con.execute("SELECT COUNT(*) FROM capture_receipt").fetchone()[0] == 1
    database.close()



def test_stale_quarantined_and_missing_reconciliation_never_publish_checkpoint(tmp_path: Path):
    database, _, persistence = store(tmp_path)
    first = aggregate("Markdown", "markdown")
    persistence.persist_capture_aggregate(first)
    stale = aggregate("Markdown", "markdown", epoch="2", previous=None)
    with pytest.raises(CapturePersistenceError, match="stale checkpoint"):
        persistence.persist_capture_aggregate(stale)
    quarantined = aggregate("Markdown", "markdown", epoch="2", previous=first.advance.checkpoint.checkpoint_ref)
    with pytest.raises(CapturePersistenceError, match="canonical contract"):
        persistence.persist_capture_aggregate(
            replace(
                quarantined,
                receipts=(replace(quarantined.receipts[0], disposition="QUARANTINED"),),
            )
        )
    assert database.con.execute("SELECT checkpoint_id FROM capture_checkpoint").fetchone()[0] == first.advance.checkpoint.checkpoint_ref
    database.close()


def test_full_cohort_requires_exact_durable_reconciliation_checkpoint_and_epoch(tmp_path: Path):
    database, _, persistence = store(tmp_path)
    aggregates = [aggregate(profile, domain) for profile, domain in PROFILES]
    for value in aggregates[1:]:
        persistence.persist_capture_aggregate(value)
    entries = [value.cohort.source_roster[0].to_mapping() for value in aggregates]
    final = aggregate("Codex", "codex", cohort_entries=entries, cohort_label="full-stage2")
    persistence.persist_capture_aggregate(final)
    assert database.con.execute("SELECT COUNT(*) FROM capture_cohort").fetchone()[0] == 4
    database.close()


def test_sqlite_stores_only_bound_encrypted_refs_and_no_raw_payload(tmp_path: Path):
    database, cas, persistence = store(tmp_path)
    value = aggregate("Codex", "codex")
    persistence.persist_capture_aggregate(value)
    receipt = database.con.execute(
        "SELECT encrypted_content_ref, encrypted_native_mapping_ref, aggregate_handle "
        "FROM capture_receipt"
    ).fetchone()
    assert tuple(receipt[:2]) == (
        value.receipts[0].encrypted_content_ref,
        value.receipts[0].encrypted_native_mapping_ref,
    )
    assert receipt[2].startswith("encrypted-capture:")
    assert cas.exists(receipt[2].removeprefix("encrypted-capture:"))
    sqlite_bytes = (tmp_path / "fixture.sqlite").read_bytes()
    assert b'"native_mapping"' not in sqlite_bytes and b"ciphertext-codex" not in sqlite_bytes
    encrypted = next(cas.objects.iterdir()).read_bytes()
    assert encrypted not in sqlite_bytes and b'"aggregate_version"' not in encrypted
    database.close()


def test_production_database_never_installs_capture_tables_or_accepts_mode_mutation(tmp_path: Path):
    database = LifecycleDatabase(tmp_path / "production.sqlite", fixture_capture_mode=True)
    database.initialize()
    assert not {row[0] for row in database.con.execute("SELECT name FROM sqlite_master WHERE type='table'")}.intersection(TABLES)
    with pytest.raises(AttributeError):
        database.fixture_capture_mode = True
    database.close()


def test_writer_reparses_forged_complete_aggregate_before_writing(tmp_path: Path):
    database, _, persistence = store(tmp_path)
    value = aggregate("Codex", "codex")
    forged = CapturePersistenceAggregateV1(
        value.aggregate_version, value.scope, value.receipts, value.manifest,
        value.registration, value.advance, value.cohort, "0" * 64,
    )
    with pytest.raises(CapturePersistenceError, match="canonical contract"):
        persistence.persist_capture_aggregate(forged)
    assert database.con.execute("SELECT COUNT(*) FROM capture_scope").fetchone()[0] == 0
    database.close()
