from __future__ import annotations

import base64
import json
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.applications.fixture_capture_service import FixtureCaptureService
from wiki_spike.connectors.claude_memory_bank import ClaudeMemoryBankFixtureConnector
from wiki_spike.connectors.codex import CodexFixtureConnector
from wiki_spike.connectors.git import GitFixtureConnector
from wiki_spike.connectors.markdown import MarkdownFixtureConnector
from wiki_spike.infrastructure.fixture_capture_clients import (
    FixtureCaptureClientError,
    FixtureCaptureClients,
    FixtureNativeMappingSealer,
)
from wiki_spike.infrastructure.lifecycle_db import (
    CapturePersistenceError,
    EncryptedCapturePersistence,
    LifecycleDatabase,
)
from wiki_spike.memory_core.second_brain_capture_contracts import (
    CaptureItemReceiptV1,
    CaptureScanManifestV1,
    MigrationRegistrationV1,
    ReconciledCheckpointAdvanceV1,
    SourceScopeRefV1,
)


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "second_brain" / "capture"
PROFILES = (
    ("codex.json", CodexFixtureConnector, "Codex", "codex"),
    ("claude_memory_bank.json", ClaudeMemoryBankFixtureConnector, "Claude/Memory Bank", "claude-memory-bank"),
    ("git.json", GitFixtureConnector, "Git", "git"),
    ("markdown.json", MarkdownFixtureConnector, "Markdown", "markdown"),
)


def digest(label: str) -> str:
    return sha256(label.encode("ascii")).hexdigest()


def ref(kind: str, label: str) -> str:
    return f"{kind}:{digest(label)}"


def scope(profile: str, domain: str, label: str, workspace: str | None = None) -> SourceScopeRefV1:
    return SourceScopeRefV1.from_mapping({
        "scope_version": "second-brain-source-scope-ref-v1",
        "source_profile": profile,
        "source_domain": domain,
        "source_ref": ref(f"{domain}-source", f"{label}-source"),
        "workspace_ref": workspace or ref("workspace", "stage2-workspace"),
        "scope_ref": ref(f"{domain}-scope", f"{label}-scope"),
        "scope_epoch": "1",
    })


def evidence(source_scope: SourceScopeRefV1, ciphertext: bytes, *, epoch: str = "1", disposition: str = "ACCEPTED", previous: str | None = None) -> tuple[CaptureItemReceiptV1, CaptureScanManifestV1, ReconciledCheckpointAdvanceV1, MigrationRegistrationV1]:
    label = f"{source_scope.scope_ref}-{epoch}"
    receipt = CaptureItemReceiptV1.from_mapping({
        "receipt_version": "second-brain-capture-item-receipt-v1",
        "scope": source_scope.to_mapping(), "scan_epoch": epoch,
        "capture_ref": ref("capture", label), "ciphertext_digest": sha256(ciphertext).hexdigest(),
        "disposition": disposition,
    })
    manifest = CaptureScanManifestV1.from_mapping({
        "manifest_version": "second-brain-capture-scan-manifest-v1",
        "scope": source_scope.to_mapping(), "scan_epoch": epoch,
        "checkpoint_ref": previous or ref("checkpoint", f"initial-{source_scope.scope_ref}"),
        "receipt_refs": [receipt.capture_ref], "manifest_ref": ref("manifest", label),
        "manifest_digest": digest(f"manifest-{label}"),
    })
    reconciliation_ref = ref("reconciliation", label)
    reconciliation_digest = digest(f"reconciliation-{label}")
    advance = ReconciledCheckpointAdvanceV1.from_mapping({
        "advance_version": "second-brain-reconciled-checkpoint-advance-v1",
        "previous_checkpoint_ref": previous,
        "reconciliation": {
            "reconciliation_version": "second-brain-capture-reconciliation-v1",
            "scope": source_scope.to_mapping(), "scan_epoch": epoch,
            "manifest_ref": manifest.manifest_ref, "reconciliation_ref": reconciliation_ref,
            "reconciliation_epoch": epoch, "completion": "COMPLETE", "outcome": "RECONCILED",
            "expected_receipt_count": "1", "accounted_receipt_count": "1",
            "disposition_counts": {"ACCEPTED": "1" if disposition == "ACCEPTED" else "0", "DUPLICATE": "0", "TOMBSTONE": "0", "SKIPPED": "0", "QUARANTINED": "1" if disposition == "QUARANTINED" else "0"},
            "reconciliation_digest": reconciliation_digest,
        },
        "checkpoint": {
            "checkpoint_version": "second-brain-scan-checkpoint-v1",
            "scope": source_scope.to_mapping(), "scan_epoch": epoch,
            "checkpoint_ref": ref("checkpoint", label), "checkpoint_digest": digest(f"checkpoint-{label}"),
            "manifest_ref": manifest.manifest_ref, "reconciliation_ref": reconciliation_ref,
            "reconciliation_digest": reconciliation_digest, "reconciliation_epoch": epoch,
            "reconciliation_completion": "COMPLETE", "reconciliation_outcome": "RECONCILED",
        },
    })
    registration = MigrationRegistrationV1.from_mapping({
        "registration_version": "second-brain-migration-registration-v1", "migration_source": "unified-db",
        "migration_ref": ref("unified-db-migration", label),
        "migration_scope_ref": ref("unified-db-migration-scope", label), "scope": source_scope.to_mapping(),
        "migration_epoch": epoch, "registration_ref": ref("migration-registration", label),
        "ciphertext_digest": digest(f"migration-{label}"),
    })
    return receipt, manifest, advance, registration


def store(tmp_path: Path) -> tuple[LifecycleDatabase, EncryptedCapturePersistence]:
    database = LifecycleDatabase(tmp_path / "capture.sqlite")
    database.initialize()
    return database, EncryptedCapturePersistence(database)


@pytest.mark.parametrize(("fixture_name", "connector_type", "profile", "domain"), PROFILES)
def test_all_source_profiles_capture_to_real_sqlite_and_survive_restart(tmp_path, fixture_name, connector_type, profile, domain):
    source_scope = scope(profile, domain, domain)
    fixture = json.loads((FIXTURES / fixture_name).read_text())
    fixture["scope_ref"] = source_scope.scope_ref
    ciphertext = base64.b64decode(fixture["ciphertext_b64"])
    request_ref = ref("fixture-request", domain)
    clients = FixtureCaptureClients(payloads={request_ref: json.dumps(fixture, sort_keys=True).encode()})
    reader = connector_type(clients, FixtureNativeMappingSealer(), [request_ref])
    database, persistence = store(tmp_path)
    receipt, manifest, advance, registration = evidence(source_scope, ciphertext)
    service = FixtureCaptureService(persistence, clients)

    service.capture(source_scope, reader, [receipt], manifest, advance, registration, clients.issue_read_only_migration_capability(registration.migration_ref))
    database.close()

    reopened = LifecycleDatabase(tmp_path / "capture.sqlite")
    reopened.initialize()
    recovered = EncryptedCapturePersistence(reopened)
    recovered.record_scope(source_scope)
    recovered.record_capture_receipt(receipt)
    recovered.record_capture_manifest(manifest)
    recovered.record_migration_registration(registration)
    assert recovered.read_capture_receipt(receipt.capture_ref) == receipt
    assert recovered.read_scan_checkpoint(source_scope.scope_ref) == advance.checkpoint
    assert reopened.con.execute("SELECT COUNT(*) FROM capture_receipt").fetchone()[0] == 1
    reopened.close()


def test_capture_write_crash_rolls_back_and_scope_substitution_is_rejected(tmp_path, monkeypatch):
    database, persistence = store(tmp_path)
    original_scope = scope("Git", "git", "primary")
    persistence.record_scope(original_scope)
    receipt, _, _, _ = evidence(original_scope, b"fixture-ciphertext")
    original_insert = persistence._insert

    def crash_after_insert(*args, **kwargs):
        original_insert(*args, **kwargs)
        raise RuntimeError("injected crash")

    monkeypatch.setattr(persistence, "_insert", crash_after_insert)
    with pytest.raises(RuntimeError, match="injected crash"):
        persistence.record_capture_receipt(receipt)
    assert persistence.read_capture_receipt(receipt.capture_ref) is None

    workspace_substituted = scope("Git", "git", "substituted", ref("workspace", "other-workspace"))
    source_substituted = scope("Git", "git", "other-source")
    for substituted in (workspace_substituted, source_substituted):
        substituted = SourceScopeRefV1.from_mapping({**substituted.to_mapping(), "scope_ref": original_scope.scope_ref})
        with pytest.raises(CapturePersistenceError, match="mismatch"):
            persistence.record_capture_receipt(CaptureItemReceiptV1.from_mapping({**receipt.to_mapping(), "scope": substituted.to_mapping()}))
    database.close()


def test_reconciliation_refuses_missing_mismatched_quarantined_and_stale_checkpoint(tmp_path):
    database, persistence = store(tmp_path)
    source_scope = scope("Markdown", "markdown", "reconcile")
    persistence.record_scope(source_scope)
    receipt, manifest, advance, _ = evidence(source_scope, b"one")

    with pytest.raises(CapturePersistenceError, match="manifest is not durable"):
        persistence.reconcile_and_advance_checkpoint(advance)
    persistence.record_capture_receipt(receipt)
    persistence.record_capture_manifest(manifest)
    extra = CaptureItemReceiptV1.from_mapping({
        **receipt.to_mapping(), "capture_ref": ref("capture", "extra-receipt"),
        "ciphertext_digest": digest("extra-receipt"),
    })
    persistence.record_capture_receipt(extra)
    with pytest.raises(CapturePersistenceError, match="incomplete or mismatched"):
        persistence.reconcile_and_advance_checkpoint(advance)

    database.con.execute("DELETE FROM capture_receipt WHERE capture_id=?", (extra.capture_ref,))
    quarantined_receipt, quarantined_manifest, quarantined_advance, _ = evidence(source_scope, b"quarantine", epoch="2", disposition="QUARANTINED")
    persistence.record_capture_receipt(quarantined_receipt)
    persistence.record_capture_manifest(quarantined_manifest)
    with pytest.raises(CapturePersistenceError, match="quarantine"):
        persistence.reconcile_and_advance_checkpoint(quarantined_advance)
    assert persistence.read_scan_checkpoint(source_scope.scope_ref) is None

    persistence.reconcile_and_advance_checkpoint(advance)
    next_receipt, next_manifest, stale_advance, _ = evidence(source_scope, b"next", epoch="3")
    persistence.record_capture_receipt(next_receipt)
    persistence.record_capture_manifest(next_manifest)
    with pytest.raises(CapturePersistenceError, match="stale checkpoint"):
        persistence.reconcile_and_advance_checkpoint(stale_advance)
    assert persistence.read_scan_checkpoint(source_scope.scope_ref) == advance.checkpoint
    database.close()


def test_service_refuses_forged_migration_capability_before_persistence(tmp_path):
    database, persistence = store(tmp_path)
    source_scope = scope("Codex", "codex", "capability")
    receipt, manifest, advance, registration = evidence(source_scope, b"fixture")
    clients = FixtureCaptureClients()
    service = FixtureCaptureService(persistence, clients)

    with pytest.raises(FixtureCaptureClientError, match="capability"):
        service.capture(source_scope, object(), [receipt], manifest, advance, registration, object())
    assert database.con.execute("SELECT COUNT(*) FROM capture_scope").fetchone()[0] == 0
    database.close()
