"""Stage-2 fixture capture orchestration; persistence remains in infrastructure."""
from __future__ import annotations

from hashlib import sha256
from typing import Sequence

from wiki_spike.memory_core.second_brain_capture_contracts import (
    CaptureItemReceiptV1, CaptureScanManifestV1, MigrationRegistrationV1,
    NonServingCaptureCohortV1, ReconciledCheckpointAdvanceV1, SourceScopeRefV1,
)
from wiki_spike.memory_core.second_brain_capture_ports import ConnectorSourceReaderPort
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients
from wiki_spike.infrastructure.lifecycle_db import EncryptedCapturePersistence


class FixtureCaptureServiceError(ValueError):
    pass


class FixtureCaptureService:
    """Coordinates frozen ports without source I/O, activation, or serving."""

    def __init__(self, persistence: EncryptedCapturePersistence, fixture_clients: FixtureCaptureClients) -> None:
        self._persistence = persistence
        self._fixture_clients = fixture_clients

    def capture(
        self, scope: SourceScopeRefV1, reader: ConnectorSourceReaderPort,
        receipts: Sequence[CaptureItemReceiptV1], manifest: CaptureScanManifestV1,
        advance: ReconciledCheckpointAdvanceV1, registration: MigrationRegistrationV1,
        migration_capability: object,
    ) -> None:
        if registration.scope != scope or manifest.scope != scope or advance.checkpoint.scope != scope:
            raise FixtureCaptureServiceError("all capture evidence must bind one exact source scope")
        self._fixture_clients.verify_read_only_migration_capability(migration_capability, registration.migration_ref)
        ciphertexts = reader.read_fixture_ciphertexts(scope, scope.scope_epoch)
        by_digest = sorted(sha256(value).hexdigest() for value in ciphertexts)
        expected = sorted(receipt.ciphertext_digest for receipt in receipts)
        if by_digest != expected or set(manifest.receipt_refs) != {receipt.capture_ref for receipt in receipts}:
            raise FixtureCaptureServiceError("fixture ciphertexts and receipt manifest do not reconcile")
        self._persistence.record_scope(scope)
        for receipt in receipts:
            if receipt.scope != scope or receipt.scan_epoch != scope.scope_epoch:
                raise FixtureCaptureServiceError("receipt scope or epoch mismatch")
            self._persistence.record_capture_receipt(receipt)
        self._persistence.record_capture_manifest(manifest)
        self._persistence.record_migration_registration(registration)
        self._persistence.reconcile_and_advance_checkpoint(advance)

    def record_final_non_serving_cohort(self, cohort: NonServingCaptureCohortV1) -> None:
        self._persistence.record_non_serving_capture_cohort(cohort)
