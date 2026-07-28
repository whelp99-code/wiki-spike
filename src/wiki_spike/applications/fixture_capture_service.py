"""Fixture-only Stage-2 capture orchestration against core ports."""
from __future__ import annotations

from hashlib import sha256
from typing import Protocol, runtime_checkable

from wiki_spike.memory_core.second_brain_capture import (
    AtomicCapturePersistencePort,
    CapturePersistenceAggregateV1,
    ConnectorSourceReaderPort,
    SourceScopeRefV1,
)


class FixtureCaptureServiceError(ValueError):
    pass


@runtime_checkable
class MigrationCapabilityVerificationPort(Protocol):
    """Verifies a capability bound to the exact resolved source scope."""
    def verify_read_only_migration_capability(
        self, capability: object, migration_ref: str, scope: SourceScopeRefV1
    ) -> None: ...


class FixtureCaptureService:
    """Validates transient fixture evidence, then invokes the sole write port."""

    def __init__(
        self,
        persistence: AtomicCapturePersistencePort,
        capability_verifier: MigrationCapabilityVerificationPort,
    ) -> None:
        if not isinstance(persistence, AtomicCapturePersistencePort):
            raise FixtureCaptureServiceError("atomic capture persistence port is required")
        if not isinstance(capability_verifier, MigrationCapabilityVerificationPort):
            raise FixtureCaptureServiceError("migration capability verification port is required")
        self._persistence = persistence
        self._capability_verifier = capability_verifier

    def capture(
        self,
        aggregate: CapturePersistenceAggregateV1,
        reader: ConnectorSourceReaderPort,
        migration_capability: object,
    ) -> None:
        if not isinstance(aggregate, CapturePersistenceAggregateV1):
            raise FixtureCaptureServiceError("complete capture aggregate is required")
        scope = aggregate.scope
        self._capability_verifier.verify_read_only_migration_capability(
            migration_capability, aggregate.registration.migration_ref, scope
        )
        items = reader.read_fixture_capture_items(scope, aggregate.manifest.scan_epoch)
        if len({item.capture_ref for item in items}) != len(items):
            raise FixtureCaptureServiceError("connector returned duplicate capture references")
        observed = {
            item.capture_ref: (
                item.encrypted_content_ref,
                item.encrypted_native_mapping_ref,
                sha256(item.ciphertext).hexdigest(),
            )
            for item in items
        }
        expected = {
            receipt.capture_ref: (
                receipt.encrypted_content_ref,
                receipt.encrypted_native_mapping_ref,
                receipt.ciphertext_digest,
            )
            for receipt in aggregate.receipts
        }
        if observed != expected:
            raise FixtureCaptureServiceError("fixture capture identity and ciphertext evidence does not exactly match receipts")
        self._persistence.persist_capture_aggregate(aggregate)
