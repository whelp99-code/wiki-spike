"""Inert Stage-2 fixture capture composition.

This module is the only Stage-2 wiring point.  It accepts concrete synthetic
fixture dependencies and exposes no production source, activation, or serve
entrypoint.
"""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from wiki_spike.applications.fixture_capture_service import FixtureCaptureService
from wiki_spike.connectors import (
    ClaudeMemoryBankFixtureConnector,
    CodexFixtureConnector,
    FixtureConnectorReader,
    GitFixtureConnector,
    MarkdownFixtureConnector,
)
from wiki_spike.infrastructure.fixture_capture_clients import (
    FixtureCaptureClients,
    FixtureNativeMappingSealer,
    ReadOnlyMigrationCapability,
)
from wiki_spike.infrastructure.lifecycle_db import EncryptedCapturePersistence, LifecycleDatabase
from wiki_spike.memory_core.second_brain_capture_contracts import NonServingCaptureCohortV1


_SOURCE_CONNECTORS: tuple[tuple[str, type[FixtureConnectorReader]], ...] = (
    ("Codex", CodexFixtureConnector),
    ("Claude/Memory Bank", ClaudeMemoryBankFixtureConnector),
    ("Git", GitFixtureConnector),
    ("Markdown", MarkdownFixtureConnector),
)


class CaptureCompositionError(ValueError):
    """The explicit synthetic Stage-2 composition inputs are invalid."""


@dataclass(frozen=True)
class NonServingFixtureCaptureComposition:
    """The closed, fixture-only Stage-2 object graph."""

    database: LifecycleDatabase
    persistence: EncryptedCapturePersistence
    fixture_clients: FixtureCaptureClients
    native_mapping_sealer: FixtureNativeMappingSealer
    connectors: Mapping[str, FixtureConnectorReader]
    capture_service: FixtureCaptureService
    read_only_migration_capabilities: Mapping[str, ReadOnlyMigrationCapability]

    def record_non_serving_cohort(self, cohort: NonServingCaptureCohortV1) -> None:
        """Persist only the frozen non-serving cohort contract."""
        if not isinstance(cohort, NonServingCaptureCohortV1):
            raise CaptureCompositionError("Stage-2 composition accepts only NON_SERVING capture cohorts")
        self.capture_service.record_final_non_serving_cohort(cohort)


def compose_non_serving_fixture_capture(
    *,
    database: LifecycleDatabase,
    fixture_clients: FixtureCaptureClients,
    native_mapping_sealer: FixtureNativeMappingSealer,
    fixture_request_refs: Mapping[str, Sequence[str]],
    read_only_migration_capabilities: Mapping[str, ReadOnlyMigrationCapability],
) -> NonServingFixtureCaptureComposition:
    """Construct the four-source, inert fixture graph from explicit test inputs."""
    if not isinstance(database, LifecycleDatabase):
        raise CaptureCompositionError("an initialized synthetic LifecycleDatabase is required")
    if database.con is None:
        raise CaptureCompositionError("synthetic LifecycleDatabase must be initialized")
    if not isinstance(fixture_clients, FixtureCaptureClients):
        raise CaptureCompositionError("synthetic FixtureCaptureClients are required")
    if not isinstance(native_mapping_sealer, FixtureNativeMappingSealer):
        raise CaptureCompositionError("synthetic FixtureNativeMappingSealer is required")
    if set(fixture_request_refs) != {profile for profile, _ in _SOURCE_CONNECTORS}:
        raise CaptureCompositionError("fixture request references must cover exactly the four Stage-2 source profiles")

    capabilities = dict(read_only_migration_capabilities)
    for migration_ref, capability in capabilities.items():
        if not isinstance(migration_ref, str):
            raise CaptureCompositionError("migration capability references must be strings")
        fixture_clients.verify_read_only_migration_capability(capability, migration_ref)

    connectors = {
        profile: connector_type(fixture_clients, native_mapping_sealer, fixture_request_refs[profile])
        for profile, connector_type in _SOURCE_CONNECTORS
    }
    persistence = EncryptedCapturePersistence(database)
    return NonServingFixtureCaptureComposition(
        database=database,
        persistence=persistence,
        fixture_clients=fixture_clients,
        native_mapping_sealer=native_mapping_sealer,
        connectors=MappingProxyType(connectors),
        capture_service=FixtureCaptureService(persistence, fixture_clients),
        read_only_migration_capabilities=MappingProxyType(capabilities),
    )


__all__ = [
    "CaptureCompositionError",
    "NonServingFixtureCaptureComposition",
    "compose_non_serving_fixture_capture",
]
