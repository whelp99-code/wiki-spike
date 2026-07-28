"""Explicit synthetic-only composition for inert Stage-2 capture."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from wiki_spike.applications.fixture_capture_service import FixtureCaptureService
from wiki_spike.connectors import ClaudeMemoryBankFixtureConnector, CodexFixtureConnector, FixtureConnectorReader, GitFixtureConnector, MarkdownFixtureConnector
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients, FixtureNativeMappingSealer, ReadOnlyMigrationCapability
from wiki_spike.infrastructure.lifecycle_db import EncryptedCapturePersistence, LifecycleDatabase

_SOURCE_CONNECTORS: tuple[tuple[str, type[FixtureConnectorReader]], ...] = (
    ("Codex", CodexFixtureConnector), ("Claude/Memory Bank", ClaudeMemoryBankFixtureConnector),
    ("Git", GitFixtureConnector), ("Markdown", MarkdownFixtureConnector),
)


class CaptureCompositionError(ValueError):
    pass


@dataclass(frozen=True)
class NonServingFixtureCaptureComposition:
    """Closed synthetic graph; it exposes no production registration or serving."""
    persistence: EncryptedCapturePersistence
    connectors: Mapping[str, FixtureConnectorReader]
    capture_service: FixtureCaptureService
    read_only_migration_capabilities: Mapping[str, ReadOnlyMigrationCapability]


def compose_non_serving_fixture_capture(
    *, database: LifecycleDatabase, cas: EncryptedContentStore, encryption_key: bytes,
    fixture_clients: FixtureCaptureClients, fixture_request_refs: Mapping[str, Sequence[str]],
    read_only_migration_capabilities: Mapping[str, ReadOnlyMigrationCapability],
) -> NonServingFixtureCaptureComposition:
    """Wire only explicit synthetic dependencies to the non-serving aggregate path."""
    if not isinstance(database, LifecycleDatabase) or database.con is None or not database.fixture_capture_mode:
        raise CaptureCompositionError("fixture composition requires an initialized explicit synthetic database")
    if not isinstance(cas, EncryptedContentStore) or not isinstance(fixture_clients, FixtureCaptureClients) or len(encryption_key) != 32:
        raise CaptureCompositionError("explicit encrypted synthetic dependencies are required")
    if set(fixture_request_refs) != {profile for profile, _ in _SOURCE_CONNECTORS}:
        raise CaptureCompositionError("fixture request references must cover exactly the four Stage-2 source profiles")
    capabilities = dict(read_only_migration_capabilities)
    connectors = {profile: connector(fixture_clients, FixtureNativeMappingSealer(cas, encryption_key), fixture_request_refs[profile]) for profile, connector in _SOURCE_CONNECTORS}
    persistence = EncryptedCapturePersistence(database, cas, encryption_key)
    return NonServingFixtureCaptureComposition(persistence, MappingProxyType(connectors), FixtureCaptureService(persistence, fixture_clients), MappingProxyType(capabilities))
