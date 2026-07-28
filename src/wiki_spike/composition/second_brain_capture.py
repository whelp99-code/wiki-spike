"""Explicit synthetic-only composition for inert Stage-2 capture."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from wiki_spike.applications.fixture_capture_service import FixtureCaptureService
from wiki_spike.connectors import ClaudeMemoryBankFixtureConnector, CodexFixtureConnector, FixtureConnectorReader, GitFixtureConnector, MarkdownFixtureConnector
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients, FixtureEncryptedContentSealer, FixtureNativeMappingSealer, ReadOnlyMigrationCapability
from wiki_spike.infrastructure.lifecycle_db import EncryptedCapturePersistence, FixtureCaptureLifecycleDatabase
from wiki_spike.memory_core.second_brain_capture import SourceScopeRefV1, canonical_identity_body_digest

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
    migration_capability_registry: Mapping[str, ReadOnlyMigrationCapability]


def compose_non_serving_fixture_capture(
    *, database: FixtureCaptureLifecycleDatabase, cas: EncryptedContentStore, encryption_key: bytes,
    fixture_clients: FixtureCaptureClients, fixture_request_refs: Mapping[str, Sequence[str]],
    migration_capability_registry: Mapping[str, ReadOnlyMigrationCapability],
) -> NonServingFixtureCaptureComposition:
    """Wire only explicit synthetic dependencies to the non-serving aggregate path."""
    if not isinstance(database, FixtureCaptureLifecycleDatabase) or database.con is None or not database.fixture_capture_mode:
        raise CaptureCompositionError("fixture composition requires an initialized explicit synthetic database")
    if not isinstance(cas, EncryptedContentStore) or not isinstance(fixture_clients, FixtureCaptureClients) or len(encryption_key) != 32:
        raise CaptureCompositionError("explicit encrypted synthetic dependencies are required")
    if set(fixture_request_refs) != {profile for profile, _ in _SOURCE_CONNECTORS}:
        raise CaptureCompositionError("fixture request references must cover exactly the four Stage-2 source profiles")
    registry: dict[str, ReadOnlyMigrationCapability] = {}
    for registration_identity, capability in migration_capability_registry.items():
        if not isinstance(registration_identity, str) or not isinstance(capability, ReadOnlyMigrationCapability):
            raise CaptureCompositionError("migration capability registry must contain registration identities and issued capabilities")
        canonical_scope = capability.scope.to_mapping()
        expected_identity = canonical_identity_body_digest(
            "migration-registration-identity-v1",
            {"migration_ref": capability.migration_ref, "scope": canonical_scope},
        )
        if (registration_identity != expected_identity
                or capability.migration_registration_identity != expected_identity):
            raise CaptureCompositionError("migration capability registry key must exactly match its registration binding")
        try:
            fixture_clients.verify_read_only_migration_capability(
                capability, capability.migration_ref, SourceScopeRefV1.from_mapping(canonical_scope)
            )
        except Exception as exc:
            raise CaptureCompositionError("migration capability registry contains an invalid registration binding") from exc
        registry[registration_identity] = capability
    immutable_registry = MappingProxyType(registry)
    content_sealer = FixtureEncryptedContentSealer(database, cas, encryption_key)
    native_mapping_sealer = FixtureNativeMappingSealer(database, cas, encryption_key)
    connectors = {
        profile: connector(fixture_clients, content_sealer, native_mapping_sealer, fixture_request_refs[profile])
        for profile, connector in _SOURCE_CONNECTORS
    }
    persistence = EncryptedCapturePersistence(database, cas, encryption_key)
    capture_service = FixtureCaptureService(persistence, fixture_clients, immutable_registry)
    return NonServingFixtureCaptureComposition(
        persistence, MappingProxyType(connectors), capture_service, immutable_registry
    )
