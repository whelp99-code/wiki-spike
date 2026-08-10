"""Explicit synthetic-only composition for inert Stage-2 capture."""
from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Sequence

from wiki_spike.applications.fixture_capture_service import FixtureCaptureService
from wiki_spike.connectors import ClaudeMemoryBankFixtureConnector, CodexFixtureConnector, FixtureConnectorReader, GitFixtureConnector, MarkdownFixtureConnector
from wiki_spike.connectors.claude_memory_bank import ClaudeMemoryBankLiveSourceAdapter
from wiki_spike.connectors.codex import CodexLiveSourceAdapter
from wiki_spike.connectors.git import GitLiveSourceAdapter
from wiki_spike.connectors.markdown import MarkdownLiveSourceAdapter
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients, FixtureEncryptedContentSealer, FixtureNativeMappingSealer, ReadOnlyMigrationCapability
from wiki_spike.infrastructure.lifecycle_db import EncryptedCapturePersistence, FixtureCaptureLifecycleDatabase
from wiki_spike.memory_core.second_brain_capture import SourceScopeRefV1, canonical_identity_body_digest
from wiki_spike.memory_core.second_brain_ports import (
    CredentialProviderPort,
    FilesystemSourceClientPort,
    SourceApiClientPort,
    SourceReaderPort,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
    require_security_context_authority,
)

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


@dataclass(frozen=True)
class NonAuthorizingLiveSourceComposition:
    """Typed reader graph only. It has neither a capture path nor activation surface."""

    readers: Mapping[str, SourceReaderPort]
    live_operation_authorized: bool = False


def compose_non_authorizing_live_source_adapters(
    *, security_authority: SecurityContextAuthority | None,
    codex_api_client: SourceApiClientPort | None = None,
    claude_memory_bank_api_client: SourceApiClientPort | None = None,
    git_filesystem_client: FilesystemSourceClientPort | None = None,
    markdown_filesystem_client: FilesystemSourceClientPort | None = None,
    credential_providers: Mapping[str, CredentialProviderPort],
) -> NonAuthorizingLiveSourceComposition:
    """Inject only Stage-0-enabled readers; this graph remains non-authorizing."""
    profiles = ("Codex", "Claude/Memory Bank", "Git", "Markdown")
    try:
        # Reuses the existing revalidating Stage-0 aggregate/trust authority.
        require_security_context_authority(security_authority)
    except Exception as exc:
        raise CaptureCompositionError("a resolved trusted Stage-0 security authority is required") from exc
    supplied = {
        "Codex": codex_api_client, "Claude/Memory Bank": claude_memory_bank_api_client,
        "Git": git_filesystem_client, "Markdown": markdown_filesystem_client,
    }
    enabled: list[str] = []
    for profile in profiles:
        try:
            require_security_context_authority(security_authority, scope_kind="source_profile", scope_name=profile)
        except Exception:
            if supplied[profile] is not None or profile in credential_providers:
                raise CaptureCompositionError("disabled source profiles must not receive clients or credential providers")
        else:
            enabled.append(profile)
    if set(credential_providers) != set(enabled) or not all(
        isinstance(provider, CredentialProviderPort) for provider in credential_providers.values()
    ):
        raise CaptureCompositionError("each enabled source profile requires exactly one typed credential provider")
    if any(supplied[profile] is None for profile in enabled):
        raise CaptureCompositionError("each enabled source profile requires exactly one explicit low-level client")
    readers: dict[str, SourceReaderPort] = {}
    if "Codex" in enabled:
        readers["Codex"] = CodexLiveSourceAdapter(api_client=codex_api_client, credential_provider=credential_providers["Codex"], security_authority=security_authority)  # type: ignore[arg-type]
    if "Claude/Memory Bank" in enabled:
        readers["Claude/Memory Bank"] = ClaudeMemoryBankLiveSourceAdapter(api_client=claude_memory_bank_api_client, credential_provider=credential_providers["Claude/Memory Bank"], security_authority=security_authority)  # type: ignore[arg-type]
    if "Git" in enabled:
        readers["Git"] = GitLiveSourceAdapter(filesystem_client=git_filesystem_client, credential_provider=credential_providers["Git"], security_authority=security_authority)  # type: ignore[arg-type]
    if "Markdown" in enabled:
        readers["Markdown"] = MarkdownLiveSourceAdapter(filesystem_client=markdown_filesystem_client, credential_provider=credential_providers["Markdown"], security_authority=security_authority)  # type: ignore[arg-type]
    return NonAuthorizingLiveSourceComposition(MappingProxyType(readers), False)


# Explicit alias for callers that describe this wiring by outcome rather than its guard.
compose_live_source_adapters = compose_non_authorizing_live_source_adapters


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
