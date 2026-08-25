"""Resolver-verified production import gate bound to trusted DB-03 GO authority.

An in-process resolver mints a non-serializable ``VerifiedMigrationImportAuthorityV1``
only after exact joins of: a fully RESOLVED Stage-0 scope, a trusted DB-03
revision-2 GO decision for the source, live (non-fixture) export evidence, an
immutable snapshot/discovery/certificate package, and an encrypted persistence
profile already bound to live storage. The authority type cannot be constructed
from JSON or a mapping, and it can only be minted by this resolver.

The gate then invokes the existing #83 fixture/persistence mechanism
(``wiki_spike.applications.source_import_service.SourceImportService``)
unmodified and wraps its receipt with resolver-verified evidence. The result
always stays ``READY_NON_SERVING`` / ``serving_promoted=False`` /
``cutover_eligible=False``: this gate never serves or cuts over.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import final

from wiki_spike.infrastructure.persistence_profile import VerifiedPersistenceProfile
from wiki_spike.memory_core.production_migration_import_contracts import (
    PRODUCTION_MIGRATION_SOURCE,
    TRUSTED_DB03_REVISION,
    ImmutableMigrationPackageV1,
    LiveExportEvidenceV1,
    ProductionMigrationImportReceiptV1,
    instant_in_half_open_window,
)
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNING_DOMAIN,
    ContractResolutionV1,
    DecisionRecordV1,
    TrustedDecisionKeyBindingsV1,
)
from wiki_spike.memory_core.second_brain_product_release import resolved_scope_digest
from wiki_spike.memory_core.snapshot_import import (
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
)
from wiki_spike.memory_core.snapshot_import_parse import import_namespace
from wiki_spike.memory_core.source_discovery import SourceDiscoveryManifestV1

from .source_import_service import SourceImportService

__all__ = (
    "ProductionImportAuthorityError",
    "ProductionMigrationImportGate",
    "VerifiedMigrationImportAuthorityV1",
    "resolve_migration_import_authority",
)


class ProductionImportAuthorityError(ValueError):
    """The production migration import authority could not be minted or bound."""


class _AuthorityMint:
    __slots__ = ()


_AUTHORITY_MINT = _AuthorityMint()


@final
class VerifiedMigrationImportAuthorityV1:
    """Non-serializable, resolver-minted authority for one exact migration import.

    There is deliberately no ``from_mapping``/``from_dict``/``__init__`` path
    that accepts caller-supplied JSON: the sole constructor requires the
    private mint token that only ``resolve_migration_import_authority`` holds,
    and the instance cannot be copied, pickled, or otherwise serialized.
    """

    __slots__ = (
        "__discovery_manifest_digest",
        "__evidence_digest",
        "__mint",
        "__package_digest",
        "__profile_digest",
        "__resolved_scope_digest",
        "__snapshot_digest",
        "__source_name",
        "__target_namespace",
    )

    def __init__(
        self,
        mint: _AuthorityMint,
        source_name: str,
        target_namespace: str,
        scope_digest: str,
        snapshot_digest: str,
        discovery_manifest_digest: str,
        package_digest: str,
        evidence_digest: str,
        profile_digest: str,
    ) -> None:
        if mint is not _AUTHORITY_MINT:
            raise ProductionImportAuthorityError(
                "verified migration import authority must be minted by the resolver"
            )
        self.__mint = mint
        self.__source_name = source_name
        self.__target_namespace = target_namespace
        self.__resolved_scope_digest = scope_digest
        self.__snapshot_digest = snapshot_digest
        self.__discovery_manifest_digest = discovery_manifest_digest
        self.__package_digest = package_digest
        self.__evidence_digest = evidence_digest
        self.__profile_digest = profile_digest

    @property
    def source_name(self) -> str:
        return self.__source_name

    @property
    def target_namespace(self) -> str:
        return self.__target_namespace

    @property
    def resolved_scope_digest(self) -> str:
        return self.__resolved_scope_digest

    @property
    def snapshot_digest(self) -> str:
        return self.__snapshot_digest

    @property
    def discovery_manifest_digest(self) -> str:
        return self.__discovery_manifest_digest

    @property
    def package_digest(self) -> str:
        return self.__package_digest

    @property
    def evidence_digest(self) -> str:
        return self.__evidence_digest

    @property
    def profile_digest(self) -> str:
        return self.__profile_digest

    def __copy__(self) -> VerifiedMigrationImportAuthorityV1:
        raise ProductionImportAuthorityError(
            "verified migration import authority cannot be copied"
        )

    def __deepcopy__(self, memo: dict[int, object]) -> VerifiedMigrationImportAuthorityV1:
        _ = memo
        raise ProductionImportAuthorityError(
            "verified migration import authority cannot be copied"
        )

    def __reduce__(self) -> str | tuple[object, ...]:
        raise TypeError("verified migration import authority cannot be serialized")


def resolve_migration_import_authority(
    *,
    contract_resolution: ContractResolutionV1,
    db03_decision: DecisionRecordV1,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    live_evidence: LiveExportEvidenceV1,
    package: ImmutableMigrationPackageV1,
    persistence_profile: VerifiedPersistenceProfile,
    request: SnapshotImportRequestV1,
    now: datetime,
    source_name: str = PRODUCTION_MIGRATION_SOURCE,
) -> VerifiedMigrationImportAuthorityV1:
    """Mint the production import authority only after every exact join passes.

    Every check below runs purely in memory before any database or CAS
    mutation is possible: this function never touches the store.
    """
    if source_name != PRODUCTION_MIGRATION_SOURCE:
        raise ProductionImportAuthorityError(
            "the production import gate only authorizes the unified-db migration source"
        )
    if type(request) is not SnapshotImportRequestV1:
        raise ProductionImportAuthorityError("an exact snapshot import request is required")
    if (
        request.source_name != source_name
        or request.target_namespace != import_namespace(source_name)
    ):
        raise ProductionImportAuthorityError("non-unified import namespace")
    if request.serving_promotion_requested is not False:
        raise ProductionImportAuthorityError("serving promotion is refused")

    if type(contract_resolution) is not ContractResolutionV1:
        raise ProductionImportAuthorityError(
            "an exact resolved Stage-0 contract resolution is required"
        )
    if contract_resolution.outcome != "RESOLVED" or contract_resolution.contract is None:
        raise ProductionImportAuthorityError("Stage-0 scope is not fully RESOLVED")
    contract = contract_resolution.contract

    if request.resolved_scope_digest != resolved_scope_digest(contract.resolved_scope):
        raise ProductionImportAuthorityError("forged or bare resolved_scope_digest")

    scope = contract.resolved_scope
    if source_name not in scope.enabled_migration_sources or source_name in dict(
        scope.disabled_migration_sources
    ):
        raise ProductionImportAuthorityError(
            "migration source is absent from the enabled inventory"
        )

    if type(db03_decision) is not DecisionRecordV1:
        raise ProductionImportAuthorityError("an exact DB-03 decision record is required")
    if (
        db03_decision.decision_id,
        db03_decision.scope_kind,
        db03_decision.scope_name,
    ) != ("DB-03", "migration_source", source_name):
        raise ProductionImportAuthorityError(
            "DB-03 decision does not scope the production migration source"
        )
    if db03_decision.outcome != "GO":
        raise ProductionImportAuthorityError("DB-03 is not a trusted GO decision")
    if db03_decision.record_revision != TRUSTED_DB03_REVISION:
        raise ProductionImportAuthorityError(
            "DB-03 must be at the trusted revision-2 reaffirmation"
        )
    try:
        DecisionRecordV1.from_mapping(db03_decision.to_mapping(), now=now)
    except ValueError as exc:
        raise ProductionImportAuthorityError(f"DB-03 decision is invalid or expired: {exc}") from exc

    binding = (
        db03_decision.decision_id,
        db03_decision.scope_kind,
        db03_decision.scope_name,
        db03_decision.digest,
    )
    if binding not in contract.decision_digests:
        raise ProductionImportAuthorityError(
            "DB-03 decision is not the one bound into the resolved contract"
        )

    if type(trusted_keys) is not TrustedDecisionKeyBindingsV1:
        raise ProductionImportAuthorityError("trusted DB-03 key bindings are required")
    if len(db03_decision.signatures) != 2 or tuple(
        signature.role for signature in db03_decision.signatures
    ) != ("approver", "owner"):
        raise ProductionImportAuthorityError("DB-03 signatures are malformed")
    payload = db03_decision.signing_payload()
    for signature in db03_decision.signatures:
        if not trusted_keys.matches_decision(db03_decision, signature) or not signature.verify(
            DECISION_SIGNING_DOMAIN, payload
        ):
            raise ProductionImportAuthorityError("DB-03 signature is not trusted")

    if type(live_evidence) is not LiveExportEvidenceV1:
        raise ProductionImportAuthorityError(
            "live export evidence must be a verified live-export record, not fixture evidence"
        )
    if live_evidence.source_name != source_name or live_evidence.live_export_authorized is not True:
        raise ProductionImportAuthorityError("live export evidence does not authorize this source")

    if type(package) is not ImmutableMigrationPackageV1:
        raise ProductionImportAuthorityError("an exact immutable migration package is required")
    if package.source_name != source_name:
        raise ProductionImportAuthorityError(
            "immutable package does not scope the production migration source"
        )
    if not (
        package.snapshot_digest == request.snapshot_digest == live_evidence.snapshot_digest
        and package.discovery_manifest_digest
        == request.discovery_manifest_digest
        == live_evidence.discovery_manifest_digest
        and package.package_digest == live_evidence.package_digest
    ):
        raise ProductionImportAuthorityError(
            "package, snapshot, and evidence digests must match exactly"
        )

    now_text = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not instant_in_half_open_window(now_text, live_evidence.captured_at, live_evidence.expires_at):
        raise ProductionImportAuthorityError("live export evidence is not fresh")

    if type(persistence_profile) is not VerifiedPersistenceProfile:
        raise ProductionImportAuthorityError(
            "an exact verified encrypted persistence profile is required"
        )
    if not persistence_profile.serving_ready:
        raise ProductionImportAuthorityError(
            "encrypted persistence profile is not bound to live storage"
        )

    return VerifiedMigrationImportAuthorityV1(
        _AUTHORITY_MINT,
        source_name,
        request.target_namespace,
        request.resolved_scope_digest,
        request.snapshot_digest,
        request.discovery_manifest_digest,
        package.package_digest,
        live_evidence.evidence_digest,
        persistence_profile.profile_digest,
    )


class ProductionMigrationImportGate:
    """Binds a resolver-minted authority to the existing #83 persistence mechanism."""

    def __init__(self, service: SourceImportService) -> None:
        if type(service) is not SourceImportService:
            raise ProductionImportAuthorityError("an exact SourceImportService is required")
        self._service = service

    def import_verified_migration(
        self,
        authority: VerifiedMigrationImportAuthorityV1,
        request: SnapshotImportRequestV1,
        snapshot: BoundedSnapshotV1,
        discovery: SourceDiscoveryManifestV1,
    ) -> ProductionMigrationImportReceiptV1:
        if type(authority) is not VerifiedMigrationImportAuthorityV1:
            raise ProductionImportAuthorityError("an exact resolver-minted authority is required")
        if (
            authority.source_name != request.source_name
            or authority.target_namespace != request.target_namespace
            or authority.resolved_scope_digest != request.resolved_scope_digest
            or authority.snapshot_digest != request.snapshot_digest
            or authority.discovery_manifest_digest != request.discovery_manifest_digest
        ):
            raise ProductionImportAuthorityError(
                "authority does not bind this exact import request"
            )
        underlying = self._service.import_snapshot(request, snapshot, discovery)
        return ProductionMigrationImportReceiptV1.create(
            underlying=underlying,
            resolved_scope_digest=authority.resolved_scope_digest,
            package_digest=authority.package_digest,
            evidence_digest=authority.evidence_digest,
        )
