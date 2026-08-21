"""Bind live-export plan digests to identity, mapping, and commitments."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from wiki_spike.applications.unified_db_export_authorization_checks import (
    bind_trusted_time,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
    parse_utc,
)
from wiki_spike.memory_core.unified_db_live_export_commitments import (
    UnifiedDbLiveExportAdapterV1,
    UnifiedDbLiveExportDestinationV1,
    UnifiedDbWriterQuiescenceV1,
)
from wiki_spike.memory_core.unified_db_live_export_mapping import (
    UnifiedDbLiveExportMappingV1,
)
from wiki_spike.memory_core.unified_db_live_export_plan import UnifiedDbLiveExportPlanV1
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)

MAX_IDENTITY_AGE: Final = timedelta(minutes=15)
_BUNDLE_FIELDS: Final = frozenset(
    {
        "identity",
        "mapping",
        "adapter",
        "destination",
        "quiescence",
        "plan",
        "authorization",
    }
)


@dataclass(frozen=True, slots=True)
class LiveExportVerifyRequestV1:
    identity: PostgresIdentityReceiptV1
    mapping: UnifiedDbLiveExportMappingV1
    adapter: UnifiedDbLiveExportAdapterV1
    destination: UnifiedDbLiveExportDestinationV1
    quiescence: UnifiedDbWriterQuiescenceV1
    plan: UnifiedDbLiveExportPlanV1
    authorization: UnifiedDbExportOnlyAuthorizationV1

    @classmethod
    def from_mappings(
            cls, bundle: Mapping[str, Mapping[str, JsonValue]]
        ) -> LiveExportVerifyRequestV1:
            missing = _BUNDLE_FIELDS - set(bundle)
            if missing:
                raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
            unexpected = set(bundle) - _BUNDLE_FIELDS
            if unexpected:
                raise InvalidContractValue(f"unexpected fields: {sorted(unexpected)}")
            return cls(
                PostgresIdentityReceiptV1.from_mapping(bundle["identity"]),
                UnifiedDbLiveExportMappingV1.from_mapping(bundle["mapping"]),
                UnifiedDbLiveExportAdapterV1.from_mapping(bundle["adapter"]),
                UnifiedDbLiveExportDestinationV1.from_mapping(bundle["destination"]),
                UnifiedDbWriterQuiescenceV1.from_mapping(bundle["quiescence"]),
                UnifiedDbLiveExportPlanV1.from_mapping(bundle["plan"]),
                UnifiedDbExportOnlyAuthorizationV1.from_mapping(bundle["authorization"]),
            )


def verify_live_export_plan(request: LiveExportVerifyRequestV1, now: datetime) -> None:
    _reject_stale_evidence(request, now)
    _require_equal(
        request.identity.identity_digest,
        request.plan.source_identity_digest,
        "source identity does not match the plan",
    )
    _require_equal(
        request.identity.identity_digest,
        request.mapping.source_identity_digest,
        "source identity does not match the mapping",
    )
    _require_equal(
        request.identity.identity_digest,
        request.quiescence.source_identity_digest,
        "source identity does not match the quiescence proof",
    )
    _require_equal(
        request.identity.catalog_digest,
        request.plan.catalog_digest,
        "catalog digest does not match the plan",
    )
    _require_equal(
        request.mapping.mapping_digest,
        request.plan.mapping_digest,
        "mapping digest does not match the plan",
    )
    _require_equal(
        request.adapter.adapter_digest,
        request.plan.adapter_digest,
        "adapter digest does not match the plan",
    )
    _require_equal(
        request.destination.destination_digest,
        request.plan.destination_digest,
        "destination digest does not match the plan",
    )
    _require_equal(
        request.quiescence.quiescence_digest,
        request.plan.quiescence_digest,
        "quiescence digest does not match the plan",
    )
    _require_equal(
        request.mapping.mapper_id,
        request.plan.mapper_id,
        "mapper identity does not match the plan",
    )
    _require_equal(
        request.mapping.mapper_version,
        request.plan.mapper_version,
        "mapper version does not match the plan",
    )
    _require_equal(
        request.mapping.select_template_digest,
        request.adapter.select_template_digest,
        "select template digest does not match the adapter",
    )
    bind_trusted_time(request.authorization, now)
    _bind_authorization(request)


def _bind_authorization(request: LiveExportVerifyRequestV1) -> None:
    authorization = request.authorization
    plan = request.plan
    _require_equal(
        authorization.plan_digest,
        plan.plan_digest,
        "plan digest does not match the authorization",
    )
    _require_equal(
        authorization.mapping_digest,
        plan.mapping_digest,
        "mapping digest does not match the authorization",
    )
    _require_equal(
        authorization.adapter_digest,
        plan.adapter_digest,
        "adapter digest does not match the authorization",
    )
    _require_equal(
        authorization.destination_digest,
        plan.destination_digest,
        "destination digest does not match the authorization",
    )
    _require_equal(
        authorization.profile_digest,
        plan.profile_digest,
        "profile digest does not match the authorization",
    )
    _require_equal(
        authorization.authorization_kind,
        plan.authorization_kind,
        "authorization kind does not match the plan",
    )


def _reject_stale_evidence(
    request: LiveExportVerifyRequestV1, now: datetime
) -> None:
    if now.utcoffset() is None:
        raise InvalidContractValue("trusted now must carry a timezone utcoffset")
    current = now.astimezone(UTC)
    evidence = (
        ("identity", request.identity.captured_at),
        ("quiescence", request.quiescence.captured_at),
    )
    for label, captured_at in evidence:
        captured = parse_utc(captured_at, "captured_at")
        if captured > current or current - captured > MAX_IDENTITY_AGE:
            raise InvalidContractValue(f"{label} is stale")


def _require_equal(actual: str, expected: str, message: str) -> None:
    if actual != expected:
        raise InvalidContractValue(message)
