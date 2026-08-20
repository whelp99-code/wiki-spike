"""Verify and emit a user-reviewable PostgreSQL capture plan."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_export_authorization import parse_utc
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_plan import (
    CAPTURE_PLAN_DOMAIN,
    CAPTURE_PLAN_VERSION,
    PostgresCapturePlanV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)

MAX_CAPTURE_AGE: Final = timedelta(minutes=15)
_BUNDLE_FIELDS: Final = frozenset({"query_manifest", "identity", "catalog", "plan"})


@dataclass(frozen=True, slots=True)
class CapturePlanRequestV1:
    query_manifest: PostgresCaptureQueryManifestV1
    identity: PostgresIdentityReceiptV1
    catalog: PostgresCatalogSnapshotV1


@dataclass(frozen=True, slots=True)
class CaptureVerifyRequestV1:
    query_manifest: PostgresCaptureQueryManifestV1
    identity: PostgresIdentityReceiptV1
    catalog: PostgresCatalogSnapshotV1
    plan: PostgresCapturePlanV1

    @classmethod
    def from_mappings(
        cls, bundle: Mapping[str, Mapping[str, JsonValue]]
    ) -> CaptureVerifyRequestV1:
        missing = _BUNDLE_FIELDS - set(bundle)
        if missing:
            raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
        unexpected = set(bundle) - _BUNDLE_FIELDS
        if unexpected:
            raise InvalidContractValue(f"unexpected fields: {sorted(unexpected)}")
        return cls(
            PostgresCaptureQueryManifestV1.from_mapping(bundle["query_manifest"]),
            PostgresIdentityReceiptV1.from_mapping(bundle["identity"]),
            PostgresCatalogSnapshotV1.from_mapping(bundle["catalog"]),
            PostgresCapturePlanV1.from_mapping(bundle["plan"]),
        )


def plan_postgres_identity_capture(
    request: CapturePlanRequestV1, now: datetime
) -> PostgresCapturePlanV1:
    _reject_stale(request.identity.captured_at, now)
    _require_equal(
        request.identity.catalog_digest,
        request.catalog.catalog_digest,
        "catalog digest does not match identity",
    )
    body: dict[str, JsonValue] = {
        "plan_version": CAPTURE_PLAN_VERSION,
        "source_name": "unified-db",
        "query_manifest_digest": request.query_manifest.manifest_digest,
        "system_identifier": request.identity.system_identifier,
        "database_oid": request.identity.database_oid,
        "server_version_num": request.identity.server_version_num,
        "catalog_digest": request.catalog.catalog_digest,
        "captured_at": request.identity.captured_at,
    }
    return PostgresCapturePlanV1.from_mapping(
        body | {"plan_digest": canonical_ledger_digest(CAPTURE_PLAN_DOMAIN, body)}
    )


def verify_postgres_capture_plan(request: CaptureVerifyRequestV1, now: datetime) -> None:
    _reject_stale(request.identity.captured_at, now)
    _reject_stale(request.plan.captured_at, now)
    _require_equal(
        request.plan.query_manifest_digest,
        request.query_manifest.manifest_digest,
        "query manifest digest does not match the plan",
    )
    _require_equal(
        request.plan.catalog_digest,
        request.catalog.catalog_digest,
        "catalog digest does not match the plan",
    )
    _require_equal(
        request.identity.catalog_digest,
        request.catalog.catalog_digest,
        "catalog digest does not match identity",
    )
    _require_equal(
        request.plan.system_identifier,
        request.identity.system_identifier,
        "system identifier does not match the plan",
    )
    _require_equal(
        request.plan.database_oid,
        request.identity.database_oid,
        "database oid does not match the plan",
    )
    _require_equal(
        request.plan.server_version_num,
        request.identity.server_version_num,
        "server version does not match the plan",
    )
    _require_equal(
        request.plan.captured_at,
        request.identity.captured_at,
        "captured_at does not match the plan",
    )


def _reject_stale(captured_at: str, now: datetime) -> None:
    if now.utcoffset() is None:
        raise InvalidContractValue("trusted now must carry a timezone utcoffset")
    current = now.astimezone(UTC)
    captured = parse_utc(captured_at, "captured_at")
    if captured > current or current - captured > MAX_CAPTURE_AGE:
        raise InvalidContractValue("identity is stale")


def _require_equal(actual: str, expected: str, message: str) -> None:
    if actual != expected:
        raise InvalidContractValue(message)
