"""Claimed-only POSTGRES_METADATA_CAPTURE_ONLY executor against a catalog port."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from wiki_spike.applications.unified_db_export_authorization_publish import (
    publish_exclusive_bytes,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    ClaimedUnifiedDbMetadataCaptureAuthorityV1,
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
)
from wiki_spike.applications.unified_db_postgres_capture_verify import (
    CapturePlanRequestV1,
    plan_postgres_identity_capture,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
    enforce_create_only_destination,
)
from wiki_spike.memory_core.unified_db_postgres_capture_interpret import (
    interpret_closed_catalog_results,
)
from wiki_spike.memory_core.unified_db_postgres_capture_output import (
    CAPTURE_ARTIFACT_NAMES,
    PostgresMetadataCaptureOutputManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_plan import (
    PostgresCapturePlanV1,
    PostgresIdentityInputsV1,
    produce_postgres_identity_receipt,
)
from wiki_spike.memory_core.unified_db_postgres_capture_ports import (
    PostgresCatalogQueryPort,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    PostgresMetadataCaptureReceiptV1,
    bind_capture_receipt,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

type CaptureGrant = (
    ClaimedUnifiedDbMetadataCaptureAuthorityV1 | VerifiedUnifiedDbMetadataCaptureAuthorityV1
)


class PostgresMetadataCaptureService:
    """Run closed catalog capture only after a process-local claimed grant exists."""

    _catalog: PostgresCatalogQueryPort

    def __init__(self, catalog: PostgresCatalogQueryPort) -> None:
        self._catalog = catalog

    def capture(
        self,
        authority: CaptureGrant,
        now: datetime,
        *,
        dsn_fd: int | None = None,
    ) -> PostgresMetadataCaptureReceiptV1:
        _ = dsn_fd
        claimed = _require_claimed(authority)
        destination = claimed.authorization.destination
        enforce_create_only_destination(destination.destination_path)
        queries = PostgresCaptureQueryManifestV1.closed()
        if queries.manifest_digest != claimed.query_manifest_digest:
            raise InvalidContractValue("query manifest digest does not match authorization")
        tables = tuple(
            self._catalog.execute_closed_query(query.sql) for query in queries.queries
        )
        parsed = interpret_closed_catalog_results(queries.queries, tables)
        catalog = PostgresCatalogSnapshotV1.from_rows(parsed.rows)
        identity = produce_postgres_identity_receipt(
            PostgresIdentityInputsV1.from_mapping(
                {
                    "system_identifier": parsed.system_identifier,
                    "database_oid": parsed.database_oid,
                    "server_version_num": parsed.server_version_num,
                    "catalog_digest": catalog.catalog_digest,
                    "captured_at": _stamp(now),
                }
            )
        )
        plan = plan_postgres_identity_capture(
            CapturePlanRequestV1(queries, identity, catalog), now
        )
        files, receipt = _artifact_bytes(
            _CaptureBundle(destination, queries, catalog, identity, plan)
        )
        _write_tree(destination.destination_path, files)
        return receipt


def _require_claimed(authority: CaptureGrant) -> ClaimedUnifiedDbMetadataCaptureAuthorityV1:
    match authority:
        case ClaimedUnifiedDbMetadataCaptureAuthorityV1():
            return authority
        case VerifiedUnifiedDbMetadataCaptureAuthorityV1():
            raise UnifiedDbExportError("claimed metadata capture authority is required")


@dataclass(frozen=True, slots=True)
class _CaptureBundle:
    destination: PostgresMetadataCaptureDestinationV1
    queries: PostgresCaptureQueryManifestV1
    catalog: PostgresCatalogSnapshotV1
    identity: PostgresIdentityReceiptV1
    plan: PostgresCapturePlanV1


def _stamp(now: datetime) -> str:
    if now.utcoffset() is None:
        raise InvalidContractValue("trusted now must carry a timezone utcoffset")
    return now.astimezone(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def _artifact_bytes(
    bundle: _CaptureBundle,
) -> tuple[dict[str, bytes], PostgresMetadataCaptureReceiptV1]:
    files = {
        "capture-plan.json": canonical_bytes(bundle.plan.to_mapping()) + b"\n",
        "catalog.json": canonical_bytes(bundle.catalog.to_mapping()) + b"\n",
        "identity.json": canonical_bytes(bundle.identity.to_mapping()) + b"\n",
        "output-manifest.json": b"\n",
        "query-manifest.json": canonical_bytes(bundle.queries.to_mapping()) + b"\n",
        "receipt.json": b"\n",
    }
    manifest = PostgresMetadataCaptureOutputManifestV1.create(
        bundle.destination.destination_digest, files
    )
    receipt = PostgresMetadataCaptureReceiptV1.create(bundle.destination, manifest)
    bind_capture_receipt(bundle.destination, manifest, receipt)
    files["output-manifest.json"] = canonical_bytes(manifest.to_mapping()) + b"\n"
    files["receipt.json"] = canonical_bytes(receipt.to_mapping()) + b"\n"
    return files, receipt


def _write_tree(path: str, files: Mapping[str, bytes]) -> None:
    dest = Path(path)
    try:
        os.mkdir(dest, 0o700)
    except FileExistsError as exc:
        raise InvalidContractValue("destination already exists; overwrite refused") from exc
    for name in CAPTURE_ARTIFACT_NAMES:
        publish_exclusive_bytes(dest / name, files[name])
