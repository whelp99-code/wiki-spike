"""Dict builders for body-free live-export identity, mapping, and plan tests."""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from tests.second_brain.unified_db_export_authorization_support import (
    SCRIPT,
    authorization_body,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest

IDENTITY_VERSION = "second-brain-unified-db-postgres-identity-v1"
IDENTITY_DOMAIN = "unified-db-postgres-identity-v1"
CAPTURE_METHOD = "owner-produced-body-free"
CAPTURE_VERSION = "second-brain-unified-db-postgres-identity-capture-v1"
MAPPING_VERSION = "second-brain-unified-db-live-export-mapping-v1"
MAPPING_DOMAIN = "unified-db-live-export-mapping-v1"
ADAPTER_VERSION = "second-brain-unified-db-live-export-adapter-v1"
ADAPTER_DOMAIN = "unified-db-live-export-adapter-v1"
DESTINATION_VERSION = "second-brain-unified-db-live-export-destination-v1"
DESTINATION_DOMAIN = "unified-db-live-export-destination-v1"
QUIESCENCE_VERSION = "second-brain-unified-db-writer-quiescence-v1"
QUIESCENCE_DOMAIN = "unified-db-writer-quiescence-v1"
LIVE_PLAN_VERSION = "second-brain-unified-db-live-export-plan-v1"
LIVE_PLAN_DOMAIN = "unified-db-live-export-plan-v1"
DELETION_SEMANTICS = "EXPLICIT_TOMBSTONE_ONLY"
ABSENCE_POLICY = "ABSENCE_IS_NOT_DELETION"
MAPPER_ID = "unified-db-reviewed-notes"
MAPPER_VERSION = "v1"
TABLE = "public.notes"
COLUMNS = ("id", "revision", "content_sha256", "watermark", "is_tombstone")
SYSTEM_IDENTIFIER = "7234017283807667306"
DATABASE_OID = "16384"
SERVER_VERSION_NUM = "160004"
CATALOG_DIGEST = "aa" * 32
SELECT_TEMPLATE_DIGEST = "bb" * 32
PROFILE_DIGEST = "11" * 32
CAPTURED_AT = "2026-08-18T12:05:00Z"
NOW = datetime(2026, 8, 18, 12, 10, tzinfo=UTC)
STALE_CAPTURED_AT = "2026-08-18T11:50:00Z"
CONFORMANCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-live-export-plan-conformance-v1.schema.json"
)
CONFORMANCE_EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/"
    + "unified-db-live-export-plan-conformance-v1.json"
)
IDENTITY_SCHEMA = Path("schemas/second-brain/unified-db-postgres-identity-v1.schema.json")
MAPPING_SCHEMA = Path(
    "schemas/second-brain/unified-db-live-export-mapping-v1.schema.json"
)
ADAPTER_SCHEMA = Path(
    "schemas/second-brain/unified-db-live-export-adapter-v1.schema.json"
)
DESTINATION_SCHEMA = Path(
    "schemas/second-brain/unified-db-live-export-destination-v1.schema.json"
)
QUIESCENCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-writer-quiescence-v1.schema.json"
)
LIVE_PLAN_SCHEMA = Path("schemas/second-brain/unified-db-live-export-plan-v1.schema.json")


def _digest(domain: str, body: dict[str, JsonValue], field: str) -> dict[str, JsonValue]:
    unsigned = {key: value for key, value in body.items() if key != field}
    return unsigned | {field: canonical_ledger_digest(domain, unsigned)}


def identity_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "identity_version": IDENTITY_VERSION,
        "source_name": "unified-db",
        "system_identifier": SYSTEM_IDENTIFIER,
        "database_oid": DATABASE_OID,
        "server_version_num": SERVER_VERSION_NUM,
        "catalog_digest": CATALOG_DIGEST,
        "capture_method": CAPTURE_METHOD,
        "capture_version": CAPTURE_VERSION,
        "captured_at": CAPTURED_AT,
    }
    body.update(overrides)
    if "identity_digest" not in overrides:
        return _digest(IDENTITY_DOMAIN, body, "identity_digest")
    return body


def mapping_body(
    source_identity_digest: str, **overrides: JsonValue
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "mapping_version": MAPPING_VERSION,
        "mapper_id": MAPPER_ID,
        "mapper_version": MAPPER_VERSION,
        "source_name": "unified-db",
        "source_identity_digest": source_identity_digest,
        "table": TABLE,
        "columns": list(COLUMNS),
        "native_identity": "id",
        "revision": "revision",
        "content_hash": "content_sha256",
        "watermark": "watermark",
        "tombstone": "is_tombstone",
        "deletion_semantics": DELETION_SEMANTICS,
        "absence_policy": ABSENCE_POLICY,
        "select_template_digest": SELECT_TEMPLATE_DIGEST,
    }
    body.update(overrides)
    if "mapping_digest" not in overrides:
        return _digest(MAPPING_DOMAIN, body, "mapping_digest")
    return body


def adapter_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "adapter_version": ADAPTER_VERSION,
        "adapter_id": "unified-db-readonly-serializable-v1",
        "source_name": "unified-db",
        "isolation": "SERIALIZABLE",
        "read_only": True,
        "deferrable": True,
        "select_template_digest": SELECT_TEMPLATE_DIGEST,
    }
    body.update(overrides)
    if "adapter_digest" not in overrides:
        return _digest(ADAPTER_DOMAIN, body, "adapter_digest")
    return body


def destination_body(**overrides: JsonValue) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "destination_version": DESTINATION_VERSION,
        "destination_id": "local-package-tree-001",
        "commitment_kind": "LOCAL_PACKAGE_TREE",
        "path_policy": "create-only-exclusive",
        "import_requested": False,
        "serve_requested": False,
        "promote_requested": False,
        "cutover_requested": False,
    }
    body.update(overrides)
    if "destination_digest" not in overrides:
        return _digest(DESTINATION_DOMAIN, body, "destination_digest")
    return body


def quiescence_body(
    source_identity_digest: str, **overrides: JsonValue
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "quiescence_version": QUIESCENCE_VERSION,
        "source_identity_digest": source_identity_digest,
        "writer_count": "0",
        "quiesce_approved": True,
        "captured_at": CAPTURED_AT,
    }
    body.update(overrides)
    if "quiescence_digest" not in overrides:
        return _digest(QUIESCENCE_DOMAIN, body, "quiescence_digest")
    return body


def live_plan_body(
    parts: dict[str, dict[str, JsonValue]], **overrides: JsonValue
) -> dict[str, JsonValue]:
    identity = parts["identity"]
    mapping = parts["mapping"]
    body: dict[str, JsonValue] = {
        "plan_version": LIVE_PLAN_VERSION,
        "source_name": "unified-db",
        "operation": "EXPORT_ONLY",
        "authorization_kind": "LIVE_EXPORT_ONLY",
        "profile_digest": PROFILE_DIGEST,
        "source_identity_digest": identity["identity_digest"],
        "catalog_digest": identity["catalog_digest"],
        "mapper_id": mapping["mapper_id"],
        "mapper_version": mapping["mapper_version"],
        "mapping_digest": mapping["mapping_digest"],
        "adapter_digest": parts["adapter"]["adapter_digest"],
        "destination_digest": parts["destination"]["destination_digest"],
        "quiescence_digest": parts["quiescence"]["quiescence_digest"],
        "deletion_semantics": DELETION_SEMANTICS,
        "absence_policy": ABSENCE_POLICY,
    }
    body.update(overrides)
    if "plan_digest" not in overrides:
        return _digest(LIVE_PLAN_DOMAIN, body, "plan_digest")
    return body


def bound_authorization(plan: dict[str, JsonValue], **overrides: JsonValue) -> dict[str, JsonValue]:
    bound: dict[str, JsonValue] = {
        "plan_digest": plan["plan_digest"],
        "profile_digest": plan["profile_digest"],
        "mapping_digest": plan["mapping_digest"],
        "adapter_digest": plan["adapter_digest"],
        "destination_digest": plan["destination_digest"],
    }
    bound.update(overrides)
    return authorization_body(**bound)


def consistent_live_export_bundle() -> dict[str, dict[str, JsonValue]]:
    identity = identity_body()
    mapping = mapping_body(str(identity["identity_digest"]))
    adapter = adapter_body()
    destination = destination_body()
    quiescence = quiescence_body(str(identity["identity_digest"]))
    plan = live_plan_body(
        {
            "identity": identity,
            "mapping": mapping,
            "adapter": adapter,
            "destination": destination,
            "quiescence": quiescence,
        }
    )
    return {
        "identity": identity,
        "mapping": mapping,
        "adapter": adapter,
        "destination": destination,
        "quiescence": quiescence,
        "plan": plan,
        "authorization": bound_authorization(plan),
    }


__all__ = (
    "ABSENCE_POLICY",
    "ADAPTER_DOMAIN",
    "ADAPTER_SCHEMA",
    "ADAPTER_VERSION",
    "CAPTURED_AT",
    "CAPTURE_METHOD",
    "CAPTURE_VERSION",
    "CATALOG_DIGEST",
    "COLUMNS",
    "CONFORMANCE_EVIDENCE",
    "CONFORMANCE_SCHEMA",
    "DATABASE_OID",
    "DELETION_SEMANTICS",
    "DESTINATION_DOMAIN",
    "DESTINATION_SCHEMA",
    "DESTINATION_VERSION",
    "IDENTITY_DOMAIN",
    "IDENTITY_SCHEMA",
    "IDENTITY_VERSION",
    "LIVE_PLAN_DOMAIN",
    "LIVE_PLAN_SCHEMA",
    "LIVE_PLAN_VERSION",
    "MAPPER_ID",
    "MAPPER_VERSION",
    "MAPPING_DOMAIN",
    "MAPPING_SCHEMA",
    "MAPPING_VERSION",
    "NOW",
    "PROFILE_DIGEST",
    "QUIESCENCE_DOMAIN",
    "QUIESCENCE_SCHEMA",
    "QUIESCENCE_VERSION",
    "SCRIPT",
    "SELECT_TEMPLATE_DIGEST",
    "SERVER_VERSION_NUM",
    "STALE_CAPTURED_AT",
    "SYSTEM_IDENTIFIER",
    "TABLE",
    "adapter_body",
    "bound_authorization",
    "consistent_live_export_bundle",
    "destination_body",
    "identity_body",
    "live_plan_body",
    "mapping_body",
    "quiescence_body",
)
