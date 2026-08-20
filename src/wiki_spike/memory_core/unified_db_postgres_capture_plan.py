"""Capture-plan contract and identity receipt production from catalog metadata."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_export_authorization import parse_utc
from .unified_db_live_export_parse import (
    OID_MAX,
    UINT64_MAX,
    parse_canonical_uint,
    parse_server_version_num,
)
from .unified_db_postgres_identity import (
    CAPTURE_METHOD,
    CAPTURE_VERSION,
    IDENTITY_DOMAIN,
    IDENTITY_VERSION,
    PostgresIdentityReceiptV1,
)
from .unified_db_snapshot_export import parse_const

CAPTURE_PLAN_VERSION: Final = "second-brain-unified-db-postgres-capture-plan-v1"
CAPTURE_PLAN_DOMAIN: Final = "unified-db-postgres-capture-plan-v1"
_INPUT_FIELDS: Final = frozenset(
    {
        "system_identifier",
        "database_oid",
        "server_version_num",
        "catalog_digest",
        "captured_at",
    }
)
_PLAN_FIELDS: Final = frozenset(
    {
        "plan_version",
        "source_name",
        "query_manifest_digest",
        "system_identifier",
        "database_oid",
        "server_version_num",
        "catalog_digest",
        "captured_at",
        "plan_digest",
    }
)


@dataclass(frozen=True, slots=True)
class PostgresIdentityInputsV1:
    system_identifier: str
    database_oid: str
    server_version_num: str
    catalog_digest: str
    captured_at: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresIdentityInputsV1:
        strict_fields(data, _INPUT_FIELDS)
        _ = parse_utc(data["captured_at"], "captured_at")
        return cls(
            parse_canonical_uint(data["system_identifier"], "system_identifier", UINT64_MAX),
            parse_canonical_uint(data["database_oid"], "database_oid", OID_MAX),
            parse_server_version_num(data["server_version_num"], "server_version_num"),
            parse_digest(data["catalog_digest"], "catalog_digest"),
            parse_string(data["captured_at"], "captured_at"),
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "system_identifier": self.system_identifier,
            "database_oid": self.database_oid,
            "server_version_num": self.server_version_num,
            "catalog_digest": self.catalog_digest,
            "captured_at": self.captured_at,
        }


def produce_postgres_identity_receipt(
    inputs: PostgresIdentityInputsV1,
) -> PostgresIdentityReceiptV1:
    """Bind PostgresIdentityReceiptV1 to exactly the four metadata values."""
    body: dict[str, JsonValue] = {
        "identity_version": IDENTITY_VERSION,
        "source_name": "unified-db",
        "system_identifier": inputs.system_identifier,
        "database_oid": inputs.database_oid,
        "server_version_num": inputs.server_version_num,
        "catalog_digest": inputs.catalog_digest,
        "capture_method": CAPTURE_METHOD,
        "capture_version": CAPTURE_VERSION,
        "captured_at": inputs.captured_at,
    }
    return PostgresIdentityReceiptV1.from_mapping(
        body | {"identity_digest": canonical_ledger_digest(IDENTITY_DOMAIN, body)}
    )


@dataclass(frozen=True, slots=True)
class PostgresCapturePlanV1:
    plan_version: str
    source_name: str
    query_manifest_digest: str
    system_identifier: str
    database_oid: str
    server_version_num: str
    catalog_digest: str
    captured_at: str
    plan_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresCapturePlanV1:
        strict_fields(data, _PLAN_FIELDS)
        version = parse_string(data["plan_version"], "plan_version")
        if version != CAPTURE_PLAN_VERSION:
            raise UnsupportedContractVersion(f"unsupported plan_version: {version!r}")
        _ = parse_utc(data["captured_at"], "captured_at")
        parsed = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_digest(data["query_manifest_digest"], "query_manifest_digest"),
            parse_canonical_uint(data["system_identifier"], "system_identifier", UINT64_MAX),
            parse_canonical_uint(data["database_oid"], "database_oid", OID_MAX),
            parse_server_version_num(data["server_version_num"], "server_version_num"),
            parse_digest(data["catalog_digest"], "catalog_digest"),
            parse_string(data["captured_at"], "captured_at"),
            parse_digest(data["plan_digest"], "plan_digest"),
        )
        if parsed.plan_digest != parsed.computed_digest():
            raise InvalidContractValue("plan_digest does not bind plan fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["plan_digest"]
        return canonical_ledger_digest(CAPTURE_PLAN_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "plan_version": self.plan_version,
            "source_name": self.source_name,
            "query_manifest_digest": self.query_manifest_digest,
            "system_identifier": self.system_identifier,
            "database_oid": self.database_oid,
            "server_version_num": self.server_version_num,
            "catalog_digest": self.catalog_digest,
            "captured_at": self.captured_at,
            "plan_digest": self.plan_digest,
        }
