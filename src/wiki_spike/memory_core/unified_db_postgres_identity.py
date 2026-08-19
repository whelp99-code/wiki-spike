"""Canonical body-free PostgreSQL identity receipt."""
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
from .unified_db_snapshot_export import parse_const

IDENTITY_VERSION: Final = "second-brain-unified-db-postgres-identity-v1"
IDENTITY_DOMAIN: Final = "unified-db-postgres-identity-v1"
CAPTURE_METHOD: Final = "owner-produced-body-free"
CAPTURE_VERSION: Final = "second-brain-unified-db-postgres-identity-capture-v1"
_FIELDS: Final = frozenset(
    {
        "identity_version",
        "source_name",
        "system_identifier",
        "database_oid",
        "server_version_num",
        "catalog_digest",
        "capture_method",
        "capture_version",
        "captured_at",
        "identity_digest",
    }
)


@dataclass(frozen=True, slots=True)
class PostgresIdentityReceiptV1:
    identity_version: str
    source_name: str
    system_identifier: str
    database_oid: str
    server_version_num: str
    catalog_digest: str
    capture_method: str
    capture_version: str
    captured_at: str
    identity_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresIdentityReceiptV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["identity_version"], "identity_version")
        if version != IDENTITY_VERSION:
            raise UnsupportedContractVersion(f"unsupported identity_version: {version!r}")
        _ = parse_utc(data["captured_at"], "captured_at")
        parsed = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_canonical_uint(data["system_identifier"], "system_identifier", UINT64_MAX),
            parse_canonical_uint(data["database_oid"], "database_oid", OID_MAX),
            parse_server_version_num(data["server_version_num"], "server_version_num"),
            parse_digest(data["catalog_digest"], "catalog_digest"),
            parse_const(data["capture_method"], "capture_method", CAPTURE_METHOD),
            parse_const(data["capture_version"], "capture_version", CAPTURE_VERSION),
            parse_string(data["captured_at"], "captured_at"),
            parse_digest(data["identity_digest"], "identity_digest"),
        )
        if parsed.identity_digest != parsed.computed_digest():
            raise InvalidContractValue("identity_digest does not bind identity fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["identity_digest"]
        return canonical_ledger_digest(IDENTITY_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_version": self.identity_version,
            "source_name": self.source_name,
            "system_identifier": self.system_identifier,
            "database_oid": self.database_oid,
            "server_version_num": self.server_version_num,
            "catalog_digest": self.catalog_digest,
            "capture_method": self.capture_method,
            "capture_version": self.capture_version,
            "captured_at": self.captured_at,
            "identity_digest": self.identity_digest,
        }
