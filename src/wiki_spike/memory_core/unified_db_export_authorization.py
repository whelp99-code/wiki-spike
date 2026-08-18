"""Strict unsigned LIVE_EXPORT_ONLY unified-db authorization body."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import (
    EXPORT_ONLY,
    parse_const,
    parse_false,
    parse_true,
)

AUTHORIZATION_VERSION: Final = "second-brain-unified-db-export-only-authorization-v1"
AUTHORIZATION_KIND: Final = "LIVE_EXPORT_ONLY"
DIGEST_DOMAIN: Final = "unified-db-export-only-authorization-v1"
MAX_EXPORT_WINDOW: Final = timedelta(minutes=15)
_UTC: Final = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_AUTH_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FIELDS: Final = frozenset(
    {
        "authorization_version",
        "authorization_kind",
        "authorization_id",
        "nonce",
        "source_name",
        "operation",
        "profile_digest",
        "plan_digest",
        "mapping_digest",
        "adapter_digest",
        "inventory_digest",
        "destination_digest",
        "quiesce_approved",
        "max_exports",
        "source_body_read_allowed_for_export",
        "mutation_allowed",
        "import_allowed",
        "register_allowed",
        "cohort_allowed",
        "serve_allowed",
        "promote_allowed",
        "cutover_allowed",
        "issued_at",
        "not_before",
        "expires_at",
        "authorization_digest",
    }
)


def parse_authorization_id(value: JsonValue, field: str) -> str:
    text = parse_string(value, field)
    if _AUTH_ID.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be an ASCII token")
    return text


def parse_utc(value: JsonValue, field: str) -> datetime:
    text = parse_string(value, field)
    if _UTC.fullmatch(text) is None:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp")
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as exc:
        raise InvalidContractValue(f"{field} must be a canonical UTC timestamp") from exc


@dataclass(frozen=True, slots=True)
class UnifiedDbExportOnlyAuthorizationV1:
    authorization_version: str
    authorization_kind: str
    authorization_id: str
    nonce: str
    source_name: str
    operation: str
    profile_digest: str
    plan_digest: str
    mapping_digest: str
    adapter_digest: str
    inventory_digest: str
    destination_digest: str
    quiesce_approved: bool
    max_exports: str
    source_body_read_allowed_for_export: bool
    mutation_allowed: bool
    import_allowed: bool
    register_allowed: bool
    cohort_allowed: bool
    serve_allowed: bool
    promote_allowed: bool
    cutover_allowed: bool
    issued_at: str
    not_before: str
    expires_at: str
    authorization_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> UnifiedDbExportOnlyAuthorizationV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["authorization_version"], "authorization_version")
        if version != AUTHORIZATION_VERSION:
            raise UnsupportedContractVersion(
                f"unsupported authorization_version: {version!r}"
            )
        issued = parse_utc(data["issued_at"], "issued_at")
        not_before = parse_utc(data["not_before"], "not_before")
        expires = parse_utc(data["expires_at"], "expires_at")
        if not issued <= not_before <= expires:
            raise InvalidContractValue("authorization window is not ordered")
        if expires - issued > MAX_EXPORT_WINDOW:
            raise InvalidContractValue("authorization window exceeds 15 minutes")
        parsed = cls(
            version,
            parse_const(data["authorization_kind"], "authorization_kind", AUTHORIZATION_KIND),
            parse_authorization_id(data["authorization_id"], "authorization_id"),
            parse_digest(data["nonce"], "nonce"),
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", EXPORT_ONLY),
            parse_digest(data["profile_digest"], "profile_digest"),
            parse_digest(data["plan_digest"], "plan_digest"),
            parse_digest(data["mapping_digest"], "mapping_digest"),
            parse_digest(data["adapter_digest"], "adapter_digest"),
            parse_digest(data["inventory_digest"], "inventory_digest"),
            parse_digest(data["destination_digest"], "destination_digest"),
            parse_true(data["quiesce_approved"], "quiesce_approved"),
            parse_const(data["max_exports"], "max_exports", "1"),
            parse_true(
                data["source_body_read_allowed_for_export"],
                "source_body_read_allowed_for_export",
            ),
            parse_false(data["mutation_allowed"], "mutation_allowed"),
            parse_false(data["import_allowed"], "import_allowed"),
            parse_false(data["register_allowed"], "register_allowed"),
            parse_false(data["cohort_allowed"], "cohort_allowed"),
            parse_false(data["serve_allowed"], "serve_allowed"),
            parse_false(data["promote_allowed"], "promote_allowed"),
            parse_false(data["cutover_allowed"], "cutover_allowed"),
            parse_string(data["issued_at"], "issued_at"),
            parse_string(data["not_before"], "not_before"),
            parse_string(data["expires_at"], "expires_at"),
            parse_digest(data["authorization_digest"], "authorization_digest"),
        )
        if parsed.authorization_digest != parsed.computed_digest():
            raise InvalidContractValue("authorization_digest does not bind body fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["authorization_digest"]
        return canonical_ledger_digest(DIGEST_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "authorization_version": self.authorization_version,
            "authorization_kind": self.authorization_kind,
            "authorization_id": self.authorization_id,
            "nonce": self.nonce,
            "source_name": self.source_name,
            "operation": self.operation,
            "profile_digest": self.profile_digest,
            "plan_digest": self.plan_digest,
            "mapping_digest": self.mapping_digest,
            "adapter_digest": self.adapter_digest,
            "inventory_digest": self.inventory_digest,
            "destination_digest": self.destination_digest,
            "quiesce_approved": self.quiesce_approved,
            "max_exports": self.max_exports,
            "source_body_read_allowed_for_export": self.source_body_read_allowed_for_export,
            "mutation_allowed": self.mutation_allowed,
            "import_allowed": self.import_allowed,
            "register_allowed": self.register_allowed,
            "cohort_allowed": self.cohort_allowed,
            "serve_allowed": self.serve_allowed,
            "promote_allowed": self.promote_allowed,
            "cutover_allowed": self.cutover_allowed,
            "issued_at": self.issued_at,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "authorization_digest": self.authorization_digest,
        }
