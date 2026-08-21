"""Strict unsigned POSTGRES_METADATA_CAPTURE_ONLY authorization body."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_export_authorization import parse_authorization_id, parse_utc
from .unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from .unified_db_snapshot_export import parse_const, parse_false

AUTHORIZATION_VERSION: Final = (
    "second-brain-unified-db-postgres-metadata-capture-only-authorization-v1"
)
AUTHORIZATION_KIND: Final = "POSTGRES_METADATA_CAPTURE_ONLY"
CLOSED_QUERY_MANIFEST_DIGEST: Final = (
    "648ee2cdf9f10257d62744b39971ea528093e17515845b07e4286ed31555c4fb"
)
DIGEST_DOMAIN: Final = "unified-db-postgres-metadata-capture-only-authorization-v1"
MAX_CAPTURE_WINDOW: Final = timedelta(minutes=15)
_FIELDS: Final = frozenset(
    {
        "authorization_version",
        "authorization_kind",
        "authorization_id",
        "nonce",
        "source_name",
        "operation",
        "query_manifest_digest",
        "capture_plan_digest",
        "output_digest",
        "destination",
        "max_captures",
        "application_row_allowed",
        "source_body_read_allowed",
        "mutation_allowed",
        "export_allowed",
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


@dataclass(frozen=True, slots=True)
class UnifiedDbMetadataCaptureOnlyAuthorizationV1:
    authorization_version: str
    authorization_kind: str
    authorization_id: str
    nonce: str
    source_name: str
    operation: str
    query_manifest_digest: str
    capture_plan_digest: str
    output_digest: str
    destination: PostgresMetadataCaptureDestinationV1
    max_captures: str
    application_row_allowed: bool
    source_body_read_allowed: bool
    mutation_allowed: bool
    export_allowed: bool
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
    ) -> UnifiedDbMetadataCaptureOnlyAuthorizationV1:
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
        if expires - issued > MAX_CAPTURE_WINDOW:
            raise InvalidContractValue("authorization window exceeds 15 minutes")
        raw_destination = data["destination"]
        if not isinstance(raw_destination, dict):
            raise InvalidContractValue("destination must be an object")
        parsed = cls(
            version,
            parse_const(data["authorization_kind"], "authorization_kind", AUTHORIZATION_KIND),
            parse_authorization_id(data["authorization_id"], "authorization_id"),
            parse_digest(data["nonce"], "nonce"),
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", "METADATA_CAPTURE_ONLY"),
            parse_const(
                data["query_manifest_digest"],
                "query_manifest_digest",
                CLOSED_QUERY_MANIFEST_DIGEST,
            ),
            parse_digest(data["capture_plan_digest"], "capture_plan_digest"),
            parse_digest(data["output_digest"], "output_digest"),
            PostgresMetadataCaptureDestinationV1.from_mapping(raw_destination),
            parse_const(data["max_captures"], "max_captures", "1"),
            parse_false(data["application_row_allowed"], "application_row_allowed"),
            parse_false(data["source_body_read_allowed"], "source_body_read_allowed"),
            parse_false(data["mutation_allowed"], "mutation_allowed"),
            parse_false(data["export_allowed"], "export_allowed"),
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
            "query_manifest_digest": self.query_manifest_digest,
            "capture_plan_digest": self.capture_plan_digest,
            "output_digest": self.output_digest,
            "destination": self.destination.to_mapping(),
            "max_captures": self.max_captures,
            "application_row_allowed": self.application_row_allowed,
            "source_body_read_allowed": self.source_body_read_allowed,
            "mutation_allowed": self.mutation_allowed,
            "export_allowed": self.export_allowed,
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
