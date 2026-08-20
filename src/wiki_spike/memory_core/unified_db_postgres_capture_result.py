"""Receipt contract and output-binding checks for metadata capture."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from .unified_db_postgres_capture_output import (
    PostgresMetadataCaptureOutputManifestV1,
)
from .unified_db_snapshot_export import parse_const, parse_decimal, parse_false

RECEIPT_VERSION: Final = "second-brain-unified-db-postgres-metadata-capture-receipt-v1"
RECEIPT_DOMAIN: Final = "unified-db-postgres-metadata-capture-receipt-v1"
OUTPUT_DOMAIN: Final = "unified-db-postgres-metadata-capture-output-v1"
RECEIPT_STATE: Final = "METADATA_CAPTURED_NOT_AUTHORIZED"
_RECEIPT_FIELDS: Final = frozenset(
    {
        "receipt_version",
        "state",
        "operation",
        "source_name",
        "authorization_kind",
        "application_row_present",
        "source_body_present",
        "source_mutation",
        "export_invoked",
        "import_invoked",
        "serving_promotion",
        "cutover_eligible",
        "query_manifest_digest",
        "capture_plan_digest",
        "catalog_digest",
        "identity_digest",
        "destination_digest",
        "output_manifest_digest",
        "output_digest",
        "byte_count",
        "receipt_digest",
    }
)


def compute_capture_output_digest(
    destination_digest: str, manifest: PostgresMetadataCaptureOutputManifestV1
) -> str:
    return canonical_ledger_digest(
        OUTPUT_DOMAIN,
        {
            "destination_digest": destination_digest,
            "output_manifest_digest": manifest.manifest_digest,
            "entries": [entry.to_mapping() for entry in manifest.entries],
        },
    )


def _require_receipt_flags(data: Mapping[str, JsonValue]) -> None:
    _ = parse_false(data["application_row_present"], "application_row_present")
    _ = parse_false(data["source_body_present"], "source_body_present")
    _ = parse_false(data["source_mutation"], "source_mutation")
    _ = parse_false(data["export_invoked"], "export_invoked")
    _ = parse_false(data["import_invoked"], "import_invoked")
    _ = parse_false(data["serving_promotion"], "serving_promotion")
    _ = parse_false(data["cutover_eligible"], "cutover_eligible")


@dataclass(frozen=True, slots=True)
class PostgresMetadataCaptureReceiptV1:
    receipt_version: str
    state: str
    operation: str
    source_name: str
    authorization_kind: str
    application_row_present: bool
    source_body_present: bool
    source_mutation: bool
    export_invoked: bool
    import_invoked: bool
    serving_promotion: bool
    cutover_eligible: bool
    query_manifest_digest: str
    capture_plan_digest: str
    catalog_digest: str
    identity_digest: str
    destination_digest: str
    output_manifest_digest: str
    output_digest: str
    byte_count: str
    receipt_digest: str

    @classmethod
    def create(
        cls,
        destination: PostgresMetadataCaptureDestinationV1,
        manifest: PostgresMetadataCaptureOutputManifestV1,
    ) -> PostgresMetadataCaptureReceiptV1:
        digests = {entry.relative_path: entry.content_digest for entry in manifest.entries}
        byte_count = str(sum(int(entry.size_bytes) for entry in manifest.entries))
        provisional = cls(
            RECEIPT_VERSION,
            RECEIPT_STATE,
            "METADATA_CAPTURE_ONLY",
            "unified-db",
            "POSTGRES_METADATA_CAPTURE_ONLY",
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            digests["query-manifest.json"],
            digests["capture-plan.json"],
            digests["catalog.json"],
            digests["identity.json"],
            destination.destination_digest,
            manifest.manifest_digest,
            compute_capture_output_digest(destination.destination_digest, manifest),
            byte_count,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"receipt_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PostgresMetadataCaptureReceiptV1:
        strict_fields(data, _RECEIPT_FIELDS)
        version = parse_string(data["receipt_version"], "receipt_version")
        if version != RECEIPT_VERSION:
            raise UnsupportedContractVersion(f"unsupported receipt_version: {version!r}")
        _require_receipt_flags(data)
        parsed = cls(
            version,
            parse_const(data["state"], "state", RECEIPT_STATE),
            parse_const(data["operation"], "operation", "METADATA_CAPTURE_ONLY"),
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(
                data["authorization_kind"],
                "authorization_kind",
                "POSTGRES_METADATA_CAPTURE_ONLY",
            ),
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            parse_digest(data["query_manifest_digest"], "query_manifest_digest"),
            parse_digest(data["capture_plan_digest"], "capture_plan_digest"),
            parse_digest(data["catalog_digest"], "catalog_digest"),
            parse_digest(data["identity_digest"], "identity_digest"),
            parse_digest(data["destination_digest"], "destination_digest"),
            parse_digest(data["output_manifest_digest"], "output_manifest_digest"),
            parse_digest(data["output_digest"], "output_digest"),
            parse_decimal(data["byte_count"], "byte_count"),
            parse_digest(data["receipt_digest"], "receipt_digest"),
        )
        if parsed.receipt_digest != parsed.computed_digest():
            raise InvalidContractValue("receipt_digest does not bind receipt fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["receipt_digest"]
        return canonical_ledger_digest(RECEIPT_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "receipt_version": self.receipt_version,
            "state": self.state,
            "operation": self.operation,
            "source_name": self.source_name,
            "authorization_kind": self.authorization_kind,
            "application_row_present": self.application_row_present,
            "source_body_present": self.source_body_present,
            "source_mutation": self.source_mutation,
            "export_invoked": self.export_invoked,
            "import_invoked": self.import_invoked,
            "serving_promotion": self.serving_promotion,
            "cutover_eligible": self.cutover_eligible,
            "query_manifest_digest": self.query_manifest_digest,
            "capture_plan_digest": self.capture_plan_digest,
            "catalog_digest": self.catalog_digest,
            "identity_digest": self.identity_digest,
            "destination_digest": self.destination_digest,
            "output_manifest_digest": self.output_manifest_digest,
            "output_digest": self.output_digest,
            "byte_count": self.byte_count,
            "receipt_digest": self.receipt_digest,
        }


def bind_capture_receipt(
    destination: PostgresMetadataCaptureDestinationV1,
    manifest: PostgresMetadataCaptureOutputManifestV1,
    receipt: PostgresMetadataCaptureReceiptV1,
) -> None:
    if receipt.destination_digest != destination.destination_digest:
        raise InvalidContractValue("receipt destination_digest does not bind destination")
    if receipt.output_manifest_digest != manifest.manifest_digest:
        raise InvalidContractValue("receipt output_manifest_digest does not bind manifest")
    expected = compute_capture_output_digest(destination.destination_digest, manifest)
    if receipt.output_digest != expected:
        raise InvalidContractValue("output_digest does not bind destination and manifest")
    byte_count = str(sum(int(entry.size_bytes) for entry in manifest.entries))
    if receipt.byte_count != byte_count:
        raise InvalidContractValue("byte_count does not bind manifest entries")
    digests = {entry.relative_path: entry.content_digest for entry in manifest.entries}
    if (
        receipt.capture_plan_digest != digests["capture-plan.json"]
        or receipt.catalog_digest != digests["catalog.json"]
        or receipt.identity_digest != digests["identity.json"]
        or receipt.query_manifest_digest != digests["query-manifest.json"]
    ):
        raise InvalidContractValue("receipt artifact digests do not bind manifest entries")
