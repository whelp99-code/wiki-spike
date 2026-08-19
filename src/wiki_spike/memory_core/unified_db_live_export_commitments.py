"""Adapter, destination, and writer-quiescence commitments for live export."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_export_authorization import parse_utc
from .unified_db_live_export_parse import parse_ascii_token
from .unified_db_snapshot_export import parse_const, parse_false, parse_true

ADAPTER_VERSION: Final = "second-brain-unified-db-live-export-adapter-v1"
ADAPTER_DOMAIN: Final = "unified-db-live-export-adapter-v1"
ADAPTER_ID: Final = "unified-db-readonly-serializable-v1"
DESTINATION_VERSION: Final = "second-brain-unified-db-live-export-destination-v1"
DESTINATION_DOMAIN: Final = "unified-db-live-export-destination-v1"
QUIESCENCE_VERSION: Final = "second-brain-unified-db-writer-quiescence-v1"
QUIESCENCE_DOMAIN: Final = "unified-db-writer-quiescence-v1"
_ADAPTER_FIELDS: Final = frozenset(
    {
        "adapter_version",
        "adapter_id",
        "source_name",
        "isolation",
        "read_only",
        "deferrable",
        "select_template_digest",
        "adapter_digest",
    }
)
_DESTINATION_FIELDS: Final = frozenset(
    {
        "destination_version",
        "destination_id",
        "commitment_kind",
        "path_policy",
        "import_requested",
        "serve_requested",
        "promote_requested",
        "cutover_requested",
        "destination_digest",
    }
)
_QUIESCENCE_FIELDS: Final = frozenset(
    {
        "quiescence_version",
        "source_identity_digest",
        "writer_count",
        "quiesce_approved",
        "captured_at",
        "quiescence_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbLiveExportAdapterV1:
    adapter_version: str
    adapter_id: str
    source_name: str
    isolation: str
    read_only: bool
    deferrable: bool
    select_template_digest: str
    adapter_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbLiveExportAdapterV1:
        strict_fields(data, _ADAPTER_FIELDS)
        version = parse_string(data["adapter_version"], "adapter_version")
        if version != ADAPTER_VERSION:
            raise UnsupportedContractVersion(f"unsupported adapter_version: {version!r}")
        parsed = cls(
            version,
            parse_const(data["adapter_id"], "adapter_id", ADAPTER_ID),
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["isolation"], "isolation", "SERIALIZABLE"),
            parse_true(data["read_only"], "read_only"),
            parse_true(data["deferrable"], "deferrable"),
            parse_digest(data["select_template_digest"], "select_template_digest"),
            parse_digest(data["adapter_digest"], "adapter_digest"),
        )
        if parsed.adapter_digest != parsed.computed_digest():
            raise InvalidContractValue("adapter_digest does not bind adapter fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["adapter_digest"]
        return canonical_ledger_digest(ADAPTER_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "adapter_version": self.adapter_version,
            "adapter_id": self.adapter_id,
            "source_name": self.source_name,
            "isolation": self.isolation,
            "read_only": self.read_only,
            "deferrable": self.deferrable,
            "select_template_digest": self.select_template_digest,
            "adapter_digest": self.adapter_digest,
        }


@dataclass(frozen=True, slots=True)
class UnifiedDbLiveExportDestinationV1:
    destination_version: str
    destination_id: str
    commitment_kind: str
    path_policy: str
    import_requested: bool
    serve_requested: bool
    promote_requested: bool
    cutover_requested: bool
    destination_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> UnifiedDbLiveExportDestinationV1:
        strict_fields(data, _DESTINATION_FIELDS)
        version = parse_string(data["destination_version"], "destination_version")
        if version != DESTINATION_VERSION:
            raise UnsupportedContractVersion(
                f"unsupported destination_version: {version!r}"
            )
        parsed = cls(
            version,
            parse_ascii_token(data["destination_id"], "destination_id"),
            parse_const(data["commitment_kind"], "commitment_kind", "LOCAL_PACKAGE_TREE"),
            parse_const(data["path_policy"], "path_policy", "create-only-exclusive"),
            parse_false(data["import_requested"], "import_requested"),
            parse_false(data["serve_requested"], "serve_requested"),
            parse_false(data["promote_requested"], "promote_requested"),
            parse_false(data["cutover_requested"], "cutover_requested"),
            parse_digest(data["destination_digest"], "destination_digest"),
        )
        if parsed.destination_digest != parsed.computed_digest():
            raise InvalidContractValue("destination_digest does not bind destination fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["destination_digest"]
        return canonical_ledger_digest(DESTINATION_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "destination_version": self.destination_version,
            "destination_id": self.destination_id,
            "commitment_kind": self.commitment_kind,
            "path_policy": self.path_policy,
            "import_requested": self.import_requested,
            "serve_requested": self.serve_requested,
            "promote_requested": self.promote_requested,
            "cutover_requested": self.cutover_requested,
            "destination_digest": self.destination_digest,
        }


@dataclass(frozen=True, slots=True)
class UnifiedDbWriterQuiescenceV1:
    quiescence_version: str
    source_identity_digest: str
    writer_count: str
    quiesce_approved: bool
    captured_at: str
    quiescence_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbWriterQuiescenceV1:
        strict_fields(data, _QUIESCENCE_FIELDS)
        version = parse_string(data["quiescence_version"], "quiescence_version")
        if version != QUIESCENCE_VERSION:
            raise UnsupportedContractVersion(
                f"unsupported quiescence_version: {version!r}"
            )
        _ = parse_utc(data["captured_at"], "captured_at")
        parsed = cls(
            version,
            parse_digest(data["source_identity_digest"], "source_identity_digest"),
            parse_const(data["writer_count"], "writer_count", "0"),
            parse_true(data["quiesce_approved"], "quiesce_approved"),
            parse_string(data["captured_at"], "captured_at"),
            parse_digest(data["quiescence_digest"], "quiescence_digest"),
        )
        if parsed.quiescence_digest != parsed.computed_digest():
            raise InvalidContractValue("quiescence_digest does not bind quiescence fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["quiescence_digest"]
        return canonical_ledger_digest(QUIESCENCE_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "quiescence_version": self.quiescence_version,
            "source_identity_digest": self.source_identity_digest,
            "writer_count": self.writer_count,
            "quiesce_approved": self.quiesce_approved,
            "captured_at": self.captured_at,
            "quiescence_digest": self.quiescence_digest,
        }
