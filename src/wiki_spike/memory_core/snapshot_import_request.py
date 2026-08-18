"""Closed snapshot import request contract."""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePath
from typing import Final, Literal

from .contracts import JsonValue
from .errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from .snapshot_import_parse import (
    import_namespace,
    parse_digest,
    parse_source_name,
    parse_string,
)
from .source_discovery import SourceName

SNAPSHOT_IMPORT_REQUEST_V1: Final = "second-brain-snapshot-import-request-v1"
_COHORT: Final = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_REQUEST_FIELDS: Final = frozenset(
    {
        "request_version",
        "cohort_id",
        "source_name",
        "source_root",
        "target_namespace",
        "resolved_scope_digest",
        "discovery_manifest_digest",
        "snapshot_digest",
        "reconciliation_mode",
        "serving_promotion_requested",
    }
)


@dataclass(frozen=True, slots=True)
class SnapshotImportRequestV1:
    request_version: str
    cohort_id: str
    source_name: SourceName
    source_root: str
    target_namespace: str
    resolved_scope_digest: str
    discovery_manifest_digest: str
    snapshot_digest: str
    reconciliation_mode: Literal["REQUIRED"]
    serving_promotion_requested: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> SnapshotImportRequestV1:
        unknown = set(data) - _REQUEST_FIELDS
        missing = _REQUEST_FIELDS - set(data)
        if unknown:
            raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
        if missing:
            raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
        version = parse_string(data["request_version"], "request_version")
        if version != SNAPSHOT_IMPORT_REQUEST_V1:
            raise UnsupportedContractVersion(f"unsupported request_version: {version!r}")
        source_name = parse_source_name(data["source_name"])
        namespace = parse_string(data["target_namespace"], "target_namespace")
        if namespace != import_namespace(source_name):
            raise InvalidContractValue("target_namespace is not the source import namespace")
        root = parse_string(data["source_root"], "source_root")
        if not PurePath(root).is_absolute():
            raise InvalidContractValue("source_root must be a non-empty absolute path string")
        cohort_id = parse_string(data["cohort_id"], "cohort_id")
        if _COHORT.fullmatch(cohort_id) is None:
            raise InvalidContractValue("cohort_id has an invalid shape")
        if data["reconciliation_mode"] != "REQUIRED":
            raise InvalidContractValue("reconciliation_mode must be REQUIRED")
        if data["serving_promotion_requested"] is not False:
            raise InvalidContractValue("serving promotion is refused")
        return cls(
            version,
            cohort_id,
            source_name,
            root,
            namespace,
            parse_digest(data["resolved_scope_digest"], "resolved_scope_digest"),
            parse_digest(data["discovery_manifest_digest"], "discovery_manifest_digest"),
            parse_digest(data["snapshot_digest"], "snapshot_digest"),
            "REQUIRED",
            False,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "request_version": self.request_version,
            "cohort_id": self.cohort_id,
            "source_name": self.source_name,
            "source_root": self.source_root,
            "target_namespace": self.target_namespace,
            "resolved_scope_digest": self.resolved_scope_digest,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "snapshot_digest": self.snapshot_digest,
            "reconciliation_mode": self.reconciliation_mode,
            "serving_promotion_requested": self.serving_promotion_requested,
        }
