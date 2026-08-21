"""Signed absolute create-only destination for metadata capture output."""
from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import parse_const, parse_false

DESTINATION_VERSION: Final = (
    "second-brain-unified-db-postgres-metadata-capture-destination-v1"
)
DESTINATION_DOMAIN: Final = "unified-db-postgres-metadata-capture-destination-v1"
PATH_POLICY: Final = "create-only-exclusive"
_FIELDS: Final = frozenset(
    {
        "destination_version",
        "source_name",
        "operation",
        "authorization_kind",
        "destination_path",
        "path_policy",
        "import_requested",
        "serve_requested",
        "promote_requested",
        "cutover_requested",
        "destination_digest",
    }
)


def parse_absolute_destination_path(value: JsonValue) -> str:
    text = parse_string(value, "destination_path")
    if any(ord(char) < 32 or char == "\x7f" for char in text):
        raise InvalidContractValue("destination_path must not contain control characters")
    parsed = PurePosixPath(text)
    if (
        text.startswith("//")
        or "\\" in text
        or not parsed.is_absolute()
        or parsed.as_posix() != text
        or text == "/"
    ):
        raise InvalidContractValue(
            "destination_path must be an absolute canonical POSIX path"
        )
    if any(part in {".", ".."} for part in parsed.parts):
        raise InvalidContractValue(
            "destination_path must be an absolute canonical POSIX path"
        )
    return text


def enforce_create_only_destination(path: str) -> None:
    dest = Path(parse_absolute_destination_path(path))
    current = Path(dest.anchor)
    for part in dest.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise InvalidContractValue("destination symlink refused")
    if dest.exists():
        raise InvalidContractValue("destination already exists; overwrite refused")
    try:
        meta = os.lstat(dest.parent)
    except OSError as exc:
        raise InvalidContractValue("destination parent must be an existing directory") from exc
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise InvalidContractValue("destination parent must be an existing directory")


@dataclass(frozen=True, slots=True)
class PostgresMetadataCaptureDestinationV1:
    destination_version: str
    source_name: str
    operation: str
    authorization_kind: str
    destination_path: str
    path_policy: str
    import_requested: bool
    serve_requested: bool
    promote_requested: bool
    cutover_requested: bool
    destination_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> PostgresMetadataCaptureDestinationV1:
        strict_fields(data, _FIELDS)
        version = parse_string(data["destination_version"], "destination_version")
        if version != DESTINATION_VERSION:
            raise UnsupportedContractVersion(
                f"unsupported destination_version: {version!r}"
            )
        parsed = cls(
            version,
            parse_const(data["source_name"], "source_name", "unified-db"),
            parse_const(data["operation"], "operation", "METADATA_CAPTURE_ONLY"),
            parse_const(
                data["authorization_kind"],
                "authorization_kind",
                "POSTGRES_METADATA_CAPTURE_ONLY",
            ),
            parse_absolute_destination_path(data["destination_path"]),
            parse_const(data["path_policy"], "path_policy", PATH_POLICY),
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
            "source_name": self.source_name,
            "operation": self.operation,
            "authorization_kind": self.authorization_kind,
            "destination_path": self.destination_path,
            "path_policy": self.path_policy,
            "import_requested": self.import_requested,
            "serve_requested": self.serve_requested,
            "promote_requested": self.promote_requested,
            "cutover_requested": self.cutover_requested,
            "destination_digest": self.destination_digest,
        }
