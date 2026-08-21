"""Path-policy tests for signed create-only capture destinations."""
from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from tests.second_brain.unified_db_postgres_capture_result_support import (
    DESTINATION_PATH,
    DESTINATION_SCHEMA,
    PATH_POLICY,
    destination_body,
    draft_status,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    DESTINATION_VERSION,
    PostgresMetadataCaptureDestinationV1,
    enforce_create_only_destination,
    parse_absolute_destination_path,
)


def test_destination_binds_absolute_create_only_path() -> None:
    parsed = PostgresMetadataCaptureDestinationV1.from_mapping(destination_body())
    assert parsed.destination_version == DESTINATION_VERSION
    assert parsed.destination_path == DESTINATION_PATH
    assert parsed.path_policy == PATH_POLICY
    assert parsed.operation == "METADATA_CAPTURE_ONLY"
    assert parsed.authorization_kind == "POSTGRES_METADATA_CAPTURE_ONLY"
    assert parsed.import_requested is False
    assert parsed.destination_digest == parsed.computed_digest()


@pytest.mark.parametrize(
    "path",
    ["captured/out", "./captured", "postgres-metadata"],
)
def test_destination_rejects_relative_path(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="absolute"):
        _ = parse_absolute_destination_path(path)
    with pytest.raises(InvalidContractValue, match="absolute"):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(destination_body(path))


@pytest.mark.parametrize(
    "path",
    [
        "/captured/../postgres-metadata",
        "/captured/foo/..",
        "/captured/./out",
        "/captured//out",
        "//private/tmp/postgres-metadata",
        "//captured/out",
        "/captured/out/",
        "/",
    ],
)
def test_destination_rejects_dot_dot_or_non_canonical_path(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="absolute|canonical"):
        _ = parse_absolute_destination_path(path)


@pytest.mark.parametrize(
    "path",
    ["/captured/\npostgres", "/captured/\tout", "/captured/\x01meta", "/captured/\x7fmeta"],
)
def test_destination_rejects_control_characters(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="control"):
        _ = parse_absolute_destination_path(path)


def test_destination_rejects_missing_extra_and_unsupported_version() -> None:
    missing = destination_body()
    del missing["destination_path"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(
            destination_body() | {"extra": "no"}
        )
    with pytest.raises(UnsupportedContractVersion):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(
            destination_body(destination_version="destination-v0")
        )


def test_destination_rejects_overwrite_or_serve_flags() -> None:
    with pytest.raises(InvalidContractValue):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(
            destination_body(path_policy="overwrite")
        )
    with pytest.raises(InvalidContractValue):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(
            destination_body(import_requested=True)
        )
    with pytest.raises(InvalidContractValue):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(
            destination_body(serve_requested=True)
        )


def test_destination_rejects_tampered_digest() -> None:
    body = destination_body()
    body["destination_digest"] = "ab" * 32
    with pytest.raises(InvalidContractValue, match="destination_digest"):
        _ = PostgresMetadataCaptureDestinationV1.from_mapping(body)


def test_enforce_accepts_missing_create_only_path(tmp_path: Path) -> None:
    dest = tmp_path / "capture-out"
    enforce_create_only_destination(str(dest))
    parsed = PostgresMetadataCaptureDestinationV1.from_mapping(
        destination_body(str(dest))
    )
    assert parsed.destination_path == str(dest)


def test_enforce_rejects_existing_destination(tmp_path: Path) -> None:
    dest = tmp_path / "capture-out"
    dest.mkdir()
    with pytest.raises(InvalidContractValue, match="exists|overwrite"):
        enforce_create_only_destination(str(dest))


def test_enforce_rejects_symlink_destination(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    dest = tmp_path / "link"
    dest.symlink_to(target)
    with pytest.raises(InvalidContractValue, match="symlink"):
        enforce_create_only_destination(str(dest))


def test_enforce_rejects_symlink_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    with pytest.raises(InvalidContractValue, match="symlink"):
        enforce_create_only_destination(str(alias / "out"))


def test_destination_schema_is_draft_2020_12() -> None:
    instance = destination_body()
    assert "https://json-schema.org/draft/2020-12/schema" in DESTINATION_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert draft_status(DESTINATION_SCHEMA, instance) == 0
    assert draft_status(DESTINATION_SCHEMA, instance | {"extra": "no"}) != 0
    broken: dict[str, object] = dict(instance)
    broken["import_requested"] = 1
    assert draft_status(DESTINATION_SCHEMA, cast(Mapping[str, JsonValue], broken)) != 0
