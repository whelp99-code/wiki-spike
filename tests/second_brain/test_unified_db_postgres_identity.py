"""Contract tests for the body-free PostgreSQL identity receipt."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from tests.second_brain.unified_db_live_export_support import (
    CATALOG_DIGEST,
    IDENTITY_SCHEMA,
    IDENTITY_VERSION,
    identity_body,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _parse(data: Mapping[str, JsonValue]) -> PostgresIdentityReceiptV1:
    return PostgresIdentityReceiptV1.from_mapping(data)


def test_identity_binds_system_oid_version_and_catalog_digest() -> None:
    parsed = _parse(identity_body())
    assert parsed.identity_version == IDENTITY_VERSION
    assert parsed.source_name == "unified-db"
    assert parsed.system_identifier == "7234017283807667306"
    assert parsed.database_oid == "16384"
    assert parsed.server_version_num == "160004"
    assert parsed.catalog_digest == CATALOG_DIGEST
    assert parsed.capture_method == "owner-produced-body-free"
    assert parsed.identity_digest == parsed.computed_digest()


def test_identity_rejects_missing_and_extra_fields() -> None:
    missing = identity_body()
    del missing["catalog_digest"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = _parse(missing)
    with pytest.raises(UnknownContractField):
        _ = _parse(identity_body() | {"extra": "no"})


def test_identity_rejects_unsupported_version() -> None:
    with pytest.raises(UnsupportedContractVersion):
        _ = _parse(identity_body(identity_version="forged-identity-v0"))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("system_identifier", "07234017283807667306"),
        ("system_identifier", "-1"),
        ("system_identifier", "18446744073709551616"),
        ("system_identifier", "not-an-id"),
        ("database_oid", "016384"),
        ("database_oid", "-1"),
        ("database_oid", "4294967296"),
        ("server_version_num", "0160004"),
        ("server_version_num", "16.4"),
        ("server_version_num", "0"),
        ("catalog_digest", "AA" * 32),
        ("catalog_digest", "aa" * 31),
        ("catalog_digest", "zz" * 32),
    ],
)
def test_identity_rejects_malformed_system_oid_version_or_catalog(
    field: str, value: str
) -> None:
    with pytest.raises(InvalidContractValue):
        _ = _parse(identity_body(**{field: value}))


def test_identity_rejects_raw_numeric_payload_values() -> None:
    encoded = json.dumps(identity_body(), separators=(",", ":"), sort_keys=True)
    numeric = encoded.replace('"16384"', "16384")
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object(numeric)
    broken: dict[str, object] = dict(identity_body())
    broken["server_version_num"] = 160004
    with pytest.raises(InvalidContractValue, match="canonical"):
        _ = _parse(cast(Mapping[str, JsonValue], broken))


def _draft_status(schema_path: Path, instance: Mapping[str, JsonValue]) -> int:
    script = (
        "import json,sys,jsonschema;"
        "schema=json.load(open(sys.argv[1], encoding='utf-8'));"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(schema_path), json.dumps(dict(instance))],
        capture_output=True,
        check=False,
        text=True,
    )
    return completed.returncode


def test_identity_schema_is_draft_2020_12_and_rejects_extra() -> None:
    assert "https://json-schema.org/draft/2020-12/schema" in IDENTITY_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert _draft_status(IDENTITY_SCHEMA, identity_body()) == 0
    assert _draft_status(IDENTITY_SCHEMA, identity_body() | {"extra": "no"}) != 0
