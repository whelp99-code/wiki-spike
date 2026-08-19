"""Contract tests for the reviewed live-export mapping profile."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_live_export_support import (
    MAPPER_ID,
    MAPPING_SCHEMA,
    MAPPING_VERSION,
    identity_body,
    mapping_body,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_live_export_mapping import (
    UnifiedDbLiveExportMappingV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)


def _identity_digest() -> str:
    return PostgresIdentityReceiptV1.from_mapping(identity_body()).identity_digest


def _parse(data: Mapping[str, JsonValue]) -> UnifiedDbLiveExportMappingV1:
    return UnifiedDbLiveExportMappingV1.from_mapping(data)


def test_mapping_keeps_mapper_identity_distinct_from_source_identity() -> None:
    source = _identity_digest()
    parsed = _parse(mapping_body(source))
    assert parsed.mapping_version == MAPPING_VERSION
    assert parsed.mapper_id == MAPPER_ID
    assert parsed.mapper_version == "v1"
    assert parsed.source_identity_digest == source
    assert parsed.mapper_id != parsed.source_identity_digest
    assert parsed.deletion_semantics == "EXPLICIT_TOMBSTONE_ONLY"
    assert parsed.absence_policy == "ABSENCE_IS_NOT_DELETION"
    assert parsed.mapping_digest == parsed.computed_digest()


def test_mapping_rejects_missing_extra_and_unsupported_version() -> None:
    source = _identity_digest()
    missing = mapping_body(source)
    del missing["tombstone"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = _parse(missing)
    with pytest.raises(UnknownContractField):
        _ = _parse(mapping_body(source) | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = _parse(mapping_body(source, mapping_version="mapping-v0"))


@pytest.mark.parametrize(
    "field",
    ["deletion_semantics", "absence_policy", "tombstone"],
)
def test_mapping_rejects_missing_or_ambiguous_deletion_semantics(field: str) -> None:
    source = _identity_digest()
    if field == "tombstone":
        broken = mapping_body(source, tombstone="maybe_deleted")
    elif field == "deletion_semantics":
        broken = mapping_body(source, deletion_semantics="ABSENCE_MEANS_DELETED")
    else:
        broken = mapping_body(source, absence_policy="INFER_FROM_ABSENCE")
    with pytest.raises(InvalidContractValue):
        _ = _parse(broken)


def test_mapping_rejects_source_identity_used_as_mapper_identity() -> None:
    source = _identity_digest()
    with pytest.raises(InvalidContractValue, match="mapper"):
        _ = _parse(mapping_body(source, mapper_id=source))


def test_mapping_rejects_unknown_mapper_version_token() -> None:
    source = _identity_digest()
    with pytest.raises(InvalidContractValue, match="mapper_version"):
        _ = _parse(mapping_body(source, mapper_version="latest"))


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


def test_mapping_schema_is_draft_2020_12_and_rejects_extra() -> None:
    instance = mapping_body(_identity_digest())
    assert "https://json-schema.org/draft/2020-12/schema" in MAPPING_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert _draft_status(MAPPING_SCHEMA, instance) == 0
    assert _draft_status(MAPPING_SCHEMA, instance | {"guess": "select *"}) != 0
