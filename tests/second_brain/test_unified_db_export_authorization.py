"""Contract tests for the unsigned LIVE_EXPORT_ONLY authorization body."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import override

import pytest

from tests.second_brain.unified_db_export_authorization_support import (
    CONFORMANCE_SCHEMA,
    EVIDENCE,
    SCHEMA,
    authorization_body,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_export_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
    UnifiedDbExportOnlyAuthorizationV1,
    parse_utc,
)
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
    export_only_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def test_body_binds_export_only_identity_and_one_shot_window() -> None:
    parsed = UnifiedDbExportOnlyAuthorizationV1.from_mapping(authorization_body())
    assert parsed.authorization_version == AUTHORIZATION_VERSION
    assert parsed.authorization_kind == AUTHORIZATION_KIND
    assert parsed.source_name == "unified-db"
    assert parsed.operation == "EXPORT_ONLY"
    assert parsed.max_exports == "1"
    assert parsed.source_body_read_allowed_for_export is True
    assert parsed.quiesce_approved is True
    assert parsed.mutation_allowed is False
    assert parsed.import_allowed is False
    assert parsed.register_allowed is False
    assert parsed.cohort_allowed is False
    assert parsed.serve_allowed is False
    assert parsed.promote_allowed is False
    assert parsed.cutover_allowed is False
    assert parsed.authorization_digest == parsed.computed_digest()


def test_parse_utc_accepts_year_one_without_platform_strptime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PortableDateTime(datetime):
        @classmethod
        @override
        def strptime(cls, date_string: str, format: str) -> datetime:
            _ = date_string, format
            raise AssertionError("parse_utc must not depend on platform strptime")

    monkeypatch.setattr(
        "wiki_spike.memory_core.unified_db_export_authorization.datetime",
        PortableDateTime,
    )

    parsed = parse_utc("0001-01-01T00:00:00Z", "authorization_floor_at")

    assert parsed.year == 1


def test_signing_bytes_are_domain_plus_canonical_body() -> None:
    body = authorization_body()
    payload = export_only_authorization_signing_bytes(body)
    assert payload.startswith(EXPORT_ONLY_AUTHORIZATION_DOMAIN)
    assert EXPORT_ONLY_AUTHORIZATION_DOMAIN == (
        b"wiki-spike.second-brain.unified-db.export-only-authorization.v1\x00"
    )
    assert payload == EXPORT_ONLY_AUTHORIZATION_DOMAIN + canonical_bytes(body)
    reordered = dict(reversed(list(body.items())))
    assert export_only_authorization_signing_bytes(reordered) == payload


@pytest.mark.parametrize("field", ["authorization_id", "nonce", "authorization_digest"])
def test_body_rejects_missing_and_extra_fields(field: str) -> None:
    missing = authorization_body()
    del missing[field]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(missing)
    extra = authorization_body() | {"extra": "no"}
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(extra)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_version", "forged-v1"),
        ("authorization_kind", "FIXTURE_ONLY"),
        ("source_name", "me-wiki"),
        ("operation", "IMPORT"),
        ("max_exports", "2"),
        ("max_exports", "0"),
        ("max_exports", "01"),
        ("profile_digest", "zz" * 32),
        ("destination_digest", "1" * 63),
    ],
)
def test_body_rejects_wrong_version_source_operation_or_digest(
    field: str, value: str
) -> None:
    with pytest.raises((InvalidContractValue, UnsupportedContractVersion)):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(
            authorization_body(**{field: value})
        )


@pytest.mark.parametrize(
    "field",
    [
        "mutation_allowed",
        "import_allowed",
        "register_allowed",
        "cohort_allowed",
        "serve_allowed",
        "promote_allowed",
        "cutover_allowed",
    ],
)
def test_body_rejects_any_prohibited_flag_true(field: str) -> None:
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(
            authorization_body(**{field: True})
        )


@pytest.mark.parametrize(
    "value",
    ["export-auth-caf\u00e9", "export-auth-cafe\u0301", "export-auth-001\u0435"],
)
def test_authorization_id_rejects_unicode_and_confusables(value: str) -> None:
    with pytest.raises(InvalidContractValue, match="authorization_id"):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(
            authorization_body(authorization_id=value)
        )


@pytest.mark.parametrize(
    "value",
    ["AB" * 32, "ab" * 31, "export-nonce-caf\u00e9", "ab" * 31 + "G"],
)
def test_nonce_rejects_non_lowercase_hex(value: str) -> None:
    with pytest.raises(InvalidContractValue, match="nonce"):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(
            authorization_body(nonce=value)
        )


def test_body_rejects_window_longer_than_fifteen_minutes() -> None:
    with pytest.raises(InvalidContractValue, match="15"):
        _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(
            authorization_body(expires_at="2026-08-18T12:15:01Z")
        )


def test_body_rejects_raw_numbers_in_persisted_values() -> None:
    encoded = canonical_bytes(authorization_body()).decode("utf-8")
    numeric = encoded.replace('"max_exports":"1"', '"max_exports":1')
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object(numeric)


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


def test_schema_and_body_free_conformance_use_draft_2020_12() -> None:
    evidence = decode_json_object(EVIDENCE.read_text(encoding="utf-8"))
    assert SCHEMA.read_text(encoding="utf-8").find(
        "https://json-schema.org/draft/2020-12/schema"
    ) != -1
    assert CONFORMANCE_SCHEMA.read_text(encoding="utf-8").find(
        "https://json-schema.org/draft/2020-12/schema"
    ) != -1
    assert _draft_status(SCHEMA, authorization_body()) == 0
    assert _draft_status(CONFORMANCE_SCHEMA, evidence) == 0
    assert evidence.get("body_present") is False
    assert evidence.get("private_key_material") is False
    assert "body" not in evidence
    assert _draft_status(SCHEMA, authorization_body() | {"extra": "no"}) != 0
    assert _draft_status(CONFORMANCE_SCHEMA, evidence | {"extra": "no"}) != 0
