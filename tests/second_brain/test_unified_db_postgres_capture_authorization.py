"""Contract tests for the unsigned POSTGRES_METADATA_CAPTURE_ONLY body."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    CONFORMANCE_SCHEMA,
    EVIDENCE,
    SCHEMA,
    authorization_body,
    expected_digests,
)
from tests.second_brain.unified_db_postgres_capture_result_support import (
    DESTINATION_PATH,
    destination_body,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN,
    metadata_capture_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def test_body_binds_metadata_capture_only_identity_and_one_shot_window() -> None:
    parsed = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(authorization_body())
    assert parsed.authorization_version == AUTHORIZATION_VERSION
    assert parsed.authorization_kind == AUTHORIZATION_KIND
    assert parsed.source_name == "unified-db"
    assert parsed.operation == "METADATA_CAPTURE_ONLY"
    assert parsed.max_captures == "1"
    assert parsed.application_row_allowed is False
    assert parsed.source_body_read_allowed is False
    assert parsed.mutation_allowed is False
    assert parsed.export_allowed is False
    assert parsed.import_allowed is False
    assert parsed.register_allowed is False
    assert parsed.cohort_allowed is False
    assert parsed.serve_allowed is False
    assert parsed.promote_allowed is False
    assert parsed.cutover_allowed is False
    assert parsed.query_manifest_digest == (
        PostgresCaptureQueryManifestV1.closed().manifest_digest
    )
    assert expected_digests().query_manifest_digest == parsed.query_manifest_digest
    assert parsed.authorization_digest == parsed.computed_digest()


def test_body_binds_embedded_destination() -> None:
    dest = destination_body()
    parsed = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
        authorization_body(destination=dest)
    )
    assert parsed.destination.destination_path == DESTINATION_PATH
    assert parsed.destination.destination_digest == dest["destination_digest"]
    assert parsed.destination.destination_digest == parsed.destination.computed_digest()
    assert expected_digests().destination_digest == parsed.destination.destination_digest


def test_signing_bytes_are_domain_separated_from_export() -> None:
    body = authorization_body()
    payload = metadata_capture_authorization_signing_bytes(body)
    assert payload.startswith(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN)
    assert METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN == (
        b"wiki-spike.second-brain.unified-db.postgres-metadata-capture-only-authorization.v1\x00"
    )
    assert METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN != EXPORT_ONLY_AUTHORIZATION_DOMAIN
    assert payload == METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN + canonical_bytes(body)
    destination = body["destination"]
    assert isinstance(destination, dict)
    digest = destination["destination_digest"]
    assert isinstance(digest, str)
    assert digest.encode("ascii") in payload
    reordered = dict(reversed(list(body.items())))
    assert metadata_capture_authorization_signing_bytes(reordered) == payload


@pytest.mark.parametrize(
    "field", ["authorization_id", "nonce", "authorization_digest", "destination"]
)
def test_body_rejects_missing_and_extra_fields(field: str) -> None:
    missing = authorization_body()
    del missing[field]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(missing)
    extra = authorization_body() | {"extra": "no"}
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(extra)


@pytest.mark.parametrize(
    "path",
    [
        "captured/out",
        "./captured",
        "/captured/../postgres-metadata",
        "/captured/./out",
        "/captured/foo/..",
    ],
)
def test_body_refuses_relative_symlink_or_dot_dot_destination(path: str) -> None:
    with pytest.raises(InvalidContractValue, match="absolute|canonical"):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(destination=destination_body(path))
        )


def test_body_refuses_extra_destination_fields() -> None:
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(destination=destination_body() | {"extra": "no"})
        )


def test_body_refuses_destination_digest_mismatch() -> None:
    dest = destination_body()
    dest["destination_digest"] = "ab" * 32
    with pytest.raises(InvalidContractValue, match="destination_digest"):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(destination=dest)
        )


@pytest.mark.parametrize(
    "digest",
    ["aa" * 32, "11" * 32],
)
def test_body_refuses_dummy_or_other_query_manifest_digest(digest: str) -> None:
    closed = PostgresCaptureQueryManifestV1.closed().manifest_digest
    assert digest != closed
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(query_manifest_digest=digest)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("authorization_version", "forged-v1"),
        ("authorization_kind", "LIVE_EXPORT_ONLY"),
        ("source_name", "me-wiki"),
        ("operation", "EXPORT_ONLY"),
        ("max_captures", "2"),
        ("max_captures", "0"),
        ("max_captures", "01"),
        ("query_manifest_digest", "zz" * 32),
        ("output_digest", "1" * 63),
    ],
)
def test_body_rejects_wrong_version_source_operation_or_digest(
    field: str, value: str
) -> None:
    with pytest.raises((InvalidContractValue, UnsupportedContractVersion)):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(**{field: value})
        )


@pytest.mark.parametrize(
    "field",
    [
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
    ],
)
def test_body_rejects_any_prohibited_flag_true(field: str) -> None:
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(**{field: True})
        )


def test_body_rejects_window_longer_than_fifteen_minutes() -> None:
    with pytest.raises(InvalidContractValue, match="15"):
        _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
            authorization_body(expires_at="2026-08-18T12:15:01Z")
        )


def test_body_rejects_raw_numbers_in_persisted_values() -> None:
    encoded = canonical_bytes(authorization_body()).decode("utf-8")
    numeric = encoded.replace('"max_captures":"1"', '"max_captures":1')
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
    assert evidence.get("nonce_store_persisted") is False
    assert evidence.get("production_capture_authorized") is False
    assert "body" not in evidence
    assert _draft_status(SCHEMA, authorization_body() | {"extra": "no"}) != 0
    assert _draft_status(
        SCHEMA, authorization_body(destination=destination_body() | {"extra": "no"})
    ) != 0
    assert _draft_status(CONFORMANCE_SCHEMA, evidence | {"extra": "no"}) != 0


def test_schema_pins_closed_query_manifest_digest_const() -> None:
    closed = PostgresCaptureQueryManifestV1.closed().manifest_digest
    text = SCHEMA.read_text(encoding="utf-8")
    assert f'"const": "{closed}"' in text
    dummy = authorization_body(query_manifest_digest="aa" * 32)
    other = authorization_body(query_manifest_digest="11" * 32)
    assert _draft_status(SCHEMA, dummy) != 0
    assert _draft_status(SCHEMA, other) != 0
