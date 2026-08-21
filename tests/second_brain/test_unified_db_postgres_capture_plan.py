"""Capture-plan contract, identity port, and verify tests."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_support import (
    CAPTURE_PLAN_SCHEMA,
    CAPTURE_PLAN_VERSION,
    FUTURE_CAPTURED_AT,
    NOW,
    STALE_CAPTURED_AT,
    FakePostgresCatalogCapture,
    FakePostgresIdentityCapture,
    bound_identity_body,
    capture_plan_body,
    catalog_body,
    identity_inputs_body,
)
from wiki_spike.applications.unified_db_postgres_capture_verify import (
    CapturePlanRequestV1,
    CaptureVerifyRequestV1,
    plan_postgres_identity_capture,
    verify_postgres_capture_plan,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_plan import (
    PostgresCapturePlanV1,
    PostgresIdentityInputsV1,
    produce_postgres_identity_receipt,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _request(
    manifest: dict[str, JsonValue],
    identity: dict[str, JsonValue],
    catalog: dict[str, JsonValue],
    plan: dict[str, JsonValue],
) -> CaptureVerifyRequestV1:
    return CaptureVerifyRequestV1.from_mappings(
        {
            "query_manifest": manifest,
            "identity": identity,
            "catalog": catalog,
            "plan": plan,
        }
    )


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


def test_identity_port_produces_receipt_from_exactly_four_metadata_values() -> None:
    inputs = PostgresIdentityInputsV1.from_mapping(identity_inputs_body())
    receipt = FakePostgresIdentityCapture().capture_identity(inputs)
    assert receipt.system_identifier == inputs.system_identifier
    assert receipt.database_oid == inputs.database_oid
    assert receipt.server_version_num == inputs.server_version_num
    assert receipt.catalog_digest == inputs.catalog_digest
    assert receipt.identity_digest == receipt.computed_digest()
    rebuilt = produce_postgres_identity_receipt(inputs)
    assert rebuilt.to_mapping() == receipt.to_mapping()


def test_catalog_port_builds_snapshot_from_typed_rows() -> None:
    catalog = PostgresCatalogSnapshotV1.from_mapping(catalog_body())
    snapshot = FakePostgresCatalogCapture().capture_catalog(catalog.rows)
    assert snapshot.catalog_digest == catalog.catalog_digest


def test_plan_binds_manifest_identity_and_catalog_digest() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    catalog = PostgresCatalogSnapshotV1.from_mapping(catalog_body())
    identity = PostgresIdentityReceiptV1.from_mapping(bound_identity_body())
    planned = plan_postgres_identity_capture(
        CapturePlanRequestV1(manifest, identity, catalog), NOW
    )
    assert planned.plan_version == CAPTURE_PLAN_VERSION
    assert planned.query_manifest_digest == manifest.manifest_digest
    assert planned.catalog_digest == catalog.catalog_digest
    assert planned.catalog_digest == identity.catalog_digest
    assert planned.system_identifier == identity.system_identifier
    assert planned.plan_digest == planned.computed_digest()
    verify_postgres_capture_plan(
        _request(
            manifest.to_mapping(),
            identity.to_mapping(),
            catalog.to_mapping(),
            planned.to_mapping(),
        ),
        NOW,
    )


def test_plan_rejects_unknown_fields_and_unsupported_version() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    identity = bound_identity_body()
    catalog = catalog_body()
    plan = capture_plan_body(manifest.manifest_digest, identity, catalog)
    missing = dict(plan)
    del missing["catalog_digest"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = PostgresCapturePlanV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = PostgresCapturePlanV1.from_mapping(plan | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = PostgresCapturePlanV1.from_mapping(plan | {"plan_version": "capture-plan-v0"})


@pytest.mark.parametrize("field", ["system_identifier", "database_oid", "server_version_num"])
def test_identity_inputs_reject_missing_system_db_or_server_values(field: str) -> None:
    missing = identity_inputs_body()
    del missing[field]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = PostgresIdentityInputsV1.from_mapping(missing)
    empty = identity_inputs_body(**{field: ""})
    with pytest.raises(InvalidContractValue):
        _ = PostgresIdentityInputsV1.from_mapping(empty)


def test_verify_rejects_catalog_digest_mismatch() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    catalog = catalog_body()
    identity = bound_identity_body()
    plan = capture_plan_body(manifest.manifest_digest, identity, catalog)
    other = catalog_body(
        rows=[
            {"kind": "schema", "schema_name": "other", "schema_oid": "2201"},
        ],
        row_count="1",
    )
    with pytest.raises(InvalidContractValue, match="catalog"):
        verify_postgres_capture_plan(
            _request(manifest.to_mapping(), identity, other, plan),
            NOW,
        )


def test_verify_rejects_stale_and_future_capture() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    catalog = catalog_body()
    for captured_at in (STALE_CAPTURED_AT, FUTURE_CAPTURED_AT):
        identity = bound_identity_body(captured_at=captured_at)
        plan = capture_plan_body(manifest.manifest_digest, identity, catalog)
        with pytest.raises(InvalidContractValue, match="stale"):
            verify_postgres_capture_plan(
                _request(manifest.to_mapping(), identity, catalog, plan),
                NOW,
            )


def test_plan_rejects_raw_numeric_payload_values() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    plan = capture_plan_body(manifest.manifest_digest, bound_identity_body(), catalog_body())
    encoded = json.dumps(plan, separators=(",", ":"), sort_keys=True)
    numeric = encoded.replace('"16384"', "16384")
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object(numeric)


def test_capture_plan_schema_is_draft_2020_12_and_rejects_extra() -> None:
    manifest = PostgresCaptureQueryManifestV1.closed()
    instance = capture_plan_body(manifest.manifest_digest, bound_identity_body(), catalog_body())
    assert "https://json-schema.org/draft/2020-12/schema" in CAPTURE_PLAN_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert _draft_status(CAPTURE_PLAN_SCHEMA, instance) == 0
    assert _draft_status(CAPTURE_PLAN_SCHEMA, instance | {"extra": "no"}) != 0
