"""Binding tests for live-export commitments, plan, and authorization."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from tests.second_brain.unified_db_live_export_support import (
    ADAPTER_SCHEMA,
    CONFORMANCE_EVIDENCE,
    CONFORMANCE_SCHEMA,
    DESTINATION_SCHEMA,
    LIVE_PLAN_SCHEMA,
    LIVE_PLAN_VERSION,
    NOW,
    QUIESCENCE_SCHEMA,
    adapter_body,
    bound_authorization,
    consistent_live_export_bundle,
    destination_body,
    identity_body,
    live_plan_body,
    mapping_body,
    quiescence_body,
)
from wiki_spike.applications.unified_db_live_export_verify import (
    LiveExportVerifyRequestV1,
    verify_live_export_plan,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_live_export_plan import UnifiedDbLiveExportPlanV1
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _request(bundle: dict[str, dict[str, JsonValue]]) -> LiveExportVerifyRequestV1:
    return LiveExportVerifyRequestV1.from_mappings(bundle)


def test_plan_binds_identity_mapping_adapter_destination_and_quiescence() -> None:
    bundle = consistent_live_export_bundle()
    plan = UnifiedDbLiveExportPlanV1.from_mapping(bundle["plan"])
    assert plan.plan_version == LIVE_PLAN_VERSION
    assert plan.authorization_kind == "LIVE_EXPORT_ONLY"
    assert plan.source_identity_digest == bundle["identity"]["identity_digest"]
    assert plan.mapper_id != plan.source_identity_digest
    assert plan.mapping_digest == bundle["mapping"]["mapping_digest"]
    assert plan.adapter_digest == bundle["adapter"]["adapter_digest"]
    assert plan.destination_digest == bundle["destination"]["destination_digest"]
    assert plan.quiescence_digest == bundle["quiescence"]["quiescence_digest"]
    assert plan.plan_digest == plan.computed_digest()
    verify_live_export_plan(_request(bundle), NOW)

    bundle["unexpected"] = {"value": "no"}
    with pytest.raises(InvalidContractValue, match="unexpected"):
        _ = _request(bundle)


def test_plan_rejects_missing_extra_and_unsupported_version() -> None:
    bundle = consistent_live_export_bundle()
    missing = dict(bundle["plan"])
    del missing["mapping_digest"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = UnifiedDbLiveExportPlanV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbLiveExportPlanV1.from_mapping(bundle["plan"] | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = UnifiedDbLiveExportPlanV1.from_mapping(
            live_plan_body(
                {
                    "identity": bundle["identity"],
                    "mapping": bundle["mapping"],
                    "adapter": bundle["adapter"],
                    "destination": bundle["destination"],
                    "quiescence": bundle["quiescence"],
                },
                plan_version="live-plan-v0",
            )
        )


@pytest.mark.parametrize(
    "field",
    ["mapping_digest", "adapter_digest", "destination_digest", "quiescence_digest"],
)
def test_verify_rejects_digest_mismatch(field: str) -> None:
    bundle = consistent_live_export_bundle()
    other = "cc" * 32
    if field == "mapping_digest":
        bundle["mapping"] = mapping_body(
            str(bundle["identity"]["identity_digest"]),
            select_template_digest=other,
        )
    elif field == "adapter_digest":
        bundle["adapter"] = adapter_body(select_template_digest=other)
    elif field == "destination_digest":
        bundle["destination"] = destination_body(destination_id="other-dest")
    else:
        bundle["quiescence"] = quiescence_body(
            str(bundle["identity"]["identity_digest"]),
            captured_at="2026-08-18T12:06:00Z",
        )
    with pytest.raises(InvalidContractValue, match="digest"):
        verify_live_export_plan(_request(bundle), NOW)


def test_verify_rejects_wrong_source_database_identity() -> None:
    bundle = consistent_live_export_bundle()
    bundle["identity"] = identity_body(system_identifier="1")
    with pytest.raises(InvalidContractValue, match="identity"):
        verify_live_export_plan(_request(bundle), NOW)


def test_verify_rejects_stale_identity() -> None:
    bundle = consistent_live_export_bundle()
    bundle["identity"] = identity_body(captured_at="2026-08-18T11:50:00Z")
    bundle["mapping"] = mapping_body(str(bundle["identity"]["identity_digest"]))
    bundle["quiescence"] = quiescence_body(str(bundle["identity"]["identity_digest"]))
    bundle["plan"] = live_plan_body(
        {
            "identity": bundle["identity"],
            "mapping": bundle["mapping"],
            "adapter": bundle["adapter"],
            "destination": bundle["destination"],
            "quiescence": bundle["quiescence"],
        }
    )
    bundle["authorization"] = bound_authorization(bundle["plan"])
    with pytest.raises(InvalidContractValue, match="identity is stale"):
        verify_live_export_plan(_request(bundle), NOW)

    for captured_at in ("2026-08-18T11:50:00Z", "2026-08-18T12:11:00Z"):
        candidate = consistent_live_export_bundle()
        candidate["quiescence"] = quiescence_body(
            str(candidate["identity"]["identity_digest"]),
            captured_at=captured_at,
        )
        candidate["plan"] = live_plan_body(
            {
                "identity": candidate["identity"],
                "mapping": candidate["mapping"],
                "adapter": candidate["adapter"],
                "destination": candidate["destination"],
                "quiescence": candidate["quiescence"],
            }
        )
        candidate["authorization"] = bound_authorization(candidate["plan"])
        with pytest.raises(InvalidContractValue, match="quiescence is stale"):
            verify_live_export_plan(_request(candidate), NOW)


def test_verify_rejects_plan_authorization_mismatch() -> None:
    bundle = consistent_live_export_bundle()
    bundle["authorization"] = bound_authorization(bundle["plan"], plan_digest="dd" * 32)
    with pytest.raises(InvalidContractValue, match="plan"):
        verify_live_export_plan(_request(bundle), NOW)

    expired = consistent_live_export_bundle()
    expired["authorization"] = bound_authorization(
        expired["plan"],
        issued_at="2026-08-18T11:55:00Z",
        not_before="2026-08-18T11:55:00Z",
        expires_at="2026-08-18T12:09:00Z",
    )
    with pytest.raises(InvalidContractValue, match="authorization is expired"):
        verify_live_export_plan(_request(expired), NOW)


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


def test_commitment_and_plan_schemas_are_draft_2020_12() -> None:
    bundle = consistent_live_export_bundle()
    pairs = (
        (ADAPTER_SCHEMA, bundle["adapter"]),
        (DESTINATION_SCHEMA, bundle["destination"]),
        (QUIESCENCE_SCHEMA, bundle["quiescence"]),
        (LIVE_PLAN_SCHEMA, bundle["plan"]),
    )
    for schema_path, instance in pairs:
        assert "https://json-schema.org/draft/2020-12/schema" in schema_path.read_text(
            encoding="utf-8"
        )
        assert _draft_status(schema_path, instance) == 0
        assert _draft_status(schema_path, instance | {"extra": "no"}) != 0


def test_conformance_evidence_is_body_free_and_registry_empty() -> None:
    evidence = decode_json_object(CONFORMANCE_EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["body_present"] is False
    assert evidence["private_key_material"] is False
    assert evidence["live_export_authorized"] is False
    assert evidence["dsn_read"] is False
    assert evidence["production_registry_empty"] is True
    assert evidence["approved_mapping_count"] == "0"
    assert "body" not in evidence
    assert _draft_status(CONFORMANCE_SCHEMA, evidence) == 0
    assert _draft_status(CONFORMANCE_SCHEMA, evidence | {"extra": "no"}) != 0
