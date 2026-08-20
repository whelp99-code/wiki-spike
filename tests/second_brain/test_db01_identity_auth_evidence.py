"""Neutral fixture-only DB-01 evidence bundle integration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from wiki_spike.applications.identity_auth_v2_evidence import (
    REQUIRED_CASE_IDS,
    build_identity_auth_v2_evidence,
)
from wiki_spike.memory_core.contracts import canonical_bytes

_COMMIT = "db29cd172fe5190310f5501258554b467728f8e9"
_OBSERVED_AT = "2030-01-01T00:00:00Z"
_WORKSPACE = "workspace:" + "2" * 64
_PROFILE = "profile:" + "3" * 64


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text())
    assert isinstance(value, dict)
    assert all(isinstance(key, str) for key in value)
    return value


def test_builder_emits_exact_neutral_evidence_bundle(tmp_path: Path) -> None:
    build_identity_auth_v2_evidence(
        output_root=tmp_path,
        source_commit=_COMMIT,
        observed_at=_OBSERVED_AT,
        workspace_ref=_WORKSPACE,
        profile_ref=_PROFILE,
    )
    files = sorted(
        path.relative_to(tmp_path).as_posix()
        for path in tmp_path.rglob("*.json")
    )
    assert files == [
        "evidence/db-01-authorization-conformance-v1.json",
        "evidence/db-01-identity-auth-evidence-bundle-v1.json",
        "evidence/db-01-threat-assessment-v1.json",
        "ux/db-01-authorization-ux-v1.json",
    ]
    for relative in files:
        path = tmp_path / relative
        value = _load(path)
        assert path.read_bytes() == canonical_bytes(value) + b"\n"

    conformance = _load(tmp_path / files[0])
    cases = conformance["cases"]
    assert isinstance(cases, list)
    observed_ids = tuple(
        case["case_id"] for case in cases if isinstance(case, dict)
    )
    assert observed_ids == REQUIRED_CASE_IDS
    for case in cases:
        assert isinstance(case, dict)
        if case["expected_outcome"] == "rejected":
            assert case["before_authority_digest"] == case["after_authority_digest"]
            assert case["downstream_write_count"] == "0"
            assert case["audit_id"] is None
    audited = {
        case["case_id"]: case["audit_id"]
        for case in cases
        if isinstance(case, dict)
    }
    for case_id in (
        "owner_enroll_allowed",
        "owner_device_revoke_allowed",
        "delegation_grant_audited",
        "delegation_revoke_audited",
    ):
        assert isinstance(audited[case_id], str)

    assessment = _load(tmp_path / files[2])
    assert assessment["assessment_status"] == "READY_FOR_HUMAN_REVIEW"
    assert assessment["required_threat_ids"] == [
        "COMPROMISE",
        "ENROLLMENT",
        "LOSS",
        "RECOVERY",
        "REVOCATION",
        "WRONG_WORKSPACE",
    ]
    bundle = _load(tmp_path / files[1])
    boundary = bundle["authority_boundary"]
    assert boundary == {
        "decision_outcome_asserted": False,
        "live_operation_authorized": False,
        "machine_evidence": "FIXTURE_ONLY",
        "signature_state": "ABSENT",
    }
    assert bundle["required_case_ids"] == list(REQUIRED_CASE_IDS)
    assert bundle["observed_case_ids"] == list(REQUIRED_CASE_IDS)
    verification = bundle["verification"]
    assert isinstance(verification, dict)
    assert verification["result"] == "PASS"
    serialized = json.dumps(bundle, sort_keys=True)
    assert "private_key" not in serialized
    assert '"decision":"GO"' not in serialized


def test_builder_refuses_overwrite_without_partial_mutation(tmp_path: Path) -> None:
    build_identity_auth_v2_evidence(
        output_root=tmp_path,
        source_commit=_COMMIT,
        observed_at=_OBSERVED_AT,
        workspace_ref=_WORKSPACE,
        profile_ref=_PROFILE,
    )
    before = {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*.json"))
    }

    with pytest.raises(FileExistsError):
        build_identity_auth_v2_evidence(
            output_root=tmp_path,
            source_commit=_COMMIT,
            observed_at=_OBSERVED_AT,
            workspace_ref=_WORKSPACE,
            profile_ref=_PROFILE,
        )

    assert {
        path.relative_to(tmp_path).as_posix(): path.read_bytes()
        for path in sorted(tmp_path.rglob("*.json"))
    } == before
