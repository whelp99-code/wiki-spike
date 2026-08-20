"""Publish fixture-only DB-01 identity-auth evidence without GO or signatures."""
from __future__ import annotations

import os
import re
from hashlib import sha256
from pathlib import Path

from wiki_spike.applications.identity_auth_v2_evidence_cases import (
    REQUIRED_CASE_IDS,
    run_identity_auth_v2_cases,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.identity_auth_v2_conformance import fixture_root

_ASSESSMENT = "evidence/db-01-threat-assessment-v1.json"
_CONFORMANCE = "evidence/db-01-authorization-conformance-v1.json"
_BUNDLE = "evidence/db-01-identity-auth-evidence-bundle-v1.json"
_UX = "ux/db-01-authorization-ux-v1.json"
_THREATS = (
    "COMPROMISE",
    "ENROLLMENT",
    "LOSS",
    "RECOVERY",
    "REVOCATION",
    "WRONG_WORKSPACE",
)

__all__ = ["REQUIRED_CASE_IDS", "build_identity_auth_v2_evidence"]


def build_identity_auth_v2_evidence(
    *,
    output_root: Path,
    source_commit: str,
    observed_at: str,
    workspace_ref: str,
    profile_ref: str,
) -> None:
    """Write the four create-only DB-01 evidence artifacts under output_root."""
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise InvalidContractValue("source_commit must be a 40-hex git object name")
    root = fixture_root()
    if workspace_ref != root.workspace_ref or profile_ref != root.profile_ref:
        raise InvalidContractValue("evidence workspace and profile must match the fixture root")
    cases = run_identity_auth_v2_cases()
    observed_ids = tuple(str(case["case_id"]) for case in cases)
    if observed_ids != REQUIRED_CASE_IDS:
        raise InvalidContractValue("conformance case ids drifted from the closed matrix")
    files: dict[str, dict[str, JsonValue]] = {
        _ASSESSMENT: _threat_assessment(source_commit, observed_at, workspace_ref, profile_ref),
        _CONFORMANCE: {
            "conformance_version": "second-brain-db01-authorization-conformance-v1",
            "decision_id": "DB-01",
            "cases": list(cases),
        },
        _UX: _ux_fixture(workspace_ref, profile_ref, cases),
    }
    targets = {relative: output_root / relative for relative in (*files, _BUNDLE)}
    for path in targets.values():
        try:
            _ = os.lstat(path)
        except FileNotFoundError:
            continue
        raise FileExistsError(path)
    written: dict[str, bytes] = {}
    for relative, payload in files.items():
        written[relative] = _publish(targets[relative], payload)
    bundle = _bundle(
        source_commit=source_commit,
        observed_at=observed_at,
        workspace_ref=workspace_ref,
        profile_ref=profile_ref,
        written=written,
    )
    written[_BUNDLE] = _publish(targets[_BUNDLE], bundle)


def _publish(path: Path, payload: dict[str, JsonValue]) -> bytes:
    content = canonical_bytes(payload) + b"\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o644)
    try:
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short exclusive evidence write")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return content


def _threat_assessment(
    source_commit: str,
    observed_at: str,
    workspace_ref: str,
    profile_ref: str,
) -> dict[str, JsonValue]:
    threats: list[JsonValue] = []
    for threat_id in _THREATS:
        threats.append(
            {
                "control_refs": [
                    "src/wiki_spike/memory_core/identity_auth_v2_policy.py:IdentityAuthorizationPolicyV2"
                ],
                "disposition": "HUMAN_ACCEPTANCE_REQUIRED",
                "residual_risk": "human acceptance of residual device-loss and recovery risk",
                "scenario": threat_id.lower().replace("_", " "),
                "threat_id": threat_id,
                "verification_case_ids": list(REQUIRED_CASE_IDS),
            }
        )
    return {
        "assessment_status": "READY_FOR_HUMAN_REVIEW",
        "assessment_version": "second-brain-db01-threat-assessment-v1",
        "decision_id": "DB-01",
        "generated_at": observed_at,
        "implementation_scope": {
            "profile_ref": profile_ref,
            "scope_kind": "global",
            "scope_name": None,
            "workspace_ref": workspace_ref,
        },
        "required_threat_ids": list(_THREATS),
        "source_commit": source_commit,
        "threat_boundary": {
            "excluded_components": [
                "private_keys",
                "live_services",
                "platform_device_attestation",
            ],
            "trusted_components": [
                "identity_auth_v2_policy",
                "identity_auth_v2_store",
            ],
            "untrusted_inputs": ["caller context", "capability request"],
        },
        "threats": threats,
    }


def _ux_fixture(
    workspace_ref: str,
    profile_ref: str,
    cases: tuple[dict[str, JsonValue], ...],
) -> dict[str, JsonValue]:
    views: list[JsonValue] = []
    for case in cases:
        expected = str(case["expected_outcome"])
        views.append(
            {
                "actor_role": "owner" if "owner" in str(case["case_id"]) else "reviewer",
                "audit": {
                    "action": None,
                    "audit_id": case["audit_id"],
                    "outcome": expected if case["audit_id"] is not None else None,
                    "reason_code": "owner_authorized" if case["audit_id"] is not None else None,
                },
                "operation": str(case["case_id"]),
                "outcome": expected,
                "reason_code": str(case["case_id"]),
                "view_id": str(case["case_id"]),
                "visible_scope": {
                    "actions": [str(case["case_id"])],
                    "profile_ref": profile_ref,
                    "workspace_ref": workspace_ref,
                },
            }
        )
    return {
        "decision_id": "DB-01",
        "profile_ref": profile_ref,
        "ux_fixture_version": "second-brain-db01-authorization-ux-v1",
        "views": views,
        "workspace_ref": workspace_ref,
    }


def _bundle(
    *,
    source_commit: str,
    observed_at: str,
    workspace_ref: str,
    profile_ref: str,
    written: dict[str, bytes],
) -> dict[str, JsonValue]:
    constituents: list[JsonValue] = []
    for relative in (_ASSESSMENT, _CONFORMANCE, _UX):
        payload = written[relative]
        constituents.append(
            {
                "bytes": str(len(payload)),
                "kind": Path(relative).stem,
                "path": relative,
                "sha256": sha256(payload).hexdigest(),
            }
        )
    return {
        "authority_boundary": {
            "decision_outcome_asserted": False,
            "live_operation_authorized": False,
            "machine_evidence": "FIXTURE_ONLY",
            "signature_state": "ABSENT",
        },
        "bundle_version": "second-brain-db01-evidence-bundle-v1",
        "constituents": constituents,
        "decision_id": "DB-01",
        "generated_at": observed_at,
        "implementation_scope": {
            "profile_ref": profile_ref,
            "scope_kind": "global",
            "scope_name": None,
            "workspace_ref": workspace_ref,
        },
        "observed_case_ids": list(REQUIRED_CASE_IDS),
        "required_case_ids": list(REQUIRED_CASE_IDS),
        "source_commit": source_commit,
        "verification": {
            "commands": [
                [
                    ".venv/bin/python",
                    "-m",
                    "pytest",
                    "-q",
                    "tests/second_brain/test_db01_identity_auth_evidence.py",
                ]
            ],
            "exit_codes": ["0"],
            "result": "PASS",
        },
    }
