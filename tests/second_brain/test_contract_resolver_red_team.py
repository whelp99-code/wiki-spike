"""Fail-closed red-team cases for the Stage-0 contract resolver CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.test_contract_resolver_cli import (
    APPROVER,
    CLI_FAIL_PREFIX,
    ResolverPaths,
    arguments,
    assert_no_output,
    build_inputs,
    decision,
    evidence_envelope,
    json_array_member,
    json_object_member,
    parse_json_object,
    public_key,
    run_cli,
    write_json,
)
from wiki_spike.memory_core.second_brain_contracts import DecisionRecordV1

STALE_MARKER = "stale"
SAME_IDENTITY_MARKER = "distinct"
UNKNOWN_FIELD_MARKER = "unknown"
NONCANONICAL_MARKER = "canonical"
WRONG_SCOPE_MARKER = "exactly match"
WRONG_DIGEST_MARKER = "digest"
COLLISION_MARKER = "already exists"


def _closed(paths: ResolverPaths, *, marker: str) -> None:
    result = run_cli(arguments(paths))
    assert CLI_FAIL_PREFIX in result.stderr
    assert marker in result.stderr
    assert result.returncode != 0
    assert_no_output(paths["out"])


def test_unknown_json_field_fails_closed_without_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    body = parse_json_object(paths["scope"].read_bytes())
    body["forged"] = "value"
    write_json(paths["scope"], body)
    _closed(paths, marker=UNKNOWN_FIELD_MARKER)


def test_noncanonical_json_fails_closed_without_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    body = parse_json_object(paths["aggregate"].read_bytes())
    _ = paths["aggregate"].write_text(json.dumps(body, indent=2), encoding="utf-8")
    _closed(paths, marker=NONCANONICAL_MARKER)


def test_same_owner_and_approver_key_fails_closed_without_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    bindings = parse_json_object(paths["bindings"].read_bytes())
    shared = public_key(APPROVER)
    aggregate_binding = json_object_member(bindings, "aggregate_binding")
    aggregate_binding["owner_key_id"] = aggregate_binding["approver_key_id"]
    aggregate_binding["owner_public_key_b64"] = shared
    write_json(paths["bindings"], bindings)
    _closed(paths, marker=SAME_IDENTITY_MARKER)


def test_stale_evidence_fails_closed_without_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    envelope = parse_json_object(paths["evidence"].read_bytes())
    body = json_object_member(envelope, "evidence_body")
    body["expires_at"] = "2026-08-18T12:00:00Z"
    write_json(paths["evidence"], evidence_envelope(body))
    _closed(paths, marker=STALE_MARKER)


def test_wrong_scope_and_digest_fail_closed_without_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    scope = parse_json_object(paths["scope"].read_bytes())
    scope["enabled_source_profiles"] = ["Claude/Memory Bank", "Codex", "Git"]
    write_json(paths["scope"], scope)
    _closed(paths, marker=WRONG_SCOPE_MARKER)

    paths = build_inputs(tmp_path / "digest")
    aggregate = parse_json_object(paths["aggregate"].read_bytes())
    aggregate["contract_digest"] = "0" * 64
    write_json(paths["aggregate"], aggregate)
    _closed(paths, marker=WRONG_DIGEST_MARKER)


def test_immutable_output_collision_preserves_existing_bytes(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    existing = b"preexisting-receipt"
    _ = paths["out"].write_bytes(existing)
    result = run_cli(arguments(paths))
    assert CLI_FAIL_PREFIX in result.stderr
    assert COLLISION_MARKER in result.stderr
    assert result.returncode != 0
    assert paths["out"].read_bytes() == existing
    assert list(paths["out"].parent.glob(f".{paths['out'].name}.*.tmp")) == []


@pytest.mark.parametrize("flag", ("--trusted-bindings", "--expected-scopes", "--aggregate", "--evidence-manifest"))
def test_absent_required_artifact_file_fails_before_output(tmp_path: Path, flag: str) -> None:
    paths = build_inputs(tmp_path)
    target = {
        "--trusted-bindings": paths["bindings"],
        "--expected-scopes": paths["expected"],
        "--aggregate": paths["aggregate"],
        "--evidence-manifest": paths["evidence"],
    }[flag]
    target.unlink()
    result = run_cli(arguments(paths))
    assert CLI_FAIL_PREFIX in result.stderr
    assert result.returncode != 0
    assert_no_output(paths["out"])


def test_untrusted_binding_and_extra_record_fail_closed(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    bindings = parse_json_object(paths["bindings"].read_bytes())
    attacker = Ed25519PrivateKey.generate()
    binding_entries = json_array_member(bindings, "decision_bindings")
    first_binding = binding_entries[0]
    if not isinstance(first_binding, dict):
        raise TypeError("fixture decision binding must be an object")
    first_binding["owner_public_key_b64"] = public_key(attacker)
    first_binding["owner_key_id"] = "untrusted-owner"
    write_json(paths["bindings"], bindings)
    _closed(paths, marker="untrusted")

    paths = build_inputs(tmp_path / "extra")
    extra = decision("DB-06", "model-b", "NO_GO")
    write_json(paths["records"] / "99.json", extra)
    assert DecisionRecordV1.from_mapping(extra).scope_name == "model-b"
    _closed(paths, marker="exactly match")
