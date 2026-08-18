"""Failing-first CLI contract for the Stage-0 Second Brain resolver."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from base64 import b64encode
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from typing import TypedDict, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
    detached_signing_bytes,
)

NOW, DIGEST = "2026-08-18T12:00:00Z", "a" * 64
ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "second_brain_contract_resolver.py"
CURRENT = ROOT / "artifacts" / "product-release" / "second-brain-v1" / "decisions"
CORE_COVERAGE_ERROR = "decision evidence does not exactly match the expected-scope manifest"
CLI_FAIL_PREFIX = "FAIL:"
RECEIPT_VERSION = "second-brain-contract-resolution-receipt-v1"
EVIDENCE_MANIFEST_VERSION = "second-brain-evidence-manifest-v1"
EVIDENCE_ENVELOPE_VERSION = "second-brain-evidence-manifest-envelope-v1"
EVIDENCE_SIGNATURE_VERSION = "second-brain-evidence-manifest-signature-v1"
EVIDENCE_SIGNING_DOMAIN = b"wiki-spike.second-brain.evidence-manifest.v1\x00"
OWNER, APPROVER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
SOURCES = ("Claude/Memory Bank", "Codex", "Git", "Markdown")
MIGRATIONS = ("legacy Mem0/RAG", "me-wiki", "unified-db")
SCOPED = (
    *(("DB-02", "source_profile", name) for name in SOURCES),
    *(("DB-03", "migration_source", name) for name in MIGRATIONS),
    ("DB-06", "external_model_route", "model-a"),
    ("DB-08", "export_destination", "archive"),
)
KIND = {"DB-02": "source_profile", "DB-03": "migration_source", "DB-06": "external_model_route", "DB-08": "export_destination"}


type JsonValue = None | bool | int | float | str | Sequence[JsonValue] | Mapping[str, JsonValue]
type JsonObject = dict[str, JsonValue]


class ResolverPaths(TypedDict):
    records: Path
    scope: Path
    expected: Path
    aggregate: Path
    bindings: Path
    evidence: Path
    out: Path


class AuthorityMapping(TypedDict):
    approver_key_id: str
    approver_public_key_b64: str
    owner_key_id: str
    owner_public_key_b64: str


class SignatureMapping(TypedDict):
    signature_version: str
    role: str
    key_id: str
    public_key_b64: str
    signature_b64: str


def parse_json_object(raw: bytes | str) -> JsonObject:
    parsed = cast(JsonValue, json.loads(raw))
    if not isinstance(parsed, dict):
        raise TypeError("fixture JSON must be an object")
    return parsed


def json_object_member(value: JsonObject, key: str) -> JsonObject:
    member = value[key]
    if not isinstance(member, dict):
        raise TypeError(f"fixture field {key} must be an object")
    return member


def json_array_member(value: JsonObject, key: str) -> list[JsonValue]:
    member = value[key]
    if not isinstance(member, list):
        raise TypeError(f"fixture field {key} must be an array")
    return member


def public_key(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def write_json(path: Path, value: Mapping[str, JsonValue]) -> None:
    _ = path.write_bytes(canonical_bytes(value))


def authority() -> JsonObject:
    binding: AuthorityMapping = {
        "approver_key_id": "approver",
        "approver_public_key_b64": public_key(APPROVER),
        "owner_key_id": "owner",
        "owner_public_key_b64": public_key(OWNER),
    }
    return {
        "approver_key_id": binding["approver_key_id"],
        "approver_public_key_b64": binding["approver_public_key_b64"],
        "owner_key_id": binding["owner_key_id"],
        "owner_public_key_b64": binding["owner_public_key_b64"],
    }


def sign(domain: bytes, body: Mapping[str, JsonValue], version: str) -> list[JsonValue]:
    payload = detached_signing_bytes(domain, body)
    signatures: list[JsonValue] = []
    for role, name, key in (
        ("approver", "approver", APPROVER),
        ("owner", "owner", OWNER),
    ):
        signature: SignatureMapping = {
            "signature_version": version,
            "role": role,
            "key_id": name,
            "public_key_b64": public_key(key),
            "signature_b64": b64encode(key.sign(payload)).decode("ascii"),
        }
        signatures.append(
            {
                "signature_version": signature["signature_version"],
                "role": signature["role"],
                "key_id": signature["key_id"],
                "public_key_b64": signature["public_key_b64"],
                "signature_b64": signature["signature_b64"],
            }
        )
    return signatures


def decision(decision_id: str, scope_name: str | None = None, outcome: str = "GO") -> JsonObject:
    kind = KIND.get(decision_id, "global")
    body: JsonObject = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": decision_id,
        "outcome": outcome,
        "scope_kind": kind,
        "scope_name": None if kind == "global" else scope_name,
        "record_revision": "1",
        "decided_at": "2026-08-18T11:00:00Z",
        "supersedes": None,
        "post_interview_reconciliation": {"original_question": f"q-{decision_id}", "reconciliation": f"r-{decision_id}"},
        "reason": f"reason for {decision_id}",
        "evidence_refs": [f"evidence-{decision_id}"],
        "evidence_digest": DIGEST,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    body["signatures"] = sign(DECISION_SIGNING_DOMAIN, body, DECISION_SIGNATURE_VERSION)
    return body


def scope_mapping() -> JsonObject:
    return {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": list(SOURCES),
        "disabled_source_profiles": {},
        "enabled_migration_sources": list(MIGRATIONS),
        "disabled_migration_sources": {},
        "feature_flags": ["benchmark-governance", "conflict-behavior", "cutover-retention", "identity-auth"],
        "egress_destinations": [],
        "enabled_external_model_routes": [],
        "disabled_external_model_routes": {"model-a": "signed NO_GO"},
        "disabled_export_destinations": {"archive": "signed NO_GO"},
        "capability_manifest_digest": DIGEST,
        "source_manifest_digest": DIGEST,
        "mandatory_release_constraints": ["signed-release-baseline"],
    }


def evidence_envelope(body: JsonObject) -> JsonObject:
    payload: JsonObject = {
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": sha256(canonical_bytes(body)).hexdigest(),
        "evidence_body": body,
    }
    return {
        **payload,
        "signatures": sign(
            EVIDENCE_SIGNING_DOMAIN,
            payload,
            EVIDENCE_SIGNATURE_VERSION,
        ),
    }


def records(*, current_world: bool) -> list[JsonObject]:
    if current_world:
        result: list[JsonObject] = []
        for name in ("DB-04.json", "DB-06-model-a.json", "DB-08-archive.json"):
            item = parse_json_object((CURRENT / name).read_bytes())
            _ = DecisionRecordV1.from_mapping(item)
            result.append(item)
        return result
    return [
        *(decision(decision_id) for decision_id in ("DB-01", "DB-04", "DB-05", "DB-07")),
        *(decision("DB-02", name) for name in SOURCES),
        *(decision("DB-03", name) for name in MIGRATIONS),
        decision("DB-06", "model-a", "NO_GO"),
        decision("DB-08", "archive", "NO_GO"),
    ]


def build_inputs(tmp_path: Path, *, current_world: bool = False) -> ResolverPaths:
    records_dir = tmp_path / "records"
    records_dir.mkdir(parents=True)
    decisions = records(current_world=current_world)
    for index, record in enumerate(decisions):
        write_json(records_dir / f"{index:02d}.json", record)
    scope = scope_mapping()
    expected: JsonObject = {
        "manifest_version": "second-brain-expected-scope-manifest-v1",
        "expected_scopes": [
            {"decision_id": d, "scope_kind": k, "scope_name": n}
            for d, k, n in SCOPED
        ],
    }
    paths: ResolverPaths = {
        "records": records_dir,
        "scope": tmp_path / "scope.json",
        "expected": tmp_path / "expected.json",
        "aggregate": tmp_path / "aggregate.json",
        "bindings": tmp_path / "bindings.json",
        "evidence": tmp_path / "evidence.json",
        "out": tmp_path / "receipt.json",
    }
    write_json(paths["scope"], scope)
    write_json(paths["expected"], expected)
    parsed = tuple(DecisionRecordV1.from_mapping(item) for item in decisions)
    contract = SecondBrainContractDigestV1.create(
        parsed, ResolvedScopeV1.from_mapping(scope), ExpectedScopeManifestV1.from_mapping(expected)
    )
    contract_body: JsonObject = {
        "contract_version": contract.contract_version,
        "decision_digests": [
            {"decision_id": decision_id, "scope_kind": kind, "scope_name": name, "digest": digest}
            for decision_id, kind, name, digest in contract.decision_digests
        ],
        "resolved_scope": scope,
        "expected_scope_manifest": expected,
    }
    payload: JsonObject = {
        "contract_version": contract.contract_version,
        "contract_body": contract_body,
        "contract_digest": contract.digest,
    }
    write_json(paths["aggregate"], {
        "contract_envelope_version": "second-brain-contract-envelope-v1",
        **payload,
        "signatures": sign(CONTRACT_SIGNING_DOMAIN, payload, CONTRACT_SIGNATURE_VERSION),
    })
    identities: list[tuple[str, str, str | None]]
    if current_world:
        identities = [
            ("DB-01", "global", None),
            ("DB-04", "global", None),
            ("DB-05", "global", None),
            ("DB-07", "global", None),
            *SCOPED,
        ]
    else:
        identities = []
        for item in decisions:
            decision_id = item["decision_id"]
            scope_kind = item["scope_kind"]
            scope_name = item["scope_name"]
            if not isinstance(decision_id, str) or not isinstance(scope_kind, str):
                raise TypeError("fixture decision identity must contain strings")
            if scope_name is not None and not isinstance(scope_name, str):
                raise TypeError("fixture scope name must be a string or null")
            identities.append((decision_id, scope_kind, scope_name))
    write_json(paths["bindings"], {
        "trusted_bindings_version": "second-brain-trusted-decision-key-bindings-v1",
        "decision_bindings": [
            {"decision_id": d, "scope_kind": k, "scope_name": n, **authority()}
            for d, k, n in sorted(identities, key=lambda item: (item[0], item[1], item[2] or ""))
        ],
        "aggregate_binding": authority(),
    })
    write_json(paths["evidence"], evidence_envelope({
        "evidence_manifest_version": EVIDENCE_MANIFEST_VERSION,
        "observed_at": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-18T13:00:00Z",
        "decision_evidence": [
            {"decision_id": item["decision_id"], "scope_kind": item["scope_kind"], "scope_name": item["scope_name"], "evidence_digest": item["evidence_digest"]}
            for item in sorted(decisions, key=lambda row: (str(row["decision_id"]), str(row["scope_kind"]), row["scope_name"] or ""))
        ],
    }))
    return paths


def arguments(paths: ResolverPaths, *, now: str = NOW, omit: str | None = None) -> list[str]:
    flags = {
        "--records-dir": paths["records"],
        "--resolved-scope": paths["scope"],
        "--expected-scopes": paths["expected"],
        "--aggregate": paths["aggregate"],
        "--trusted-bindings": paths["bindings"],
        "--evidence-manifest": paths["evidence"],
        "--now": now,
        "--out": paths["out"],
    }
    args = ["resolve"]
    for flag, value in flags.items():
        if flag != omit:
            args.extend([flag, str(value)])
    return args


def run_cli(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src"), "PYTHONHASHSEED": "0"},
    )


def assert_no_output(out: Path) -> None:
    assert not out.exists()
    assert list(out.parent.glob(f".{out.name}.*.tmp")) == []


def test_help_succeeds_when_cli_exists() -> None:
    result = run_cli(["--help"])
    combined = f"{result.stdout}{result.stderr}"
    assert result.returncode == 0
    assert all(flag in combined for flag in ("--records-dir", "--trusted-bindings", "--expected-scopes", "--aggregate", "--evidence-manifest"))


def test_current_incomplete_decision_set_fails_closed_with_core_coverage_error(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path, current_world=True)
    staged: set[str] = set()
    for path in paths["records"].glob("*.json"):
        decision_id = parse_json_object(path.read_bytes())["decision_id"]
        if not isinstance(decision_id, str):
            raise TypeError("fixture decision_id must be a string")
        staged.add(decision_id)
    assert staged == {"DB-04", "DB-06", "DB-08"}
    result = run_cli(arguments(paths))
    assert CORE_COVERAGE_ERROR in result.stderr
    assert CLI_FAIL_PREFIX in result.stderr
    assert result.returncode != 0
    assert_no_output(paths["out"])


def test_missing_required_input_fails_before_output(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    for flag in ("--trusted-bindings", "--expected-scopes", "--aggregate", "--evidence-manifest", "--records-dir"):
        result = run_cli(arguments(paths, omit=flag))
        assert CLI_FAIL_PREFIX in result.stderr
        assert flag in result.stderr
        assert result.returncode != 0
        assert_no_output(paths["out"])


def test_valid_signed_fixture_writes_canonical_scope_and_receipt(tmp_path: Path) -> None:
    paths = build_inputs(tmp_path)
    result = run_cli(arguments(paths))
    assert result.returncode == 0
    raw = paths["out"].read_bytes()
    receipt = parse_json_object(raw)
    assert raw == canonical_bytes(receipt)
    assert receipt["resolution_receipt_version"] == RECEIPT_VERSION
    assert receipt["resolver_outcome"] == "RESOLVED"
    assert receipt["stage0_contract_usable"] is True
    assert receipt["live_operation_authorized"] is False
    parsed_scope = ResolvedScopeV1.from_mapping(
        json_object_member(receipt, "resolved_scope")
    )
    assert parsed_scope.scope_version == "second-brain-resolved-scope-v1"
    aggregate = parse_json_object(paths["aggregate"].read_bytes())
    assert receipt["contract_digest"] == aggregate["contract_digest"]
    assert list(paths["out"].parent.glob(f".{paths['out'].name}.*.tmp")) == []
