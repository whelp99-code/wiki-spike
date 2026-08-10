from __future__ import annotations

from base64 import b64encode
import json
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import second_brain_contract_resolver as TOOL
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    FATAL_DECISIONS,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
    detached_signing_bytes,
)

NOW = "2026-08-09T12:00:00Z"
DIGEST = "a" * 64
OWNER = Ed25519PrivateKey.generate()
APPROVER = Ed25519PrivateKey.generate()


def _public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def _write(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_bytes(value))


def _decision(
    decision_id: str, scope_name: str | None = None, outcome: str = "GO", *,
    expires_at: str = "2030-01-01T00:00:00Z",
) -> dict[str, object]:
    kind = {
        "DB-02": "source_profile", "DB-03": "migration_source",
        "DB-06": "external_model_route", "DB-08": "export_destination",
    }.get(decision_id, "global")
    body: dict[str, object] = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": decision_id,
        "outcome": outcome,
        "scope_kind": kind,
        "scope_name": scope_name if kind != "global" else None,
        "record_revision": "1",
        "decided_at": "2026-08-09T11:00:00Z",
        "supersedes": None,
        "post_interview_reconciliation": {
            "original_question": f"original question for {decision_id}",
            "reconciliation": f"reconciled {decision_id}",
        },
        "reason": f"reason for {decision_id}",
        "evidence_refs": [f"evidence-{decision_id}"],
        "evidence_digest": DIGEST,
        "expires_at": expires_at,
    }
    payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, body)
    body["signatures"] = [
        {
            "signature_version": DECISION_SIGNATURE_VERSION,
            "role": "approver",
            "key_id": "approver",
            "public_key_b64": _public(APPROVER),
            "signature_b64": b64encode(APPROVER.sign(payload)).decode("ascii"),
        },
        {
            "signature_version": DECISION_SIGNATURE_VERSION,
            "role": "owner",
            "key_id": "owner",
            "public_key_b64": _public(OWNER),
            "signature_b64": b64encode(OWNER.sign(payload)).decode("ascii"),
        },
    ]
    return body


def _scope() -> dict[str, object]:
    return {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": ["Claude/Memory Bank", "Codex", "Git", "Markdown"],
        "disabled_source_profiles": {},
        "enabled_migration_sources": ["legacy Mem0/RAG", "me-wiki", "unified-db"],
        "disabled_migration_sources": {},
        "feature_flags": ["benchmark-governance", "conflict-behavior", "cutover-retention", "identity-auth"],
        "egress_destinations": ["archive"],
        "enabled_external_model_routes": ["model-a"],
        "disabled_external_model_routes": {},
        "disabled_export_destinations": {},
        "capability_manifest_digest": DIGEST,
        "source_manifest_digest": DIGEST,
        "mandatory_release_constraints": ["signed-release-baseline"],
    }


def _expected() -> dict[str, object]:
    scopes = (
        ("DB-02", "source_profile", "Claude/Memory Bank"),
        ("DB-02", "source_profile", "Codex"),
        ("DB-02", "source_profile", "Git"),
        ("DB-02", "source_profile", "Markdown"),
        ("DB-03", "migration_source", "legacy Mem0/RAG"),
        ("DB-03", "migration_source", "me-wiki"),
        ("DB-03", "migration_source", "unified-db"),
        ("DB-06", "external_model_route", "model-a"),
        ("DB-08", "export_destination", "archive"),
    )
    return {
        "manifest_version": "second-brain-expected-scope-manifest-v1",
        "expected_scopes": [
            {"decision_id": decision_id, "scope_kind": kind, "scope_name": name}
            for decision_id, kind, name in scopes
        ],
    }


def _authority() -> dict[str, str]:
    return {
        "approver_key_id": "approver",
        "approver_public_key_b64": _public(APPROVER),
        "owner_key_id": "owner",
        "owner_public_key_b64": _public(OWNER),
    }


def trusted_authority(*, now: str = NOW) -> TOOL.TrustedResolverAuthority:
    """Test-only stand-in for the deployment's out-of-band trust injection."""
    binding = TOOL._authority(_authority(), "test injected authority")
    expected = ExpectedScopeManifestV1.from_mapping(_expected())
    registry = {
        (decision_id, "global", None): binding
        for decision_id in FATAL_DECISIONS
    }
    registry.update({identity: binding for identity in expected.expected_scopes})
    return TOOL.TrustedResolverAuthority(
        TOOL.TrustedDecisionKeyBindingsV1(registry, binding),
        TOOL._timestamp(now, "test trusted clock"),
    )


def _evidence_envelope(
    body: dict[str, object], *, approver: Ed25519PrivateKey = APPROVER,
    owner: Ed25519PrivateKey = OWNER, approver_key_id: str = "approver",
    owner_key_id: str = "owner", domain: bytes = TOOL.EVIDENCE_SIGNING_DOMAIN,
) -> dict[str, object]:
    manifest_digest = sha256(canonical_bytes(body)).hexdigest()
    payload = {
        "evidence_envelope_version": TOOL.EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": manifest_digest,
        "evidence_body": body,
    }
    return {
        **payload,
        "signatures": [
            {
                "signature_version": TOOL.EVIDENCE_SIGNATURE_VERSION,
                "role": "approver", "key_id": approver_key_id,
                "public_key_b64": _public(approver),
                "signature_b64": b64encode(approver.sign(detached_signing_bytes(domain, payload))).decode("ascii"),
            },
            {
                "signature_version": TOOL.EVIDENCE_SIGNATURE_VERSION,
                "role": "owner", "key_id": owner_key_id,
                "public_key_b64": _public(owner),
                "signature_b64": b64encode(owner.sign(detached_signing_bytes(domain, payload))).decode("ascii"),
            },
        ],
    }


def build_inputs(tmp_path: Path, *, blocked: bool = False, expired: bool = False) -> dict[str, Path]:
    records_dir = tmp_path / "records"
    records_dir.parent.mkdir(parents=True, exist_ok=True)
    records_dir.mkdir()
    decisions = [
        _decision(
            "DB-01", outcome="NO_GO" if blocked else "GO",
            expires_at="2026-08-09T11:59:59Z" if expired else "2030-01-01T00:00:00Z",
        ),
        _decision("DB-04"), _decision("DB-05"), _decision("DB-07"),
        *[_decision("DB-02", name) for name in ("Claude/Memory Bank", "Codex", "Git", "Markdown")],
        *[_decision("DB-03", name) for name in ("legacy Mem0/RAG", "me-wiki", "unified-db")],
        _decision("DB-06", "model-a"), _decision("DB-08", "archive"),
    ]
    for index, record in enumerate(decisions):
        _write(records_dir / f"{index:02d}.json", record)
    scope_path, expected_path = tmp_path / "scope.json", tmp_path / "expected.json"
    scope, expected = _scope(), _expected()
    _write(scope_path, scope)
    _write(expected_path, expected)
    parsed_decisions = tuple(DecisionRecordV1.from_mapping(item) for item in decisions)
    parsed_scope = ResolvedScopeV1.from_mapping(scope)
    parsed_expected = ExpectedScopeManifestV1.from_mapping(expected)
    contract = SecondBrainContractDigestV1.create(parsed_decisions, parsed_scope, parsed_expected)
    payload = {
        "contract_version": contract.contract_version,
        "contract_body": contract.body(),
        "contract_digest": contract.digest,
    }
    aggregate = {
        "contract_envelope_version": "second-brain-contract-envelope-v1",
        **payload,
        "signatures": [
            {
                "signature_version": CONTRACT_SIGNATURE_VERSION,
                "role": "approver", "key_id": "approver", "public_key_b64": _public(APPROVER),
                "signature_b64": b64encode(APPROVER.sign(detached_signing_bytes(CONTRACT_SIGNING_DOMAIN, payload))).decode("ascii"),
            },
            {
                "signature_version": CONTRACT_SIGNATURE_VERSION,
                "role": "owner", "key_id": "owner", "public_key_b64": _public(OWNER),
                "signature_b64": b64encode(OWNER.sign(detached_signing_bytes(CONTRACT_SIGNING_DOMAIN, payload))).decode("ascii"),
            },
        ],
    }
    aggregate_path = tmp_path / "aggregate.json"
    _write(aggregate_path, aggregate)
    binding_entries = []
    for record in sorted(
        decisions,
        key=lambda item: (str(item["decision_id"]), str(item["scope_kind"]), item["scope_name"] or ""),
    ):
        binding_entries.append({
            "decision_id": record["decision_id"], "scope_kind": record["scope_kind"],
            "scope_name": record["scope_name"], **_authority(),
        })
    bindings_path = tmp_path / "bindings.json"
    _write(bindings_path, {
        "trusted_bindings_version": "second-brain-trusted-decision-key-bindings-v1",
        "decision_bindings": binding_entries,
        "aggregate_binding": _authority(),
    })
    evidence_entries = [
        {
            "decision_id": record["decision_id"], "scope_kind": record["scope_kind"],
            "scope_name": record["scope_name"], "evidence_digest": record["evidence_digest"],
        }
        for record in sorted(
            decisions,
            key=lambda item: (str(item["decision_id"]), str(item["scope_kind"]), item["scope_name"] or ""),
        )
    ]
    evidence_path = tmp_path / "evidence.json"
    evidence_body = {
        "evidence_manifest_version": "second-brain-evidence-manifest-v1",
        "observed_at": "2026-08-09T11:00:00Z",
        "expires_at": "2026-08-09T13:00:00Z",
        "decision_evidence": evidence_entries,
    }
    _write(evidence_path, _evidence_envelope(evidence_body))
    return {
        "records": records_dir, "scope": scope_path, "expected": expected_path,
        "aggregate": aggregate_path, "bindings": bindings_path, "evidence": evidence_path,
        "out": tmp_path / "receipt.json",
    }


def arguments(paths: dict[str, Path], *, now: str = NOW) -> list[str]:
    return [
        "resolve", "--records-dir", str(paths["records"]), "--resolved-scope", str(paths["scope"]),
        "--expected-scopes", str(paths["expected"]), "--aggregate", str(paths["aggregate"]),
        "--trusted-bindings", str(paths["bindings"]), "--evidence-manifest", str(paths["evidence"]),
        "--now", now, "--out", str(paths["out"]),
    ]


def test_resolve_writes_a_canonical_resolved_receipt_bound_to_every_input(tmp_path):
    paths = build_inputs(tmp_path)
    assert TOOL.main(arguments(paths), trusted_authority=trusted_authority()) == 0
    raw = paths["out"].read_bytes()
    receipt = json.loads(raw)
    assert raw == canonical_bytes(receipt)
    assert receipt["resolver_outcome"] == "RESOLVED"
    assert receipt["stage0_contract_usable"] is True
    assert receipt["live_operation_authorized"] is False
    assert receipt["next_governance_gate"] == "GOV-03"
    assert receipt["contract_digest"] == json.loads(paths["aggregate"].read_bytes())["contract_digest"]
    assert receipt["evidence_freshness"] == {
        "state": "FRESH", "signed_manifest_digest": json.loads(paths["evidence"].read_bytes())["evidence_manifest_digest"],
        "observed_at": "2026-08-09T11:00:00Z",
        "expires_at": "2026-08-09T13:00:00Z", "evaluated_at": NOW,
    }
    assert receipt["input_sha256"]["aggregate"] == sha256(paths["aggregate"].read_bytes()).hexdigest()
    assert set(receipt["input_sha256"]) == {
        "records_dir", "resolved_scope", "expected_scopes", "aggregate", "trusted_bindings", "evidence_manifest",
    }


def test_valid_core_block_is_recorded_as_denied_and_never_authorizes_operation(tmp_path):
    paths = build_inputs(tmp_path, blocked=True)
    assert TOOL.main(arguments(paths), trusted_authority=trusted_authority()) == 0
    receipt = json.loads(paths["out"].read_bytes())
    assert receipt["resolver_outcome"] == "BLOCKED"
    assert receipt["stage0_contract_usable"] is False
    assert receipt["live_operation_authorized"] is False
    assert receipt["next_governance_gate"] is None
    assert receipt["contract_digest"] is None
    assert receipt["blocked_decisions"] == [
        {"decision_id": "DB-01", "scope_kind": "global", "scope_name": None,
         "decision_digest": DecisionRecordV1.from_mapping(json.loads((paths["records"] / "00.json").read_bytes())).digest}
    ]


def test_noncanonical_now_fails_without_a_receipt(tmp_path):
    paths = build_inputs(tmp_path)
    assert TOOL.main(
        arguments(paths, now="2026-08-09T12:00:00+00:00"),
        trusted_authority=trusted_authority(),
    ) == 2
    assert not paths["out"].exists()
