"""Mac signed-authority bundle parse and pinned-trust verification."""

from __future__ import annotations

import json
from base64 import b64encode
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.second_brain.mac_production_status_support import (
    bomb_storage as _bomb_storage,
)
from tests.second_brain.mac_production_status_support import (
    isolate_home as _isolate_home,
)
from tests.second_brain.mac_production_status_support import (
    marked_root as _marked_root,
)
from tests.second_brain.mac_production_status_support import tree_snapshot
from wiki_spike.applications.mac_signed_authority_bundle_verify import (
    verify_mac_signed_authority_bundle,
)
from wiki_spike.composition.mac_production import main
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.mac_signed_authority_bundle import (
    AUTHORITY_BUNDLE_VERSION,
    EVIDENCE_ENVELOPE_VERSION,
    EVIDENCE_MANIFEST_VERSION,
    EVIDENCE_SIGNATURE_VERSION,
    EVIDENCE_SIGNING_DOMAIN,
    RESOLUTION_RECEIPT_VERSION,
    SignedAuthorityBundleV1,
    parse_mac_signed_authority_bundle,
)
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
    detached_signing_bytes,
)

NOW = datetime(2026, 8, 18, 12, 0, 0, tzinfo=UTC)
NOW_TEXT = "2026-08-18T12:00:00Z"
DIGEST = "a" * 64
WORKSPACE = f"workspace:{DIGEST}"
OWNER = Ed25519PrivateKey.generate()
APPROVER = Ed25519PrivateKey.generate()
SOURCES = ("Claude/Memory Bank", "Codex", "Git", "Markdown")
MIGRATIONS = ("legacy Mem0/RAG", "me-wiki", "unified-db")
SCOPED = (
    *(("DB-02", "source_profile", name) for name in SOURCES),
    *(("DB-03", "migration_source", name) for name in MIGRATIONS),
    ("DB-06", "external_model_route", "model-a"),
    ("DB-08", "export_destination", "archive"),
)
KIND = {
    "DB-02": "source_profile",
    "DB-03": "migration_source",
    "DB-06": "external_model_route",
    "DB-08": "export_destination",
}
SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"


def public_key(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode(
        "ascii"
    )


AUTHORITY = TrustedAuthorityBindingsV1(
    "approver", public_key(APPROVER), "owner", public_key(OWNER)
)
IDENTITIES: tuple[tuple[str, str, str | None], ...] = (
    ("DB-01", "global", None),
    ("DB-04", "global", None),
    ("DB-05", "global", None),
    ("DB-07", "global", None),
    *SCOPED,
)
TRUSTED = TrustedDecisionKeyBindingsV1(
    {identity: AUTHORITY for identity in IDENTITIES},
    AUTHORITY,
)


def sign(domain: bytes, body: Mapping[str, JsonValue], version: str) -> list[JsonValue]:
    payload = detached_signing_bytes(domain, body)
    signatures: list[JsonValue] = []
    for role, name, key in (("approver", "approver", APPROVER), ("owner", "owner", OWNER)):
        signatures.append(
            {
                "signature_version": version,
                "role": role,
                "key_id": name,
                "public_key_b64": public_key(key),
                "signature_b64": b64encode(key.sign(payload)).decode("ascii"),
            }
        )
    return signatures


def decision(decision_id: str, scope_name: str | None = None) -> dict[str, JsonValue]:
    kind = KIND.get(decision_id, "global")
    body: dict[str, JsonValue] = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": decision_id,
        "outcome": "GO",
        "scope_kind": kind,
        "scope_name": None if kind == "global" else scope_name,
        "record_revision": "1",
        "decided_at": "2026-08-18T11:00:00Z",
        "supersedes": None,
        "post_interview_reconciliation": {
            "original_question": f"q-{decision_id}",
            "reconciliation": f"r-{decision_id}",
        },
        "reason": f"reason for {decision_id}",
        "evidence_refs": [f"evidence-{decision_id}"],
        "evidence_digest": DIGEST,
        "expires_at": "2030-01-01T00:00:00Z",
    }
    body["signatures"] = sign(DECISION_SIGNING_DOMAIN, body, DECISION_SIGNATURE_VERSION)
    return body


def scope_mapping() -> dict[str, JsonValue]:
    return {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": list(SOURCES),
        "disabled_source_profiles": {},
        "enabled_migration_sources": list(MIGRATIONS),
        "disabled_migration_sources": {},
        "feature_flags": [
            "benchmark-governance",
            "conflict-behavior",
            "cutover-retention",
            "identity-auth",
        ],
        "egress_destinations": ["archive"],
        "enabled_external_model_routes": ["model-a"],
        "disabled_external_model_routes": {},
        "disabled_export_destinations": {},
        "capability_manifest_digest": DIGEST,
        "source_manifest_digest": DIGEST,
        "mandatory_release_constraints": ["signed-release-baseline"],
    }


def expected_mapping() -> dict[str, JsonValue]:
    return {
        "manifest_version": "second-brain-expected-scope-manifest-v1",
        "expected_scopes": [
            {"decision_id": decision_id, "scope_kind": kind, "scope_name": name}
            for decision_id, kind, name in SCOPED
        ],
    }


def records() -> list[dict[str, JsonValue]]:
    return [
        *(decision(decision_id) for decision_id in ("DB-01", "DB-04", "DB-05", "DB-07")),
        *(decision("DB-02", name) for name in SOURCES),
        *(decision("DB-03", name) for name in MIGRATIONS),
        decision("DB-06", "model-a"),
        decision("DB-08", "archive"),
    ]


def aggregate_mapping(
    items: list[dict[str, JsonValue]],
    scope: dict[str, JsonValue],
    expected: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    parsed = tuple(DecisionRecordV1.from_mapping(item) for item in items)
    contract = SecondBrainContractDigestV1.create(
        parsed,
        ResolvedScopeV1.from_mapping(scope),
        ExpectedScopeManifestV1.from_mapping(expected),
    )
    payload: dict[str, JsonValue] = {
        "contract_version": contract.contract_version,
        "contract_body": {
            "contract_version": contract.contract_version,
            "decision_digests": [
                {
                    "decision_id": decision_id,
                    "scope_kind": kind,
                    "scope_name": name,
                    "digest": digest,
                }
                for decision_id, kind, name, digest in contract.decision_digests
            ],
            "resolved_scope": scope,
            "expected_scope_manifest": expected,
        },
        "contract_digest": contract.digest,
    }
    return {
        "contract_envelope_version": "second-brain-contract-envelope-v1",
        **payload,
        "signatures": sign(CONTRACT_SIGNING_DOMAIN, payload, CONTRACT_SIGNATURE_VERSION),
    }


def evidence_mapping(items: list[dict[str, JsonValue]]) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "evidence_manifest_version": EVIDENCE_MANIFEST_VERSION,
        "observed_at": "2026-08-18T11:00:00Z",
        "expires_at": "2026-08-18T13:00:00Z",
        "decision_evidence": [
            {
                "decision_id": item["decision_id"],
                "scope_kind": item["scope_kind"],
                "scope_name": item["scope_name"],
                "evidence_digest": item["evidence_digest"],
            }
            for item in sorted(
                items,
                key=lambda row: (
                    str(row["decision_id"]),
                    str(row["scope_kind"]),
                    str(row["scope_name"] or ""),
                ),
            )
        ],
    }
    payload: dict[str, JsonValue] = {
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": sha256(canonical_bytes(body)).hexdigest(),
        "evidence_body": body,
    }
    return {
        **payload,
        "signatures": sign(EVIDENCE_SIGNING_DOMAIN, payload, EVIDENCE_SIGNATURE_VERSION),
    }


def records_dir_digest(entries: list[tuple[str, dict[str, JsonValue]]]) -> str:
    hashed: list[JsonValue] = [
        {"name": name, "sha256": sha256(canonical_bytes(record)).hexdigest()}
        for name, record in entries
    ]
    return sha256(canonical_bytes({"records": hashed})).hexdigest()


def receipt_mapping(
    entries: list[tuple[str, dict[str, JsonValue]]],
    scope: dict[str, JsonValue],
    expected: dict[str, JsonValue],
    aggregate: dict[str, JsonValue],
    evidence: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    digest = evidence["evidence_manifest_digest"]
    if not isinstance(digest, str):
        raise TypeError("evidence_manifest_digest must be a string")
    return {
        "resolution_receipt_version": RESOLUTION_RECEIPT_VERSION,
        "resolver_outcome": "BLOCKED",
        "stage0_contract_usable": False,
        "live_operation_authorized": False,
        "next_governance_gate": None,
        "resolved_at": NOW_TEXT,
        "resolved_scope": scope,
        "input_sha256": {
            "records_dir": records_dir_digest(entries),
            "resolved_scope": sha256(canonical_bytes(scope)).hexdigest(),
            "expected_scopes": sha256(canonical_bytes(expected)).hexdigest(),
            "aggregate": sha256(canonical_bytes(aggregate)).hexdigest(),
            "trusted_bindings": DIGEST,
            "evidence_manifest": sha256(canonical_bytes(evidence)).hexdigest(),
        },
        "evidence_freshness": {
            "state": "FRESH",
            "signed_manifest_digest": digest,
            "observed_at": "2026-08-18T11:00:00Z",
            "expires_at": "2026-08-18T13:00:00Z",
            "evaluated_at": NOW_TEXT,
        },
        "contract_digest": None,
        "blocked_decisions": [],
    }


def bundle_mapping(
    items: list[dict[str, JsonValue]] | None = None,
) -> dict[str, JsonValue]:
    decisions = records() if items is None else items
    scope = scope_mapping()
    expected = expected_mapping()
    entries = [(f"{index:02d}.json", record) for index, record in enumerate(decisions)]
    aggregate = aggregate_mapping(decisions, scope, expected)
    evidence = evidence_mapping(decisions)
    return {
        "authority_bundle_version": AUTHORITY_BUNDLE_VERSION,
        "workspace_ref": WORKSPACE,
        "decision_records": [
            {"name": name, "record": record} for name, record in entries
        ],
        "aggregate": aggregate,
        "evidence_manifest": evidence,
        "resolution_receipt": receipt_mapping(
            entries, scope, expected, aggregate, evidence
        ),
    }


def bundle_bytes(mapping: dict[str, JsonValue] | None = None) -> bytes:
    return canonical_bytes(bundle_mapping() if mapping is None else mapping)


def test_parse_rejects_unknown_bundle_field() -> None:
    mapping = bundle_mapping()
    mapping["trusted_bindings"] = {"injected": "no"}
    with pytest.raises(UnknownContractField, match="unknown fields"):
        parse_mac_signed_authority_bundle(canonical_bytes(mapping))


def test_parse_rejects_raw_numbers() -> None:
    mapping = bundle_mapping()
    encoded = json.dumps(mapping, sort_keys=True, separators=(",", ":")).replace(
        '"record_revision":"1"',
        '"record_revision":1',
        1,
    )
    with pytest.raises(InvalidContractValue, match="raw numbers"):
        parse_mac_signed_authority_bundle(encoded.encode("utf-8"))


def test_parse_rejects_missing_records() -> None:
    mapping = bundle_mapping()
    mapping["decision_records"] = []
    with pytest.raises(InvalidContractValue, match="decision_records"):
        parse_mac_signed_authority_bundle(canonical_bytes(mapping))


def test_verify_rejects_swapped_aggregate() -> None:
    mapping = bundle_mapping()
    other_items = records()
    swapped_record = decision("DB-08", "archive")
    swapped_body = {
        key: value for key, value in swapped_record.items() if key != "signatures"
    }
    swapped_body["reason"] = "swapped archive reason"
    swapped_record["reason"] = "swapped archive reason"
    swapped_record["signatures"] = sign(
        DECISION_SIGNING_DOMAIN,
        swapped_body,
        DECISION_SIGNATURE_VERSION,
    )
    other_items[-1] = swapped_record
    swapped = aggregate_mapping(other_items, scope_mapping(), expected_mapping())
    mapping["aggregate"] = swapped
    receipt = mapping["resolution_receipt"]
    if not isinstance(receipt, dict):
        raise TypeError("resolution_receipt must be an object")
    digests = receipt["input_sha256"]
    if not isinstance(digests, dict):
        raise TypeError("input_sha256 must be an object")
    digests["aggregate"] = sha256(canonical_bytes(swapped)).hexdigest()
    with pytest.raises(InvalidContractValue, match="aggregate"):
        verify_mac_signed_authority_bundle(canonical_bytes(mapping), TRUSTED, now=NOW)


def test_verify_rejects_untrusted_keys() -> None:
    other = Ed25519PrivateKey.generate()
    untrusted = TrustedDecisionKeyBindingsV1(
        TRUSTED.decision_bindings,
        TrustedAuthorityBindingsV1(
            "approver",
            public_key(APPROVER),
            "owner",
            public_key(other),
        ),
    )
    with pytest.raises(InvalidContractValue, match="untrusted"):
        verify_mac_signed_authority_bundle(bundle_bytes(), untrusted, now=NOW)


def test_verify_accepts_pinned_public_trust() -> None:
    parsed = verify_mac_signed_authority_bundle(bundle_bytes(), TRUSTED, now=NOW)
    assert isinstance(parsed, SignedAuthorityBundleV1)
    assert parsed.authority_bundle_version == AUTHORITY_BUNDLE_VERSION
    assert parsed.workspace_ref == WORKSPACE
    assert parsed.resolution_receipt.resolver_outcome == "BLOCKED"
    assert len(parsed.decision_records) == 13


def test_unauthorized_wiki_status_remains_fail_closed_with_no_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _isolate_home(tmp_path, monkeypatch)
    root = _marked_root(tmp_path)
    _bomb_storage(monkeypatch)
    before = tree_snapshot(tmp_path)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert SIGNED_AUTHORITY_ABSENT_TOKEN in captured.err
    assert tree_snapshot(tmp_path) == before
