"""The whole chain: tool -> evidence bundle -> signed DB-03 record -> resolver -> registration.

Every other test stops early. The tool tests stop at `second_brain_decision.py
verify`, which checks signatures against the keys embedded in the record and
says so on stderr. The resolver tests in `test_decision_contracts.py` stop at a
placeholder `"a" * 64` evidence digest, because they are about signature and
scope authority rather than about evidence.

So nothing proved the thing this whole change exists to make true: that a
`MigrationSourceEvidenceV1` digest, produced by the tool from real inputs, is
accepted by `resolve_second_brain_contract` -- the gate the product actually
consults -- and that the resulting resolved scope then satisfies
`assert_migration_source_registrable`.

That is the claim. This is the test for it.
"""
from __future__ import annotations

import importlib.util
import json
from base64 import b64encode
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
    Ed25519SignatureEnvelopeV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SecondBrainContractDigestV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
    detached_signing_bytes,
    resolve_second_brain_contract,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (
    MIGRATION_SOURCE_NAMES,
    MigrationSourceEvidenceV1,
    assert_migration_source_registrable,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "second_brain_migration_source_evidence.py"
PLACEHOLDER, FUTURE = "a" * 64, "2030-01-01T00:00:00Z"
OWNER, APPROVER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()


def load_tool():
    spec = importlib.util.spec_from_file_location("db03_e2e_tool", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()
SCOPE_KIND = {
    "DB-02": "source_profile", "DB-03": "migration_source",
    "DB-06": "external_model_route", "DB-08": "export_destination",
}


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


AUTHORITY = TrustedAuthorityBindingsV1("approver", public(APPROVER), "owner", public(OWNER))
TRUSTED = TrustedDecisionKeyBindingsV1(
    {
        **{(x, "global", None): AUTHORITY for x in ("DB-01", "DB-04", "DB-05", "DB-07")},
        **{("DB-02", "source_profile", n): AUTHORITY
           for n in ("Claude/Memory Bank", "Codex", "Git", "Markdown")},
        **{("DB-03", "migration_source", n): AUTHORITY for n in MIGRATION_SOURCE_NAMES},
        ("DB-06", "external_model_route", "model-a"): AUTHORITY,
        ("DB-08", "export_destination", "archive"): AUTHORITY,
    },
    AUTHORITY,
)


def build_evidence(tmp_path: Path, source: str) -> tuple[str, Path]:
    """Run the real pipeline for one source and return its evidence_digest."""
    slug = source.replace("/", "-").replace(" ", "-")
    out = tmp_path / slug
    out.mkdir()
    cand, canon = out / "cand", out / "canon"
    cand.mkdir(); canon.mkdir()
    for i, body in enumerate([f"{slug}-one", f"{slug}-two", "shared-item"]):
        (cand / f"{i}.txt").write_text(body, encoding="utf-8")
    for i, body in enumerate(["shared-item", f"{slug}-canon"]):
        (canon / f"{i}.txt").write_text(body, encoding="utf-8")

    run = lambda *a: TOOL.main([str(x) for x in a])
    assert run("snapshot", "--source-name", source, "--snapshot-ref", f"snapshot:{slug}",
               "--writers-quiesced-at", "2026-07-30T00:00:00Z",
               "--snapshot-taken-at", "2026-07-30T00:05:00Z",
               "--source-root-digest-before", d(f"root-{slug}"),
               "--source-root-digest-after", d(f"root-{slug}"),
               "--snapshot-package-digest", d(f"pkg-{slug}"),
               "--owner-key-ref", "key:migration-owner",
               "--owner-attestation-digest", d(f"owner-{slug}"),
               "--out", out / "snapshot.json") == 0
    assert run("export-profile", "--snapshot", out / "snapshot.json",
               "--export-method", "read-only-transaction",
               "--write-capability-probe-digest", d(f"probe-{slug}"),
               "--schema-version", f"{slug}-2026-07", "--schema-digest", d(f"schema-{slug}"),
               "--native-identity-field", "source_id", "--native-identity-field", "native_id",
               "--identity-mapping-digest", d(f"identity-{slug}"),
               "--revision-semantics", "content-hash-revision",
               "--revision-mapping-digest", d(f"revision-{slug}"),
               "--watermark-cursor-field", "cursor", "--overlap-behavior", "replay-overlap",
               "--restart-evidence-digest", d(f"restart-{slug}"),
               "--page-size-limit", "500", "--retention-days", "90",
               "--source-fixture-digest", d(f"fixture-{slug}"),
               "--out", out / "profile.json") == 0
    assert run("digests", "--dir", cand, "--out", out / "cand.json") == 0
    assert run("digests", "--dir", canon, "--out", out / "canon.json") == 0
    assert run("uniqueness-diff", "--snapshot", out / "snapshot.json",
               "--candidates", out / "cand.json", "--canonical", out / "canon.json",
               "--out", out / "diff.json") == 0
    assert run("history-treatment", "--snapshot", out / "snapshot.json",
               "--tombstone-representation", "absent",
               "--history-availability", "partial-with-proof",
               "--retained-sample", d(f"ret-{slug}"),
               "--unavailable-sample", d(f"unav-{slug}"),
               "--out", out / "treatment.json") == 0
    assert run("evidence", "--snapshot", out / "snapshot.json",
               "--export-profile", out / "profile.json",
               "--uniqueness-diff", out / "diff.json",
               "--history-treatment", out / "treatment.json",
               "--workspace-ref", "workspace:second-brain-final",
               "--security-review-digest", d(f"security-{slug}"),
               "--out", out / "evidence.json") == 0

    bundle = json.loads((out / "evidence.json").read_text(encoding="utf-8"))
    MigrationSourceEvidenceV1.from_mapping(bundle)  # the contract must accept it
    return bundle["evidence_digest"], out / "evidence.json"


def signed_decision(decision_id: str, scope_name: str | None, evidence_digest: str,
                    outcome: str = "GO") -> dict:
    kind = SCOPE_KIND.get(decision_id, "global")
    raw: dict = {
        "decision_version": "second-brain-decision-record-v1", "decision_id": decision_id,
        "outcome": outcome, "scope_kind": kind,
        "scope_name": scope_name if kind != "global" else None,
        "record_revision": "1", "decided_at": "2026-07-28T00:00:00Z", "supersedes": None,
        "post_interview_reconciliation": {
            "original_question": f"original question for {decision_id}",
            "reconciliation": f"reconciled {decision_id}",
        },
        "reason": f"reason-{decision_id}",
        "evidence_refs": [f"artifacts/second-brain/{decision_id}-evidence.json"],
        "evidence_digest": evidence_digest, "expires_at": FUTURE,
    }
    payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, raw)
    raw["signatures"] = [
        {"signature_version": DECISION_SIGNATURE_VERSION, "role": role, "key_id": role,
         "public_key_b64": public(key), "signature_b64": b64encode(key.sign(payload)).decode()}
        for role, key in (("approver", APPROVER), ("owner", OWNER))
    ]
    return raw


def expected_manifest() -> ExpectedScopeManifestV1:
    return ExpectedScopeManifestV1.from_tuples((
        *(("DB-02", "source_profile", n)
          for n in ("Claude/Memory Bank", "Codex", "Git", "Markdown")),
        *(("DB-03", "migration_source", n) for n in MIGRATION_SOURCE_NAMES),
        ("DB-06", "external_model_route", "model-a"),
        ("DB-08", "export_destination", "archive"),
    ))


def resolved_scope() -> ResolvedScopeV1:
    return ResolvedScopeV1.from_mapping({
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": ["Claude/Memory Bank", "Codex", "Git", "Markdown"],
        "disabled_source_profiles": {},
        "enabled_migration_sources": list(MIGRATION_SOURCE_NAMES),
        "disabled_migration_sources": {},
        "feature_flags": ["benchmark-governance", "conflict-behavior", "cutover-retention",
                          "identity-auth"],
        "egress_destinations": ["archive"], "enabled_external_model_routes": ["model-a"],
        "disabled_external_model_routes": {}, "disabled_export_destinations": {},
        "capability_manifest_digest": PLACEHOLDER, "source_manifest_digest": PLACEHOLDER,
        "mandatory_release_constraints": ["signed-release-baseline"],
    })


def aggregate(records: list[DecisionRecordV1], scope: ResolvedScopeV1):
    contract = SecondBrainContractDigestV1.create(records, scope, expected_manifest())
    payload = {"contract_version": contract.contract_version,
               "contract_body": contract.body(), "contract_digest": contract.digest}
    signed = detached_signing_bytes(CONTRACT_SIGNING_DOMAIN, payload)
    return SignedSecondBrainContractEnvelopeV1(contract, tuple(
        Ed25519SignatureEnvelopeV1.from_mapping(
            {"signature_version": CONTRACT_SIGNATURE_VERSION, "role": role, "key_id": role,
             "public_key_b64": public(key),
             "signature_b64": b64encode(key.sign(signed)).decode()},
            version=CONTRACT_SIGNATURE_VERSION)
        for role, key in (("approver", APPROVER), ("owner", OWNER))))


@pytest.fixture(scope="module")
def built(tmp_path_factory) -> dict[str, tuple[str, Path]]:
    """One genuine evidence bundle per DB-03 source, straight from the CLI."""
    root = tmp_path_factory.mktemp("db03-e2e")
    return {source: build_evidence(root, source) for source in MIGRATION_SOURCE_NAMES}


@pytest.fixture(scope="module")
def real_evidence(built) -> dict[str, str]:
    return {source: digest for source, (digest, _) in built.items()}


def bundle_for(built, source: str) -> MigrationSourceEvidenceV1:
    return MigrationSourceEvidenceV1.from_mapping(
        json.loads(built[source][1].read_text(encoding="utf-8"))
    )


def full_record_set(real_evidence: dict[str, str], **overrides) -> list[DecisionRecordV1]:
    raw = [
        *(signed_decision(x, None, PLACEHOLDER) for x in ("DB-01", "DB-04", "DB-05", "DB-07")),
        *(signed_decision("DB-02", n, PLACEHOLDER)
          for n in ("Claude/Memory Bank", "Codex", "Git", "Markdown")),
        *(signed_decision("DB-03", n, overrides.get(n, real_evidence[n]))
          for n in MIGRATION_SOURCE_NAMES),
        signed_decision("DB-06", "model-a", PLACEHOLDER),
        signed_decision("DB-08", "archive", PLACEHOLDER),
    ]
    return [DecisionRecordV1.from_mapping(x) for x in raw]


def test_every_evidence_digest_is_distinct_per_source(real_evidence):
    assert len(set(real_evidence.values())) == len(MIGRATION_SOURCE_NAMES)


def test_a_tool_produced_digest_resolves_through_the_product_contract(real_evidence):
    """The claim this whole change makes, verified against the gate the product consults."""
    records = full_record_set(real_evidence)
    scope = resolved_scope()
    resolution = resolve_second_brain_contract(
        records, scope, expected_manifest(), aggregate(records, scope), trusted_keys=TRUSTED
    )
    assert resolution.outcome == "RESOLVED"
    assert resolution.contract is not None

    # The digests the resolver accepted are the ones the tool produced.
    bound = {r.scope_name: r.evidence_digest for r in records if r.decision_id == "DB-03"}
    assert bound == real_evidence


@pytest.mark.parametrize("source", MIGRATION_SOURCE_NAMES)
def test_a_resolved_source_is_then_registrable(built, real_evidence, source):
    """Resolution enables the source; the registration guard must agree."""
    records = full_record_set(real_evidence)
    scope = resolved_scope()
    resolve_second_brain_contract(
        records, scope, expected_manifest(), aggregate(records, scope), trusted_keys=TRUSTED
    )
    assert_migration_source_registrable(bundle_for(built, source), scope)


def test_a_no_go_source_resolves_as_disabled_and_is_not_registrable(built, real_evidence):
    """NO_GO must exclude exactly that source, and the guard must refuse it."""
    raw = [r.to_mapping() for r in full_record_set(real_evidence)]
    index = next(i for i, r in enumerate(raw)
                 if r["decision_id"] == "DB-03" and r["scope_name"] == "unified-db")
    raw[index] = signed_decision("DB-03", "unified-db", real_evidence["unified-db"], "NO_GO")
    records = [DecisionRecordV1.from_mapping(x) for x in raw]

    scope = ResolvedScopeV1.from_mapping({
        **resolved_scope().to_mapping(),
        "enabled_migration_sources": [n for n in MIGRATION_SOURCE_NAMES if n != "unified-db"],
        "disabled_migration_sources": {"unified-db": "signed NO_GO"},
    })
    resolution = resolve_second_brain_contract(
        records, scope, expected_manifest(), aggregate(records, scope), trusted_keys=TRUSTED
    )
    assert resolution.outcome == "RESOLVED"

    with pytest.raises(InvalidContractValue, match="NO_GO"):
        assert_migration_source_registrable(bundle_for(built, "unified-db"), scope)


def test_a_record_bound_to_the_wrong_evidence_digest_still_resolves_but_is_traceable(
    real_evidence,
):
    """Honest boundary: the resolver checks signatures and scope, not evidence content.

    A record can bind any digest and still resolve, because the resolver has no
    way to fetch the artifact. What the digest gives a later auditor is the
    ability to detect the substitution -- the bundle on disk will not hash to
    what the signed record claims. That is the property, and it is worth stating
    rather than implying the resolver validates evidence.
    """
    records = full_record_set(real_evidence, **{"unified-db": PLACEHOLDER})
    scope = resolved_scope()
    resolution = resolve_second_brain_contract(
        records, scope, expected_manifest(), aggregate(records, scope), trusted_keys=TRUSTED
    )
    assert resolution.outcome == "RESOLVED"
    bound = next(r.evidence_digest for r in records
                 if r.decision_id == "DB-03" and r.scope_name == "unified-db")
    assert bound == PLACEHOLDER
    assert bound != real_evidence["unified-db"], (
        "the substitution is detectable by comparing the signed digest to the artifact"
    )
