"""RED/GREEN tests for the resolver-verified production migration import gate (#96)."""
from __future__ import annotations

import copy
import pickle
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from snapshot_importer_support import digest_of, verified_persistence, write_pair

from wiki_spike.applications.production_migration_import_gate import (
    ProductionImportAuthorityError,
    ProductionMigrationImportGate,
    VerifiedMigrationImportAuthorityV1,
    resolve_migration_import_authority,
)
from wiki_spike.applications.source_discovery_service import discover_source
from wiki_spike.applications.source_import_service import SourceImportService
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.snapshot_import_store import LifecycleSnapshotImportStore
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.production_migration_import_contracts import (
    ImmutableMigrationPackageV1,
    LiveExportEvidenceV1,
    ProductionMigrationImportReceiptV1,
)
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
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_product_release import resolved_scope_digest
from wiki_spike.memory_core.snapshot_import import (
    BOUNDED_SNAPSHOT_V1,
    SNAPSHOT_IMPORT_REQUEST_V1,
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
)
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
)

DIGEST, FUTURE = "a" * 64, "2030-01-01T00:00:00Z"
NOW = datetime(2026, 8, 25, 12, 0, 0, tzinfo=UTC)
SOURCE, NAMESPACE = "unified-db", "second-brain:import:unified-db"
OWNER, APPROVER = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
ROGUE = Ed25519PrivateKey.generate()
SOURCES = ("Claude/Memory Bank", "Codex", "Git", "Markdown")
MIGRATIONS = ("legacy Mem0/RAG", "me-wiki", "unified-db")
KIND = {
    "DB-02": "source_profile",
    "DB-03": "migration_source",
    "DB-06": "external_model_route",
    "DB-08": "export_destination",
}


def _public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


AUTHORITY = TrustedAuthorityBindingsV1("approver", _public(APPROVER), "owner", _public(OWNER))
TRUSTED = TrustedDecisionKeyBindingsV1(
    {
        **{(name, "global", None): AUTHORITY for name in ("DB-01", "DB-04", "DB-05", "DB-07")},
        **{("DB-02", "source_profile", name): AUTHORITY for name in SOURCES},
        **{("DB-03", "migration_source", name): AUTHORITY for name in MIGRATIONS},
        ("DB-06", "external_model_route", "model-a"): AUTHORITY,
        ("DB-08", "export_destination", "archive"): AUTHORITY,
    },
    AUTHORITY,
)


def _decision(
    decision_id: str,
    scope_name: str | None = None,
    outcome: str = "GO",
    revision: str = "1",
    expires_at: str = FUTURE,
    evidence_digest: str = DIGEST,
    owner: Ed25519PrivateKey = OWNER,
) -> dict[str, object]:
    kind = KIND.get(decision_id, "global")
    raw: dict[str, object] = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": decision_id,
        "outcome": outcome,
        "scope_kind": kind,
        "scope_name": scope_name if kind != "global" else None,
        "record_revision": revision,
        "decided_at": "2026-07-28T00:00:00Z",
        "supersedes": None
        if revision == "1"
        else {
            "decision_id": decision_id,
            "scope_kind": kind,
            "scope_name": scope_name if kind != "global" else None,
            "record_revision": str(int(revision) - 1),
            "decision_digest": DIGEST,
        },
        "post_interview_reconciliation": {
            "original_question": f"original question for {decision_id}",
            "reconciliation": f"reconciled {decision_id}",
        },
        "reason": f"reason-{decision_id}",
        "evidence_refs": [f"evidence-{decision_id}"],
        "evidence_digest": evidence_digest,
        "expires_at": expires_at,
    }
    payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, raw)
    raw["signatures"] = [
        {
            "signature_version": DECISION_SIGNATURE_VERSION,
            "role": "approver",
            "key_id": "approver",
            "public_key_b64": _public(APPROVER),
            "signature_b64": b64encode(APPROVER.sign(payload)).decode(),
        },
        {
            "signature_version": DECISION_SIGNATURE_VERSION,
            "role": "owner",
            "key_id": "owner",
            "public_key_b64": _public(owner),
            "signature_b64": b64encode(owner.sign(payload)).decode(),
        },
    ]
    return raw


def _db03(
    *,
    outcome: str = "GO",
    expires_at: str = FUTURE,
    evidence_digest: str = DIGEST,
    owner: Ed25519PrivateKey = OWNER,
) -> DecisionRecordV1:
    return DecisionRecordV1.from_mapping(
        _decision(
            "DB-03",
            SOURCE,
            outcome=outcome,
            revision="2",
            expires_at=expires_at,
            evidence_digest=evidence_digest,
            owner=owner,
        )
    )


def _records(db03: DecisionRecordV1) -> list[DecisionRecordV1]:
    others = [
        *(_decision(name) for name in ("DB-01", "DB-04", "DB-05", "DB-07")),
        *(_decision("DB-02", name) for name in SOURCES),
        *(
            _decision("DB-03", name)
            for name in ("legacy Mem0/RAG", "me-wiki")
        ),
        _decision("DB-06", "model-a"),
        _decision("DB-08", "archive"),
    ]
    return [*(DecisionRecordV1.from_mapping(raw) for raw in others), db03]


def _scope(*, unified_enabled: bool = True) -> dict[str, object]:
    enabled = list(MIGRATIONS) if unified_enabled else ["legacy Mem0/RAG", "me-wiki"]
    disabled = {} if unified_enabled else {SOURCE: "signed NO_GO"}
    return {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": list(SOURCES),
        "disabled_source_profiles": {},
        "enabled_migration_sources": enabled,
        "disabled_migration_sources": disabled,
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


def _expected() -> ExpectedScopeManifestV1:
    return ExpectedScopeManifestV1.from_tuples(
        (
            *(("DB-02", "source_profile", name) for name in SOURCES),
            *(("DB-03", "migration_source", name) for name in MIGRATIONS),
            ("DB-06", "external_model_route", "model-a"),
            ("DB-08", "export_destination", "archive"),
        )
    )


def _aggregate(
    items: list[DecisionRecordV1], raw_scope: dict[str, object]
) -> SignedSecondBrainContractEnvelopeV1:
    contract = SecondBrainContractDigestV1.create(
        items, ResolvedScopeV1.from_mapping(raw_scope), _expected()
    )
    payload = {
        "contract_version": contract.contract_version,
        "contract_body": contract.body(),
        "contract_digest": contract.digest,
    }
    return SignedSecondBrainContractEnvelopeV1(
        contract,
        tuple(
            Ed25519SignatureEnvelopeV1.from_mapping(
                {
                    "signature_version": CONTRACT_SIGNATURE_VERSION,
                    "role": role,
                    "key_id": name,
                    "public_key_b64": _public(key),
                    "signature_b64": b64encode(
                        key.sign(detached_signing_bytes(CONTRACT_SIGNING_DOMAIN, payload))
                    ).decode(),
                },
                version=CONTRACT_SIGNATURE_VERSION,
            )
            for role, name, key in (("approver", "approver", APPROVER), ("owner", "owner", OWNER))
        ),
    )


def _resolution(db03: DecisionRecordV1, *, unified_enabled: bool = True):
    items = _records(db03)
    raw_scope = _scope(unified_enabled=unified_enabled)
    return resolve_second_brain_contract(
        items,
        ResolvedScopeV1.from_mapping(raw_scope),
        _expected(),
        _aggregate(items, raw_scope),
        trusted_keys=TRUSTED,
    )


def _discovery(root: Path) -> SourceDiscoveryManifestV1:
    return discover_source(
        SourceDiscoveryRequestV1.from_mapping(
            {
                "request_version": SOURCE_DISCOVERY_REQUEST_V1,
                "source_name": SOURCE,
                "source_root": str(root.resolve()),
            }
        )
    )


def _snapshot(root: Path) -> BoundedSnapshotV1:
    records: list[JsonValue] = [
        {
            "native_id": "row-alpha",
            "revision": "7",
            "watermark": "watermark-11",
            "tombstone": False,
            "relative_path": "alpha.md",
            "content_digest": digest_of((root / "alpha.md").read_bytes()),
        },
        {
            "native_id": "row-beta",
            "revision": "3",
            "watermark": "watermark-12",
            "tombstone": False,
            "relative_path": "beta.json",
            "content_digest": digest_of((root / "beta.json").read_bytes()),
        },
        {
            "native_id": "row-deleted",
            "revision": "9",
            "watermark": "watermark-13",
            "tombstone": True,
            "relative_path": None,
            "content_digest": None,
        },
    ]
    body: dict[str, JsonValue] = {
        "snapshot_version": BOUNDED_SNAPSHOT_V1,
        "source_name": SOURCE,
        "native_namespace": NAMESPACE,
        "snapshot_watermark": "watermark-13",
        "records": records,
    }
    return BoundedSnapshotV1.from_mapping(
        body | {"snapshot_digest": canonical_ledger_digest("bounded-source-snapshot-v1", body)}
    )


def _request(
    root: Path,
    discovery_digest: str,
    snapshot: BoundedSnapshotV1,
    scope_digest: str,
    *,
    source_name: str = SOURCE,
    target_namespace: str = NAMESPACE,
) -> SnapshotImportRequestV1:
    return SnapshotImportRequestV1.from_mapping(
        {
            "request_version": SNAPSHOT_IMPORT_REQUEST_V1,
            "cohort_id": "cohort-unified-db-001",
            "source_name": source_name,
            "source_root": str(root.resolve()),
            "target_namespace": target_namespace,
            "resolved_scope_digest": scope_digest,
            "discovery_manifest_digest": discovery_digest,
            "snapshot_digest": snapshot.snapshot_digest,
            "reconciliation_mode": "REQUIRED",
            "serving_promotion_requested": False,
        }
    )


def _service(tmp_path: Path):
    database = LifecycleDatabase(tmp_path / "target.sqlite")
    database.initialize()
    cas = EncryptedContentStore(tmp_path / "cas")
    profile = verified_persistence(database, cas)
    store = LifecycleSnapshotImportStore(
        database=database,
        cas=cas,
        persistence_profile=profile,
        encryption_key=b"\x13" * 32,
    )
    return SourceImportService(store=store, max_file_bytes=1024 * 1024), profile


def _happy(tmp_path: Path) -> SimpleNamespace:
    root = tmp_path / "source"
    root.mkdir()
    write_pair(root)
    discovery = _discovery(root)
    snapshot = _snapshot(root)
    db03 = _db03()
    resolution = _resolution(db03)
    assert resolution.outcome == "RESOLVED" and resolution.contract is not None
    scope_digest = resolved_scope_digest(resolution.contract.resolved_scope)
    request = _request(root, discovery.manifest_digest, snapshot, scope_digest)
    package = ImmutableMigrationPackageV1.create(
        source_name=SOURCE,
        snapshot_digest=snapshot.snapshot_digest,
        discovery_manifest_digest=discovery.manifest_digest,
        certificate_digest="c" * 64,
    )
    live = LiveExportEvidenceV1.create(
        source_name=SOURCE,
        record_count="3",
        snapshot_digest=snapshot.snapshot_digest,
        discovery_manifest_digest=discovery.manifest_digest,
        package_digest=package.package_digest,
        captured_at="2026-08-01T00:00:00Z",
        expires_at="2027-01-01T00:00:00Z",
    )
    service, profile = _service(tmp_path)
    return SimpleNamespace(
        root=root,
        discovery=discovery,
        snapshot=snapshot,
        db03=db03,
        resolution=resolution,
        scope_digest=scope_digest,
        request=request,
        package=package,
        live=live,
        service=service,
        profile=profile,
    )


def _mint(fx: SimpleNamespace, **overrides: object) -> VerifiedMigrationImportAuthorityV1:
    arguments: dict[str, object] = {
        "contract_resolution": fx.resolution,
        "db03_decision": fx.db03,
        "trusted_keys": TRUSTED,
        "live_evidence": fx.live,
        "package": fx.package,
        "persistence_profile": fx.profile,
        "request": fx.request,
        "now": NOW,
    }
    arguments.update(overrides)
    return resolve_migration_import_authority(**arguments)  # pyright: ignore[reportArgumentType]


def test_resolver_mints_and_gate_imports_ready_non_serving(tmp_path: Path) -> None:
    # Given: exact RESOLVED scope, trusted DB-03 rev-2 GO, live evidence, package, profile.
    fx = _happy(tmp_path)

    # When: the resolver mints and the gate runs the existing #83 mechanism.
    authority = _mint(fx)
    receipt = ProductionMigrationImportGate(fx.service).import_verified_migration(
        authority, fx.request, fx.snapshot, fx.discovery
    )

    # Then: the receipt is resolver-verified and permanently non-serving/non-cutover.
    assert receipt.state == "READY_NON_SERVING"
    assert receipt.scope_authority_state == "RESOLVER_VERIFIED_DB03_GO"
    assert receipt.serving_promoted is False and receipt.cutover_eligible is False
    assert receipt.resolved_scope_digest == fx.scope_digest
    assert receipt.snapshot_digest == fx.snapshot.snapshot_digest
    assert receipt.discovery_manifest_digest == fx.discovery.manifest_digest
    assert receipt.package_digest == fx.package.package_digest
    assert receipt.evidence_digest == fx.live.evidence_digest
    assert receipt.receipt_digest == receipt.computed_digest()
    round_trip = ProductionMigrationImportReceiptV1.from_mapping(receipt.to_mapping())
    assert round_trip == receipt


def test_forged_or_bare_scope_digest_is_refused_before_any_mutation(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    bare = _request(fx.root, fx.discovery.manifest_digest, fx.snapshot, digest_of("resolved-scope"))
    with pytest.raises(ProductionImportAuthorityError, match="forged or bare"):
        _ = _mint(fx, request=bare)


def test_fixture_only_evidence_is_refused_by_exact_type(tmp_path: Path) -> None:
    fx = _happy(tmp_path)

    class LookalikeLiveEvidence(LiveExportEvidenceV1):
        """A subclass or spoof must never satisfy the exact-type live-evidence join."""

    lookalike = LookalikeLiveEvidence.from_mapping(fx.live.to_mapping())
    spoof = SimpleNamespace(**fx.live.to_mapping())
    for fixture_only in (lookalike, spoof):
        with pytest.raises(ProductionImportAuthorityError, match="fixture evidence"):
            _ = _mint(fx, live_evidence=fixture_only)


def test_no_go_db03_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    no_go = _db03(outcome="NO_GO")
    with pytest.raises(ProductionImportAuthorityError, match="not a trusted GO"):
        _ = _mint(fx, db03_decision=no_go)


def test_wrong_db03_revision_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    revision_one = DecisionRecordV1.from_mapping(_decision("DB-03", SOURCE, revision="1"))
    with pytest.raises(ProductionImportAuthorityError, match="revision-2"):
        _ = _mint(fx, db03_decision=revision_one)


def test_expired_db03_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    expired = _db03(expires_at="2026-01-01T00:00:00Z")
    with pytest.raises(ProductionImportAuthorityError, match="DB-03"):
        _ = _mint(fx, db03_decision=expired)


def test_untrusted_db03_signature_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    rogue = _db03(owner=ROGUE)
    with pytest.raises(ProductionImportAuthorityError, match="DB-03"):
        _ = _mint(fx, db03_decision=rogue)


def test_decision_not_bound_into_resolved_contract_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    unbound = _db03(evidence_digest="b" * 64)
    with pytest.raises(ProductionImportAuthorityError, match="DB-03"):
        _ = _mint(fx, db03_decision=unbound)


def test_source_absent_from_enabled_inventory_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    disabled_db03 = _db03(outcome="NO_GO")
    resolution = _resolution(disabled_db03, unified_enabled=False)
    assert resolution.outcome == "RESOLVED" and resolution.contract is not None
    scope_digest = resolved_scope_digest(resolution.contract.resolved_scope)
    request = _request(fx.root, fx.discovery.manifest_digest, fx.snapshot, scope_digest)
    with pytest.raises(ProductionImportAuthorityError, match="enabled inventory"):
        _ = _mint(fx, contract_resolution=resolution, db03_decision=disabled_db03, request=request)


def test_package_snapshot_evidence_digest_mismatch_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    mismatched = ImmutableMigrationPackageV1.create(
        source_name=SOURCE,
        snapshot_digest="d" * 64,
        discovery_manifest_digest=fx.discovery.manifest_digest,
        certificate_digest="c" * 64,
    )
    with pytest.raises(ProductionImportAuthorityError, match="match exactly"):
        _ = _mint(fx, package=mismatched)


def test_stale_live_export_evidence_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    stale = LiveExportEvidenceV1.create(
        source_name=SOURCE,
        record_count="3",
        snapshot_digest=fx.snapshot.snapshot_digest,
        discovery_manifest_digest=fx.discovery.manifest_digest,
        package_digest=fx.package.package_digest,
        captured_at="2026-08-01T00:00:00Z",
        expires_at="2026-08-20T00:00:00Z",
    )
    with pytest.raises(ProductionImportAuthorityError, match="not fresh"):
        _ = _mint(fx, live_evidence=stale)


def test_serving_promotion_is_refused_at_contract_and_gate(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    # Contract boundary: the request type itself refuses serving promotion.
    with pytest.raises(Exception, match="serving"):
        _ = SnapshotImportRequestV1.from_mapping(
            fx.request.to_mapping() | {"serving_promotion_requested": True}
        )
    # Gate boundary: a forged in-memory request is still refused by the resolver.
    forged = replace(fx.request, serving_promotion_requested=True)
    with pytest.raises(ProductionImportAuthorityError, match="serving promotion"):
        _ = _mint(fx, request=forged)


def test_non_unified_namespace_is_refused(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    foreign = _request(
        fx.root,
        fx.discovery.manifest_digest,
        fx.snapshot,
        fx.scope_digest,
        source_name="me-wiki",
        target_namespace="second-brain:import:me-wiki",
    )
    with pytest.raises(ProductionImportAuthorityError, match="unified"):
        _ = _mint(fx, request=foreign)


def test_authority_cannot_be_caller_constructed_copied_or_serialized(tmp_path: Path) -> None:
    fx = _happy(tmp_path)
    authority = _mint(fx)
    assert not hasattr(VerifiedMigrationImportAuthorityV1, "from_mapping")
    with pytest.raises(ProductionImportAuthorityError, match="minted by the resolver"):
        _ = VerifiedMigrationImportAuthorityV1(
            SimpleNamespace(),  # pyright: ignore[reportArgumentType]
            SOURCE,
            NAMESPACE,
            fx.scope_digest,
            fx.snapshot.snapshot_digest,
            fx.discovery.manifest_digest,
            fx.package.package_digest,
            fx.live.evidence_digest,
            fx.profile.profile_digest,
        )
    with pytest.raises(TypeError, match="serialized"):
        _ = pickle.dumps(authority)
    with pytest.raises(ProductionImportAuthorityError, match="copied"):
        _ = copy.copy(authority)
    with pytest.raises(ProductionImportAuthorityError, match="copied"):
        _ = copy.deepcopy(authority)


def test_gate_refuses_mismatched_authority_without_touching_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fx = _happy(tmp_path)
    authority = _mint(fx)
    other_root = tmp_path / "other"
    other_root.mkdir()
    write_pair(other_root)
    _ = (other_root / "alpha.md").write_text("different plaintext", encoding="utf-8")
    other_snapshot = _snapshot(other_root)
    other_request = _request(
        other_root, fx.discovery.manifest_digest, other_snapshot, fx.scope_digest
    )

    def _never(*_args: object, **_kwargs: object) -> object:
        pytest.fail("persistence must not run for a refused import")

    monkeypatch.setattr(fx.service, "import_snapshot", _never)
    gate = ProductionMigrationImportGate(fx.service)
    with pytest.raises(ProductionImportAuthorityError, match="does not bind"):
        _ = gate.import_verified_migration(authority, other_request, other_snapshot, fx.discovery)
    caller_asserted = SimpleNamespace(
        source_name=SOURCE,
        target_namespace=NAMESPACE,
        resolved_scope_digest=fx.scope_digest,
        snapshot_digest=fx.snapshot.snapshot_digest,
        discovery_manifest_digest=fx.discovery.manifest_digest,
        package_digest=fx.package.package_digest,
        evidence_digest=fx.live.evidence_digest,
    )
    with pytest.raises(ProductionImportAuthorityError, match="resolver-minted"):
        _ = gate.import_verified_migration(
            caller_asserted,  # pyright: ignore[reportArgumentType]
            fx.request,
            fx.snapshot,
            fx.discovery,
        )


def test_gate_requires_the_exact_import_service_type(tmp_path: Path) -> None:
    _ = tmp_path
    with pytest.raises(ProductionImportAuthorityError, match="SourceImportService"):
        _ = ProductionMigrationImportGate(SimpleNamespace())  # pyright: ignore[reportArgumentType]
