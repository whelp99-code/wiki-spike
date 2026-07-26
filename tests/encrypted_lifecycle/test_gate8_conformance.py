"""Gate 8 conformance machinery tests: verdict-free pre-review manifest, two
independent attestations (ARCHITECT/CRITIC), separate receipt, and three-import
evidence join."""
from __future__ import annotations

import hashlib
import importlib.util
import re
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure.conformance import (
    APPROVE,
    ARCHITECT,
    CANARY,
    CONFORMANCE,
    CRITIC,
    GATE1,
    ConformanceError,
    attest_manifest,
    build_evidence_join,
    build_pre_review_manifest,
    import_final_review_receipt,
    verify_attestation,
    verify_evidence_join,
    write_final_review_receipt,
)

WORKSPACE = "ws-test-1"
COMMIT = "ab" * 20  # 40-hex implementation commit


def _key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def _receipt(
    *,
    artifact_name: str,
    artifact_kind: str,
    bundle_sha256: str,
    platform: str,
    workflow_run_id: str,
    payload_paths: list[str],
    payload_sha256: list[str],
) -> dict:
    return {
        "repository": "owner/repository",
        "artifact_kind": artifact_kind,
        "platform": platform,
        "producer_commit": COMMIT,
        "contract_digest": "aa" * 32,
        "toolchain_lock_digest": "bb" * 32,
        "workflow_file_digest": "cc" * 32,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": "1",
        "artifact_name": artifact_name,
        "bundle_sha256": bundle_sha256,
        "payload_paths": payload_paths,
        "payload_sha256": payload_sha256,
        "source_run_url": f"https://github.example/owner/repository/actions/runs/{workflow_run_id}",
        "verified": True,
    }


def _bundles() -> dict:
    return {
        GATE1: _receipt(
            artifact_name="encrypted-lifecycle-gate1-decision-1-1-0123456789abcdef",
            artifact_kind="GATE1_DECISION",
            bundle_sha256="11" * 32,
            platform="self-hosted/macos-15/arm64/wiki-gate1-workstation",
            workflow_run_id="1",
            payload_paths=[
                "payload/gate1-decision.json",
                "payload/macos/sqlcipher-feasibility.json",
                "payload/ubuntu/import-receipt.json",
                "payload/vector-validation.json",
            ],
            payload_sha256=["41" * 32, "42" * 32, "43" * 32, "44" * 32],
        ),
        CONFORMANCE: _receipt(
            artifact_name="encrypted-lifecycle-conformance-pre-canary-2-1-0123456789abcdef",
            artifact_kind="CONFORMANCE_PRE_CANARY",
            bundle_sha256="22" * 32,
            platform="self-hosted/macos-15/arm64/wiki-conformance-workstation",
            workflow_run_id="2",
            payload_paths=["payload/conformance-pre-canary.json"],
            payload_sha256=["51" * 32],
        ),
        CANARY: _receipt(
            artifact_name="encrypted-lifecycle-canary-24h-3-1-0123456789abcdef",
            artifact_kind="CANARY_24H",
            bundle_sha256="33" * 32,
            platform="self-hosted/macos-15/arm64/wiki-canary-workstation",
            workflow_run_id="3",
            payload_paths=["payload/rollout-evidence.json"],
            payload_sha256=["61" * 32],
        ),
    }


# ---------------------------------------------------------------------------
# Verdict-free pre-review manifest
# ---------------------------------------------------------------------------


def test_pre_review_manifest_builds_and_is_verdict_free():
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles()
    )
    assert len(manifest.bundles) == 3
    assert {b.lane for b in manifest.bundles} == {GATE1, CONFORMANCE, CANARY}
    assert len(manifest.manifest_digest) == 64
    # Verdict-free: no verdict/pass/fail field anywhere in the manifest.
    for field in manifest.__dict__:
        assert "verdict" not in field.lower()
        assert "pass" != field.lower()


def test_pre_review_manifest_is_deterministic():
    a = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    b = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    assert a.manifest_digest == b.manifest_digest


def test_pre_review_manifest_fails_closed_on_missing_lane():
    bundles = _bundles()
    del bundles[CANARY]
    with pytest.raises(ConformanceError) as exc:
        build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=bundles)
    assert exc.value.code == "manifest_missing_lanes"


def test_pre_review_manifest_fails_closed_on_extra_lane():
    bundles = _bundles()
    bundles["rogue"] = dict(bundles[GATE1])
    with pytest.raises(ConformanceError) as exc:
        build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=bundles)
    assert exc.value.code == "manifest_extra_lanes"


def test_pre_review_manifest_fails_closed_on_missing_field():
    bundles = _bundles()
    bundles[CONFORMANCE]["bundle_sha256"] = ""
    with pytest.raises(ConformanceError) as exc:
        build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=bundles)
    assert exc.value.code == "manifest_receipt_invalid"


# ---------------------------------------------------------------------------
# Independent attestations and canonical final receipt
# ---------------------------------------------------------------------------


NOW = "2026-07-26T12:00:00Z"
ISSUED_AT = "2026-07-26T11:30:00Z"
EXPIRES_AT = "2026-07-26T12:30:00Z"


def _two_attestations(manifest_digest: str):
    arch_key, critic_key = _key(b"architect"), _key(b"critic")
    arch = attest_manifest(
        reviewer_role=ARCHITECT, reviewer_key_id="arch-key-1", private_key=arch_key,
        workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest_digest=manifest_digest,
        issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    critic = attest_manifest(
        reviewer_role=CRITIC, reviewer_key_id="critic-key-1", private_key=critic_key,
        workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest_digest=manifest_digest,
        issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    trusted = {
        ARCHITECT: ("arch-key-1", arch_key.public_key()),
        CRITIC: ("critic-key-1", critic_key.public_key()),
    }
    return arch, critic, trusted


def _receipt_bytes(manifest):
    arch, critic, trusted = _two_attestations(manifest.manifest_digest)
    evidence_join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        import_receipts=_import_receipts(), manifest_digest=manifest.manifest_digest,
    )
    receipt = write_final_review_receipt(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest=manifest,
        evidence_join=evidence_join, attestations=(arch, critic), trusted_reviewers=trusted, now=NOW,
    )
    return receipt, trusted, evidence_join


def test_attestations_are_complete_and_verify_under_independent_trusted_keys():
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles()
    )
    arch, critic, trusted = _two_attestations(manifest.manifest_digest)

    assert arch.verdict == APPROVE
    assert set(arch.to_mapping()) == {
        "schema", "reviewer_role", "verdict", "workspace_id", "implementation_commit",
        "manifest_digest", "reviewer_key_id", "issued_at", "expires_at", "signature",
    }
    verify_attestation(
        arch, trusted, workspace_id=WORKSPACE, implementation_commit=COMMIT,
        manifest_digest=manifest.manifest_digest, now=NOW,
    )
    verify_attestation(
        critic, trusted, workspace_id=WORKSPACE, implementation_commit=COMMIT,
        manifest_digest=manifest.manifest_digest, now=NOW,
    )


def test_receipt_rejects_same_public_key_under_distinct_key_ids():
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles()
    )
    shared_key = _key(b"shared-reviewer")
    arch = attest_manifest(
        reviewer_role=ARCHITECT, reviewer_key_id="arch-key-1", private_key=shared_key,
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        manifest_digest=manifest.manifest_digest, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    critic = attest_manifest(
        reviewer_role=CRITIC, reviewer_key_id="critic-key-1", private_key=shared_key,
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        manifest_digest=manifest.manifest_digest, issued_at=ISSUED_AT, expires_at=EXPIRES_AT,
    )
    trusted = {
        ARCHITECT: ("arch-key-1", shared_key.public_key()),
        CRITIC: ("critic-key-1", shared_key.public_key()),
    }
    evidence_join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        import_receipts=_import_receipts(), manifest_digest=manifest.manifest_digest,
    )
    with pytest.raises(ConformanceError) as exc:
        write_final_review_receipt(
            workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest=manifest,
            evidence_join=evidence_join, attestations=(arch, critic),
            trusted_reviewers=trusted, now=NOW,
        )
    assert exc.value.code == "receipt_duplicate_public_key"


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "now", "code"),
    (
        (ISSUED_AT, "2026-07-26T12:00:00Z", NOW, "attestation_expired"),
        ("2026-07-26T12:01:00Z", "2026-07-26T12:31:00Z", NOW, "attestation_not_yet_valid"),
        ("2026-07-26T10:00:00Z", "2026-07-26T12:00:01Z", NOW, "attestation_lifetime_invalid"),
    ),
)
def test_attestation_rejects_expired_future_and_long_lived(issued_at, expires_at, now, code):
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    key = _key(b"architect")
    attestation = attest_manifest(
        reviewer_role=ARCHITECT, reviewer_key_id="arch-key-1", private_key=key,
        workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest_digest=manifest.manifest_digest,
        issued_at=issued_at, expires_at=expires_at,
    )
    with pytest.raises(ConformanceError) as exc:
        verify_attestation(
            attestation, {ARCHITECT: ("arch-key-1", key.public_key())},
            workspace_id=WORKSPACE, implementation_commit=COMMIT,
            manifest_digest=manifest.manifest_digest, now=now,
        )
    assert exc.value.code == code


def test_final_review_receipt_is_canonical_and_strictly_imported():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    receipt, trusted, evidence_join = _receipt_bytes(manifest)

    assert receipt == json.dumps(json.loads(receipt), sort_keys=True, separators=(",", ":")).encode()
    imported = import_final_review_receipt(
        receipt, trusted_reviewers=trusted, workspace_id=WORKSPACE,
        implementation_commit=COMMIT, manifest=manifest, evidence_join=evidence_join, now=NOW,
    )
    assert {attestation.reviewer_role for attestation in imported} == {ARCHITECT, CRITIC}
    assert json.loads(receipt)["artifact_inventory"] == {
        path: digest
        for lane in (GATE1, CONFORMANCE, CANARY)
        for path, digest in zip(_bundles()[lane]["payload_paths"], _bundles()[lane]["payload_sha256"])
    }


@pytest.mark.parametrize(
    ("mutate_manifest", "mutate_receipt", "code"),
    (
        (
            lambda bundles, receipts: bundles[CANARY]["payload_paths"].append("payload/extra.json"),
            lambda receipt: None,
            "receipt_manifest_receipt_mismatch",
        ),
        (
            lambda bundles, receipts: (
                bundles[CONFORMANCE]["payload_paths"].__setitem__(
                    0, "payload/../conformance-pre-canary.json"
                ),
                receipts[CONFORMANCE]["payload_paths"].__setitem__(
                    0, "payload/../conformance-pre-canary.json"
                ),
            ),
            lambda receipt: None,
            "receipt_inventory_path_invalid",
        ),
        (
            lambda bundles, receipts: bundles[CONFORMANCE]["payload_sha256"].__setitem__(0, "ff" * 32),
            lambda receipt: None,
            "receipt_manifest_receipt_mismatch",
        ),
        (
            lambda bundles, receipts: None,
            lambda receipt: receipt["artifact_inventory"].update({"payload/extra.json": "ff" * 32}),
            "receipt_inventory_mismatch",
        ),
    ),
)
def test_final_receipt_inventory_rejects_manifest_and_wire_substitution(
    mutate_manifest, mutate_receipt, code,
):
    bundles, receipts = _bundles(), _import_receipts()
    mutate_manifest(bundles, receipts)
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=bundles,
    )
    evidence_join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        import_receipts=receipts, manifest_digest=manifest.manifest_digest,
    )
    arch, critic, trusted = _two_attestations(manifest.manifest_digest)
    if code in {"receipt_manifest_receipt_mismatch", "receipt_inventory_path_invalid"}:
        with pytest.raises(ConformanceError) as exc:
            write_final_review_receipt(
                workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest=manifest,
                evidence_join=evidence_join, attestations=(arch, critic),
                trusted_reviewers=trusted, now=NOW,
            )
        assert exc.value.code == code
        return
    receipt = write_final_review_receipt(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest=manifest,
        evidence_join=evidence_join, attestations=(arch, critic),
        trusted_reviewers=trusted, now=NOW,
    )
    wire = json.loads(receipt)
    mutate_receipt(wire)
    with pytest.raises(ConformanceError) as exc:
        import_final_review_receipt(
            json.dumps(wire, sort_keys=True, separators=(",", ":")).encode(),
            trusted_reviewers=trusted, workspace_id=WORKSPACE, implementation_commit=COMMIT,
            manifest=manifest, evidence_join=evidence_join, now=NOW,
        )
    assert exc.value.code == code
def test_final_receipt_inventory_rejects_duplicate_and_aliased_paths():
    bundles = _bundles()
    bundles[CONFORMANCE]["payload_paths"][0] = "payload/./gate1-decision.json"
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=bundles,
    )
    receipts = _bundles()
    receipts[CONFORMANCE]["payload_paths"][0] = "payload/./gate1-decision.json"
    evidence_join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT,
        import_receipts=receipts, manifest_digest=manifest.manifest_digest,
    )
    arch, critic, trusted = _two_attestations(manifest.manifest_digest)
    with pytest.raises(ConformanceError) as exc:
        write_final_review_receipt(
            workspace_id=WORKSPACE, implementation_commit=COMMIT, manifest=manifest,
            evidence_join=evidence_join, attestations=(arch, critic),
            trusted_reviewers=trusted, now=NOW,
        )
    assert exc.value.code == "receipt_inventory_path_invalid"



@pytest.mark.parametrize(
    ("mutate", "code"),
    (
        (lambda receipt: receipt["attestations"][0].update({"verdict": "REJECT"}), "attestation_invalid_verdict"),
        (lambda receipt: receipt["attestations"][0].update({"reviewer_key_id": "wrong-key"}), "attestation_untrusted_key"),
        (lambda receipt: receipt["attestations"][0].update({"reviewer_role": "PRODUCT_OWNER"}), "attestation_invalid_role"),
        (lambda receipt: receipt["attestations"][1].update({"reviewer_role": ARCHITECT}), "receipt_duplicate_role"),
        (lambda receipt: receipt["attestations"][1].update({"reviewer_key_id": "arch-key-1"}), "receipt_duplicate_key"),
        (lambda receipt: receipt.update({"unexpected": True}), "receipt_fields_invalid"),
        (lambda receipt: receipt.update({"implementation_commit": "ff" * 20}), "receipt_binding_mismatch"),
        (lambda receipt: receipt["attestations"][0].update({"implementation_commit": "ff" * 20}), "attestation_binding_mismatch"),
    ),
)
def test_final_review_receipt_rejects_adversarial_wires(mutate, code):
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    receipt_bytes, trusted, evidence_join = _receipt_bytes(manifest)
    receipt = json.loads(receipt_bytes)
    mutate(receipt)
    with pytest.raises(ConformanceError) as exc:
        import_final_review_receipt(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
            trusted_reviewers=trusted, workspace_id=WORKSPACE, implementation_commit=COMMIT,
            manifest=manifest, evidence_join=evidence_join, now=NOW,
        )
    assert exc.value.code == code


def test_final_review_receipt_rejects_noncanonical_bytes_and_extra_attestation_field():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    receipt_bytes, trusted, evidence_join = _receipt_bytes(manifest)
    with pytest.raises(ConformanceError, match="receipt_noncanonical"):
        import_final_review_receipt(
            receipt_bytes + b"\n", trusted_reviewers=trusted, workspace_id=WORKSPACE,
            implementation_commit=COMMIT, manifest=manifest, evidence_join=evidence_join, now=NOW,
        )

    receipt = json.loads(receipt_bytes)
    receipt["attestations"][0]["extra"] = "forbidden"
    with pytest.raises(ConformanceError) as exc:
        import_final_review_receipt(
            json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode(),
            trusted_reviewers=trusted, workspace_id=WORKSPACE, implementation_commit=COMMIT,
            manifest=manifest, evidence_join=evidence_join, now=NOW,
        )
    assert exc.value.code == "attestation_fields_invalid"
# ---------------------------------------------------------------------------
# Three-import evidence join
# ---------------------------------------------------------------------------


def _import_receipts() -> dict:
    return _bundles()


def test_evidence_join_builds_and_verifies():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    join = build_evidence_join(
        workspace_id=WORKSPACE,
        implementation_commit=COMMIT,
        import_receipts=_import_receipts(),
        manifest_digest=manifest.manifest_digest,
    )
    assert {lane for lane, _ in join.import_receipts} == {GATE1, CONFORMANCE, CANARY}
    verify_evidence_join(join, manifest.manifest_digest)


def test_evidence_join_preserves_receipts_verbatim():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    receipts = _import_receipts()
    join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, import_receipts=receipts, manifest_digest=manifest.manifest_digest
    )
    joined = {lane: receipt for lane, receipt in join.import_receipts}
    assert joined[GATE1] == receipts[GATE1]
    assert joined[CONFORMANCE] == receipts[CONFORMANCE]
    assert joined[CANARY] == receipts[CANARY]


def test_evidence_join_fails_closed_on_missing_lane():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    receipts = _import_receipts()
    del receipts[CANARY]
    with pytest.raises(ConformanceError) as exc:
        build_evidence_join(
            workspace_id=WORKSPACE, implementation_commit=COMMIT, import_receipts=receipts, manifest_digest=manifest.manifest_digest
        )
    assert exc.value.code == "join_missing_lanes"


def test_evidence_join_rejects_wrong_manifest_digest():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    join = build_evidence_join(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, import_receipts=_import_receipts(), manifest_digest=manifest.manifest_digest
    )
    with pytest.raises(ConformanceError) as exc:
        verify_evidence_join(join, "ff" * 32)
    assert exc.value.code == "join_manifest_mismatch"
def test_gate8_runbook_uses_current_receipt_apis_and_workflows():
    runbook = (Path(__file__).resolve().parents[2] / "docs/gate8-runbook.md").read_text(encoding="utf-8")
    for name in (
        "encrypted-lifecycle-gate1-decision.yml",
        "encrypted-lifecycle-conformance.yml",
        "encrypted-lifecycle-canary.yml",
        "encrypted-lifecycle-evidence-join.yml",
        "write_final_review_receipt",
        "import_final_review_receipt",
        "CANARY_DURABLE_STATE_ROOT",
        "same original workflow run ID",
        "fresh workflow dispatch",
    ):
        assert name in runbook
    assert "build_review_receipt" not in runbook
    assert "verify_review_receipt" not in runbook

# ---------------------------------------------------------------------------
# CI producer structure
# ---------------------------------------------------------------------------


def _load_conformance_producer():
    root = Path(__file__).resolve().parents[2]
    scripts = root / "scripts"
    sys.path.insert(0, str(scripts))
    spec = importlib.util.spec_from_file_location(
        "gate8_conformance_producer",
        scripts / "run_encrypted_lifecycle_conformance.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_conformance_producer_issues_exact_payload_and_strictly_imports(tmp_path, monkeypatch):
    producer = _load_conformance_producer()
    monkeypatch.setattr(producer, "_git_head_commit", lambda: COMMIT)
    monkeypatch.setattr(
        producer,
        "run_conformance",
        lambda: {"schema": producer.REPORT_SCHEMA, "conformant": True, "checks": {}},
    )
    output = tmp_path / "report"
    bundle = tmp_path / "bundle"
    metadata = tmp_path / "bundle-metadata.json"
    assert producer.main(
        [
            "--output-dir", str(output),
            "--bundle-output-dir", str(bundle),
            "--artifact-metadata-output", str(metadata),
            "--repository", "owner/repository",
            "--workflow-run-id", "7",
            "--workflow-run-attempt", "1",
            "--platform", "self-hosted/macos-15/arm64/wiki-conformance-workstation",
            "--produced-at", "2026-07-26T01:02:03Z",
            "--source-run-url", "https://github.example/owner/repository/actions/runs/7",
            "--contract-digest", "11" * 32,
            "--toolchain-lock-digest", "22" * 32,
            "--workflow-file-digest", "33" * 32,
        ]
    ) == 0
    payload_path = output / "payload/conformance-pre-canary.json"
    assert payload_path.is_file()
    assert payload_path.read_bytes() == producer.canonical_bytes(
        json.loads(payload_path.read_text(encoding="utf-8"))
    )
    issued = json.loads(metadata.read_text(encoding="utf-8"))
    tar_path = Path(issued["tar_path"])
    assert tar_path.is_file()
    assert issued["expected"]["payload_paths"] == ["payload/conformance-pre-canary.json"]

    from import_encrypted_lifecycle_bundle import import_bundle

    receipt = import_bundle(tar_path, expected=issued["expected"])
    assert receipt["artifact_name"] == issued["artifact_name"]


def test_conformance_producer_strict_import_rejects_wrong_expected_tuple(tmp_path, monkeypatch):
    producer = _load_conformance_producer()
    monkeypatch.setattr(producer, "_git_head_commit", lambda: COMMIT)
    monkeypatch.setattr(
        producer,
        "run_conformance",
        lambda: {"schema": producer.REPORT_SCHEMA, "conformant": True, "checks": {}},
    )
    metadata = tmp_path / "bundle-metadata.json"
    assert producer.main(
        [
            "--output-dir", str(tmp_path / "report"),
            "--bundle-output-dir", str(tmp_path / "bundle"),
            "--artifact-metadata-output", str(metadata),
            "--repository", "owner/repository",
            "--workflow-run-id", "7",
            "--workflow-run-attempt", "1",
            "--platform", "self-hosted/macos-15/arm64/wiki-conformance-workstation",
            "--produced-at", "2026-07-26T01:02:03Z",
            "--source-run-url", "https://github.example/owner/repository/actions/runs/7",
            "--contract-digest", "11" * 32,
            "--toolchain-lock-digest", "22" * 32,
            "--workflow-file-digest", "33" * 32,
        ]
    ) == 0
    issued = json.loads(metadata.read_text(encoding="utf-8"))
    issued["expected"]["producer_commit"] = "ff" * 20

    from import_encrypted_lifecycle_bundle import BundleImportError, import_bundle

    with pytest.raises(BundleImportError) as exc:
        import_bundle(Path(issued["tar_path"]), expected=issued["expected"])
    assert exc.value.code == "EXPECTED_TUPLE_MISMATCH"


def test_gate8_conformance_workflow_is_a_dedicated_macos_producer():
    root = Path(__file__).resolve().parents[2]
    conformance = (
        root / ".github/workflows/encrypted-lifecycle-conformance.yml"
    ).read_text(encoding="utf-8")

    assert "runs-on: [self-hosted, macOS, ARM64, wiki-conformance-workstation]" in conformance
    assert "gate8-evidence-join:" not in conformance
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in conformance
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in conformance
    assert "actions/upload-artifact@0b7f8abb1508181956e8e162db84b466c27e18ce" in conformance
    assert "implementation_commit:" in conformance
    assert 'ref: ${{ inputs.implementation_commit }}' in conformance
    assert 'test "$(git symbolic-ref -q HEAD || true)" = ""' in conformance
    assert 'test "$(git rev-parse HEAD)" = "${{ inputs.implementation_commit }}"' in conformance
    assert 'test "$(uname -s)" = "Darwin"' in conformance
    assert 'test "$(uname -r | cut -d. -f1)" = "24"' in conformance
    assert 'test "$(uname -m)" = "arm64"' in conformance
    assert 'test "${{ github.sha }}" = "${{ inputs.implementation_commit }}"' in conformance
    for action in ("checkout", "setup-python", "upload-artifact"):
        assert re.search(rf"actions/{action}@[0-9a-f]{{40}}", conformance)
    assert "--produced-at" in conformance
    assert "--source-run-url" in conformance
    assert "payload/conformance-pre-canary.json" in conformance
    assert 'name: ${{ steps.bundle.outputs.artifact_name }}' in conformance
    assert 'path: ${{ steps.bundle.outputs.tar_path }}' in conformance
    assert 'expected = {"repository": sys.argv[4]' in conformance
