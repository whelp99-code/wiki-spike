"""Gate 8 conformance machinery tests: verdict-free pre-review manifest, two
independent attestations (ARCHITECT/CRITIC), separate receipt, and three-import
evidence join."""
from __future__ import annotations

import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure.conformance import (
    ARCHITECT,
    CANARY,
    CONFORMANCE,
    CRITIC,
    GATE1,
    ConformanceError,
    attest_manifest,
    build_evidence_join,
    build_pre_review_manifest,
    build_review_receipt,
    verify_attestation,
    verify_evidence_join,
    verify_review_receipt,
)

WORKSPACE = "ws-test-1"
COMMIT = "ab" * 20  # 40-hex implementation commit


def _key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())


def _bundles() -> dict:
    return {
        GATE1: {
            "artifact_name": "encrypted-lifecycle-gate1-decision-1-1-0123456789abcdef",
            "artifact_kind": "GATE1_DECISION",
            "bundle_sha256": "11" * 32,
            "platform": "self-hosted/macos-15/arm64/wiki-gate1-workstation",
        },
        CONFORMANCE: {
            "artifact_name": "encrypted-lifecycle-conformance-pre-canary-2-1-0123456789abcdef",
            "artifact_kind": "CONFORMANCE_PRE_CANARY",
            "bundle_sha256": "22" * 32,
            "platform": "self-hosted/macos-15/arm64/wiki-conformance-workstation",
        },
        CANARY: {
            "artifact_name": "encrypted-lifecycle-canary-24h-3-1-0123456789abcdef",
            "artifact_kind": "CANARY_24H",
            "bundle_sha256": "33" * 32,
            "platform": "self-hosted/macos-15/arm64/wiki-canary-workstation",
        },
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
    assert exc.value.code == "manifest_lane_field_missing"


# ---------------------------------------------------------------------------
# Independent attestations
# ---------------------------------------------------------------------------


def test_attestations_verify_under_their_own_keys():
    manifest = build_pre_review_manifest(
        workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles()
    )
    arch_key, critic_key = _key(b"architect"), _key(b"critic")
    arch = attest_manifest(role=ARCHITECT, key_id="arch-key-1", private_key=arch_key, manifest_digest=manifest.manifest_digest)
    critic = attest_manifest(role=CRITIC, key_id="critic-key-1", private_key=critic_key, manifest_digest=manifest.manifest_digest)

    # Each verifies under its own key, independently.
    verify_attestation(arch, arch_key.public_key(), manifest.manifest_digest)
    verify_attestation(critic, critic_key.public_key(), manifest.manifest_digest)


def test_attestation_rejects_wrong_key():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch = attest_manifest(role=ARCHITECT, key_id="arch-key-1", private_key=_key(b"architect"), manifest_digest=manifest.manifest_digest)
    with pytest.raises(ConformanceError) as exc:
        verify_attestation(arch, _key(b"imposter").public_key(), manifest.manifest_digest)
    assert exc.value.code == "attestation_signature_invalid"


def test_attestation_rejects_wrong_manifest_digest():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch_key = _key(b"architect")
    arch = attest_manifest(role=ARCHITECT, key_id="arch-key-1", private_key=arch_key, manifest_digest=manifest.manifest_digest)
    with pytest.raises(ConformanceError) as exc:
        verify_attestation(arch, arch_key.public_key(), "ff" * 32)
    assert exc.value.code == "attestation_manifest_mismatch"


def test_attestation_rejects_invalid_role():
    with pytest.raises(ConformanceError) as exc:
        attest_manifest(role="PRODUCT_OWNER", key_id="k", private_key=_key(b"x"), manifest_digest="aa" * 32)
    assert exc.value.code == "attestation_invalid_role"


# ---------------------------------------------------------------------------
# Separate review receipt
# ---------------------------------------------------------------------------


def _two_attestations(manifest_digest: str):
    arch_key, critic_key = _key(b"architect"), _key(b"critic")
    arch = attest_manifest(role=ARCHITECT, key_id="arch-key-1", private_key=arch_key, manifest_digest=manifest_digest)
    critic = attest_manifest(role=CRITIC, key_id="critic-key-1", private_key=critic_key, manifest_digest=manifest_digest)
    return arch, critic, {ARCHITECT: arch_key.public_key(), CRITIC: critic_key.public_key()}


def test_review_receipt_builds_and_verifies():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch, critic, pubkeys = _two_attestations(manifest.manifest_digest)
    receipt = build_review_receipt(
        workspace_id=WORKSPACE, manifest_digest=manifest.manifest_digest, attestations=(arch, critic)
    )
    assert len(receipt.receipt_digest) == 64
    verify_review_receipt(receipt, pubkeys, manifest.manifest_digest)


def test_review_receipt_rejects_duplicate_role():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch_key = _key(b"architect")
    a1 = attest_manifest(role=ARCHITECT, key_id="k1", private_key=arch_key, manifest_digest=manifest.manifest_digest)
    a2 = attest_manifest(role=ARCHITECT, key_id="k2", private_key=arch_key, manifest_digest=manifest.manifest_digest)
    with pytest.raises(ConformanceError) as exc:
        build_review_receipt(workspace_id=WORKSPACE, manifest_digest=manifest.manifest_digest, attestations=(a1, a2))
    assert exc.value.code == "receipt_duplicate_role"


def test_review_receipt_rejects_single_attestation():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch, _critic, _pub = _two_attestations(manifest.manifest_digest)
    with pytest.raises(ConformanceError) as exc:
        build_review_receipt(workspace_id=WORKSPACE, manifest_digest=manifest.manifest_digest, attestations=(arch,))
    assert exc.value.code == "receipt_attestation_count"


def test_review_receipt_rejects_forged_attestation():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch, critic, pubkeys = _two_attestations(manifest.manifest_digest)
    receipt = build_review_receipt(
        workspace_id=WORKSPACE, manifest_digest=manifest.manifest_digest, attestations=(arch, critic)
    )
    # Swap the critic public key for an imposter -> verification must fail.
    bad_pubkeys = dict(pubkeys)
    bad_pubkeys[CRITIC] = _key(b"imposter").public_key()
    with pytest.raises(ConformanceError) as exc:
        verify_review_receipt(receipt, bad_pubkeys, manifest.manifest_digest)
    assert exc.value.code == "attestation_signature_invalid"


def test_review_receipt_rejects_wrong_manifest_digest():
    manifest = build_pre_review_manifest(workspace_id=WORKSPACE, implementation_commit=COMMIT, bundles=_bundles())
    arch, critic, pubkeys = _two_attestations(manifest.manifest_digest)
    receipt = build_review_receipt(
        workspace_id=WORKSPACE, manifest_digest=manifest.manifest_digest, attestations=(arch, critic)
    )
    with pytest.raises(ConformanceError) as exc:
        verify_review_receipt(receipt, pubkeys, "ff" * 32)
    assert exc.value.code == "receipt_manifest_mismatch"


# ---------------------------------------------------------------------------
# Three-import evidence join
# ---------------------------------------------------------------------------


def _import_receipts() -> dict:
    return {
        GATE1: {"artifact_name": "g1", "bundle_sha256": "11" * 32, "payload_paths": ["a.json"], "verified": True},
        CONFORMANCE: {"artifact_name": "cf", "bundle_sha256": "22" * 32, "payload_paths": ["b.json"], "verified": True},
        CANARY: {"artifact_name": "cn", "bundle_sha256": "33" * 32, "payload_paths": ["c.json"], "verified": True},
    }


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
