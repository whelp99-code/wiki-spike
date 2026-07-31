"""Integration tests for ``scripts/issue_gate8_receipt.py``: the Gate 8
section 4 CLI that issues reviewer attestations, writes the final review
receipt, and strictly imports it -- as subprocess invocations, exactly as an
operator following docs/gate8-runbook.md §4 would run them."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure.conformance import (
    CANARY,
    CONFORMANCE,
    GATE1,
    build_evidence_join,
    build_pre_review_manifest,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "issue_gate8_receipt.py"
SRC = REPO_ROOT / "src"

WORKSPACE = "ws-gate8-cli"
COMMIT = "cd" * 20
NOW = "2026-07-26T12:00:00Z"
ISSUED_AT = "2026-07-26T11:30:00Z"
EXPIRES_AT = "2026-07-26T12:30:00Z"


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
            platform="self-hosted/macos-26/arm64/wiki-gate1-workstation",
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
            platform="self-hosted/macos-26/arm64/wiki-conformance-workstation",
            workflow_run_id="2",
            payload_paths=["payload/conformance-pre-canary.json"],
            payload_sha256=["51" * 32],
        ),
        CANARY: _receipt(
            artifact_name="encrypted-lifecycle-canary-24h-3-1-0123456789abcdef",
            artifact_kind="CANARY_24H",
            bundle_sha256="33" * 32,
            platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
            workflow_run_id="3",
            payload_paths=["payload/rollout-evidence.json"],
            payload_sha256=["61" * 32],
        ),
    }


def _write_manifest_and_join(out_dir: Path, *, workspace_id: str = WORKSPACE, implementation_commit: str = COMMIT) -> tuple[Path, Path, str]:
    bundles = _bundles()
    manifest = build_pre_review_manifest(
        workspace_id=workspace_id, implementation_commit=implementation_commit, bundles=bundles,
    )
    join = build_evidence_join(
        workspace_id=workspace_id, implementation_commit=implementation_commit,
        import_receipts=bundles, manifest_digest=manifest.manifest_digest,
    )
    manifest_doc = {
        "schema": manifest.schema,
        "workspace_id": manifest.workspace_id,
        "implementation_commit": manifest.implementation_commit,
        "bundles": [{"lane": b.lane, "receipt": b.receipt} for b in manifest.bundles],
        "manifest_digest": manifest.manifest_digest,
    }
    join_doc = {
        "schema": join.schema,
        "workspace_id": join.workspace_id,
        "implementation_commit": join.implementation_commit,
        "import_receipts": [{"lane": lane, "receipt": receipt} for lane, receipt in join.import_receipts],
        "manifest_digest": join.manifest_digest,
        "join_digest": join.join_digest,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "pre-review-manifest.json"
    join_path = out_dir / "evidence-join.json"
    manifest_path.write_text(json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    join_path.write_text(json.dumps(join_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest_path, join_path, manifest.manifest_digest


def _write_key(path: Path, raw: bytes) -> Path:
    path.write_text(raw.hex(), encoding="utf-8")
    return path


def _run(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SRC)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT),
    )


@pytest.fixture()
def keys(tmp_path: Path) -> dict:
    arch_key, critic_key = _key(b"cli-architect"), _key(b"cli-critic")
    arch_priv = _write_key(tmp_path / "arch.priv", arch_key.private_bytes_raw())
    arch_pub = _write_key(tmp_path / "arch.pub", arch_key.public_key().public_bytes_raw())
    critic_priv = _write_key(tmp_path / "critic.priv", critic_key.private_bytes_raw())
    critic_pub = _write_key(tmp_path / "critic.pub", critic_key.public_key().public_bytes_raw())
    return {
        "arch_key": arch_key, "critic_key": critic_key,
        "arch_priv": arch_priv, "arch_pub": arch_pub,
        "critic_priv": critic_priv, "critic_pub": critic_pub,
    }


@pytest.fixture()
def manifest_join(tmp_path: Path):
    manifest_path, join_path, manifest_digest = _write_manifest_and_join(tmp_path / "join-out")
    return manifest_path, join_path, manifest_digest


def _attest(tmp_path: Path, manifest_path: Path, *, role: str, key_id: str, private_key_path: Path,
            issued_at: str = ISSUED_AT, expires_at: str = EXPIRES_AT, out_name: str) -> tuple[subprocess.CompletedProcess, Path]:
    out_path = tmp_path / out_name
    result = _run(
        "attest",
        "--manifest", str(manifest_path),
        "--role", role,
        "--key-id", key_id,
        "--private-key", str(private_key_path),
        "--issued-at", issued_at,
        "--expires-at", expires_at,
        "--out", str(out_path),
    )
    return result, out_path


def _trusted_reviewer_args(keys: dict, *, arch_key_id: str = "arch-key-1", critic_key_id: str = "critic-key-1",
                            arch_pub: Path | None = None, critic_pub: Path | None = None) -> list[str]:
    arch_pub = arch_pub or keys["arch_pub"]
    critic_pub = critic_pub or keys["critic_pub"]
    return [
        "--trusted-reviewer", f"ARCHITECT={arch_key_id}={arch_pub}",
        "--trusted-reviewer", f"CRITIC={critic_key_id}={critic_pub}",
    ]


def test_happy_path_attest_receipt_verify(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join

    arch_result, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch-attestation.json",
    )
    assert arch_result.returncode == 0, arch_result.stderr
    critic_result, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic-attestation.json",
    )
    assert critic_result.returncode == 0, critic_result.stderr

    receipt_path = tmp_path / "final-review-receipt.json"
    receipt_result = _run(
        "receipt",
        "--manifest", str(manifest_path),
        "--join", str(join_path),
        "--attestation", str(arch_attestation),
        "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE,
        "--implementation-commit", COMMIT,
        "--now", NOW,
        "--out", str(receipt_path),
    )
    assert receipt_result.returncode == 0, receipt_result.stderr
    assert receipt_path.exists()

    verify_result = _run(
        "verify",
        "--receipt", str(receipt_path),
        "--manifest", str(manifest_path),
        "--join", str(join_path),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE,
        "--implementation-commit", COMMIT,
        "--now", NOW,
    )
    assert verify_result.returncode == 0, verify_result.stderr
    assert "VERIFIED" in verify_result.stdout
    assert "reviewer_role=ARCHITECT" in verify_result.stdout
    assert "reviewer_role=CRITIC" in verify_result.stdout


def test_receipt_output_round_trips_through_verify(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch-attestation.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic-attestation.json",
    )
    receipt_path = tmp_path / "final-review-receipt.json"
    receipt_result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(receipt_path),
    )
    assert receipt_result.returncode == 0, receipt_result.stderr
    written_bytes = receipt_path.read_bytes()

    # Re-run verify against the exact bytes written; the CLI never rewrites
    # what it verifies (no re-serialization).
    verify_result = _run(
        "verify", "--receipt", str(receipt_path), "--manifest", str(manifest_path), "--join", str(join_path),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
    )
    assert verify_result.returncode == 0, verify_result.stderr
    assert receipt_path.read_bytes() == written_bytes


def test_receipt_rejects_same_role_attested_twice(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch1 = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch1.json",
    )
    _, arch2 = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-2",
        private_key_path=keys["critic_priv"], out_name="arch2.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch1), "--attestation", str(arch2),
        *_trusted_reviewer_args(keys, arch_key_id="arch-key-1", critic_key_id="arch-key-2", critic_pub=keys["critic_pub"]),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_receipt_rejects_same_key_id_for_both_roles(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="dup-key",
        private_key_path=keys["arch_priv"], out_name="arch.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="dup-key",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys, arch_key_id="dup-key", critic_key_id="dup-key"),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_receipt_rejects_attestation_over_different_manifest_digest(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    other_manifest_path, _, _ = _write_manifest_and_join(tmp_path / "other-join-out", workspace_id="ws-gate8-cli-other")

    # Architect attests the *other* manifest; critic attests the real one.
    _, arch_attestation = _attest(
        tmp_path, other_manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch-wrong-manifest.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_receipt_rejects_expired_attestation(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT,
        "--now", "2026-07-26T13:00:00Z",  # past EXPIRES_AT
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_receipt_rejects_attestation_lifetime_over_one_hour(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch.json",
        issued_at="2026-07-26T10:00:00Z", expires_at="2026-07-26T11:00:01Z",  # 3601s
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_receipt_rejects_untrusted_reviewer_public_key(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    rogue_key = _key(b"rogue-reviewer")
    rogue_pub = _write_key(tmp_path / "rogue.pub", rogue_key.public_key().public_bytes_raw())
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys, arch_pub=rogue_pub),  # wrong key under the right key-id
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr


def test_verify_rejects_tampered_receipt_bytes(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch.json",
    )
    _, critic_attestation = _attest(
        tmp_path, manifest_path, role="CRITIC", key_id="critic-key-1",
        private_key_path=keys["critic_priv"], out_name="critic.json",
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation), "--attestation", str(critic_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(receipt_path),
    )
    assert receipt_result.returncode == 0, receipt_result.stderr

    tampered = bytearray(receipt_path.read_bytes())
    # Flip one byte inside the JSON payload to break canonical bytes / digest binding.
    for index in range(len(tampered)):
        if tampered[index:index + 1].isdigit():
            tampered[index] = ord("9") if tampered[index] != ord("9") else ord("8")
            break
    tampered_path = tmp_path / "receipt-tampered.json"
    tampered_path.write_bytes(bytes(tampered))

    verify_result = _run(
        "verify", "--receipt", str(tampered_path), "--manifest", str(manifest_path), "--join", str(join_path),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
    )
    assert verify_result.returncode == 1
    assert "REJECTED [" in verify_result.stderr


def test_receipt_rejects_only_one_attestation_supplied(tmp_path: Path, keys, manifest_join):
    manifest_path, join_path, _ = manifest_join
    _, arch_attestation = _attest(
        tmp_path, manifest_path, role="ARCHITECT", key_id="arch-key-1",
        private_key_path=keys["arch_priv"], out_name="arch.json",
    )
    result = _run(
        "receipt",
        "--manifest", str(manifest_path), "--join", str(join_path),
        "--attestation", str(arch_attestation),
        *_trusted_reviewer_args(keys),
        "--workspace-id", WORKSPACE, "--implementation-commit", COMMIT, "--now", NOW,
        "--out", str(tmp_path / "receipt.json"),
    )
    assert result.returncode == 1
    assert "REJECTED [" in result.stderr
