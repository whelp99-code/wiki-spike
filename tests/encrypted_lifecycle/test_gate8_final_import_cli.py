from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure.conformance import (
    ARCHITECT,
    CANARY,
    CONFORMANCE,
    CRITIC,
    GATE1,
    attest_manifest,
    build_evidence_join,
    build_pre_review_manifest,
    import_final_review_receipt,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes

_COMMIT = "d" * 40
_WORKSPACE = "workspace-gate8-test"
_ISSUED_AT = "2026-08-18T08:00:00Z"
_EXPIRES_AT = "2026-08-18T08:30:00Z"
_NOW = "2026-08-18T08:15:00Z"
_KINDS = {
    GATE1: "GATE1_DECISION",
    CONFORMANCE: "CONFORMANCE_PRE_CANARY",
    CANARY: "CANARY_24H",
}


class Summary(TypedDict):
    manifest_digest: str
    join_digest: str


def _summary(stdout: str) -> Summary:
    raw_value = cast(object, json.loads(stdout))
    if not isinstance(raw_value, dict):
        raise TypeError("CLI summary must be a JSON object")
    value = cast(dict[object, object], raw_value)
    manifest_digest = value.get("manifest_digest")
    join_digest = value.get("join_digest")
    if not isinstance(manifest_digest, str) or not isinstance(join_digest, str):
        raise TypeError("CLI summary digests must be strings")
    return {"manifest_digest": manifest_digest, "join_digest": join_digest}


def _receipt(lane: str, position: int) -> dict[str, JsonValue]:
    digest_character = "abcdef"[position]
    return {
        "repository": "owner/repository",
        "artifact_kind": _KINDS[lane],
        "platform": f"test/{lane}",
        "producer_commit": _COMMIT,
        "contract_digest": "1" * 64,
        "toolchain_lock_digest": "2" * 64,
        "workflow_file_digest": "3" * 64,
        "workflow_run_id": str(position + 1),
        "workflow_run_attempt": "1",
        "artifact_name": f"{lane}-artifact",
        "bundle_sha256": digest_character * 64,
        "payload_paths": [f"payload/{lane}.json"],
        "payload_sha256": [str(position + 4) * 64],
        "source_run_url": f"https://example.invalid/runs/{position + 1}",
        "verified": True,
    }


def _write_review_inputs(tmp_path: Path):
    receipts = {
        lane: _receipt(lane, position)
        for position, lane in enumerate((GATE1, CONFORMANCE, CANARY))
    }
    manifest = build_pre_review_manifest(
        workspace_id=_WORKSPACE,
        implementation_commit=_COMMIT,
        bundles=receipts,
    )
    evidence_join = build_evidence_join(
        workspace_id=_WORKSPACE,
        implementation_commit=_COMMIT,
        import_receipts=receipts,
        manifest_digest=manifest.manifest_digest,
    )
    manifest_path = tmp_path / "manifest.json"
    _ = manifest_path.write_bytes(
        canonical_bytes(
            {
                "schema": manifest.schema,
                "workspace_id": manifest.workspace_id,
                "implementation_commit": manifest.implementation_commit,
                "bundles": [
                    {"lane": bundle.lane, "receipt": bundle.receipt}
                    for bundle in manifest.bundles
                ],
                "manifest_digest": manifest.manifest_digest,
            }
        )
    )
    join_path = tmp_path / "evidence-join.json"
    _ = join_path.write_bytes(
        canonical_bytes(
            {
                "schema": evidence_join.schema,
                "workspace_id": evidence_join.workspace_id,
                "implementation_commit": evidence_join.implementation_commit,
                "import_receipts": [
                    {"lane": lane, "receipt": receipt}
                    for lane, receipt in evidence_join.import_receipts
                ],
                "manifest_digest": evidence_join.manifest_digest,
                "join_digest": evidence_join.join_digest,
            }
        )
    )

    architect_key = Ed25519PrivateKey.generate()
    critic_key = Ed25519PrivateKey.generate()
    architect = attest_manifest(
        reviewer_role=ARCHITECT,
        reviewer_key_id="architect-key-1",
        private_key=architect_key,
        workspace_id=_WORKSPACE,
        implementation_commit=_COMMIT,
        manifest_digest=manifest.manifest_digest,
        issued_at=_ISSUED_AT,
        expires_at=_EXPIRES_AT,
    )
    critic = attest_manifest(
        reviewer_role=CRITIC,
        reviewer_key_id="critic-key-1",
        private_key=critic_key,
        workspace_id=_WORKSPACE,
        implementation_commit=_COMMIT,
        manifest_digest=manifest.manifest_digest,
        issued_at=_ISSUED_AT,
        expires_at=_EXPIRES_AT,
    )
    paths = {
        "manifest": manifest_path,
        "evidence_join": join_path,
        "architect_attestation": tmp_path / "architect-attestation.json",
        "architect_public_key": tmp_path / "architect-public.pem",
        "critic_attestation": tmp_path / "critic-attestation.json",
        "critic_public_key": tmp_path / "critic-public.pem",
    }
    _ = paths["architect_attestation"].write_bytes(
        canonical_bytes(architect.to_mapping())
    )
    _ = paths["critic_attestation"].write_bytes(canonical_bytes(critic.to_mapping()))
    _ = paths["architect_public_key"].write_bytes(
        architect_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _ = paths["critic_public_key"].write_bytes(
        critic_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    trusted = {
        ARCHITECT: ("architect-key-1", architect_key.public_key()),
        CRITIC: ("critic-key-1", critic_key.public_key()),
    }
    return paths, manifest, evidence_join, trusted


def _command(paths: dict[str, Path], output: Path) -> list[str]:
    return [
        sys.executable,
        "scripts/import_gate8_final_review_receipt.py",
        "--manifest",
        str(paths["manifest"]),
        "--evidence-join",
        str(paths["evidence_join"]),
        "--architect-attestation",
        str(paths["architect_attestation"]),
        "--architect-public-key",
        str(paths["architect_public_key"]),
        "--critic-attestation",
        str(paths["critic_attestation"]),
        "--critic-public-key",
        str(paths["critic_public_key"]),
        "--now",
        _NOW,
        "--output",
        str(output),
    ]


def test_cli_writes_and_strictly_imports_final_receipt(tmp_path: Path) -> None:
    paths, manifest, evidence_join, trusted = _write_review_inputs(tmp_path)
    output = tmp_path / "final-review-receipt.json"

    result = subprocess.run(
        _command(paths, output),
        check=True,
        capture_output=True,
        text=True,
    )

    summary = _summary(result.stdout)
    assert summary["manifest_digest"] == manifest.manifest_digest
    assert summary["join_digest"] == evidence_join.join_digest
    imported = import_final_review_receipt(
        output.read_bytes(),
        trusted_reviewers=trusted,
        workspace_id=_WORKSPACE,
        implementation_commit=_COMMIT,
        manifest=manifest,
        evidence_join=evidence_join,
        now=_NOW,
    )
    assert tuple(attestation.reviewer_role for attestation in imported) == (
        ARCHITECT,
        CRITIC,
    )


def test_cli_refuses_to_overwrite_existing_receipt(tmp_path: Path) -> None:
    paths, _, _, _ = _write_review_inputs(tmp_path)
    output = tmp_path / "final-review-receipt.json"
    _ = output.write_text("existing", encoding="utf-8")

    result = subprocess.run(
        _command(paths, output),
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert output.read_text(encoding="utf-8") == "existing"


def test_cli_rejects_durable_receipt_outside_foundational_tree(
    tmp_path: Path,
) -> None:
    paths, _, _, _ = _write_review_inputs(tmp_path)
    output = tmp_path / "final-review-receipt.json"

    result = subprocess.run(
        [
            *_command(paths, output),
            "--durable",
            "--repository-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert (
        "durable output must be under artifacts/encrypted-lifecycle/gate8-final"
        in result.stderr
    )
    assert not output.exists()


def test_cli_rejects_durable_receipt_symlink_escape(tmp_path: Path) -> None:
    paths, _, _, _ = _write_review_inputs(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    durable_tree = (
        tmp_path / "artifacts" / "encrypted-lifecycle" / "gate8-final"
    )
    durable_tree.parent.mkdir(parents=True)
    durable_tree.symlink_to(outside, target_is_directory=True)
    output = durable_tree / "final-review-receipt.json"

    result = subprocess.run(
        [
            *_command(paths, output),
            "--durable",
            "--repository-root",
            str(tmp_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "durable output path must not traverse symlinks" in result.stderr
    assert not (outside / "final-review-receipt.json").exists()
