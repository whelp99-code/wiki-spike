from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.build_phase2_checkpoint import DOMAIN, build_checkpoint
from scripts.preflight_common import PreflightError, sha256_bytes, sha256_file, strict_json_load, write_canonical_json
from scripts.verify_phase2_checkpoint import verify_checkpoint
from wiki_spike.canonical import canonical_bytes

BASELINE = "026bc351020661cd91dc44b79e1d250d21e89a84"
REPOSITORY = "whelp99-code/wiki-spike"


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def _make_signed_repo(tmp_path: Path) -> tuple[Path, Path]:
    source = repo_root()
    repo = tmp_path / "repo"
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(source), str(repo)], check=True)
    subprocess.run(["git", "checkout", "-q", BASELINE], cwd=repo, check=True)
    evidence_path = repo / "artifacts/checkpoints/g2/phase2-storage-test-evidence.json"
    write_canonical_json(
        evidence_path,
        {
            "baseline_commit": BASELINE,
            "commands": [],
            "result": "pass",
            "schema_version": "phase2-storage-test-evidence-v1",
            "test_count": "116",
        },
    )
    key_path = tmp_path / "checkpoint.key"
    key = Ed25519PrivateKey.generate()
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    output = repo / "artifacts/checkpoints/g2"
    build_checkpoint(
        repo=repo,
        baseline_commit=BASELINE,
        repository=REPOSITORY,
        private_key_path=key_path,
        evidence_path=evidence_path,
        output_dir=output,
        created_at="2026-07-22T00:00:00+09:00",
        signer_key_id="test-key",
    )
    _refresh_trust(repo)
    return repo, key_path


def _paths(repo: Path) -> dict[str, Path]:
    base = repo / "artifacts/checkpoints/g2"
    return {
        "manifest": base / "phase2-storage-checkpoint.json",
        "signature": base / "phase2-storage-checkpoint.sig",
        "public": base / "phase2-storage-public-key.pem",
        "trust": repo / ".github/phase2-checkpoint-trust.json",
        "evidence": base / "phase2-storage-test-evidence.json",
    }


def _refresh_trust(repo: Path) -> None:
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    checkpoint = manifest["checkpoint"]
    write_canonical_json(
        p["trust"],
        {
            "baseline_commit": checkpoint["baseline_commit"],
            "checkpoint_id": manifest["checkpoint_id"],
            "public_key_sha256": checkpoint["public_key_sha256"],
            "repository": checkpoint["repository"],
            "schema_version": "phase2-checkpoint-trust-v1",
        },
    )


def _resign(repo: Path, key_path: Path, *, recompute_id: bool = True) -> None:
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    if recompute_id:
        manifest["checkpoint_id"] = sha256_bytes(canonical_bytes(manifest["checkpoint"]))
        write_canonical_json(p["manifest"], manifest)
    key = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
    signature = key.sign(DOMAIN + b"\x00" + p["manifest"].read_bytes())
    p["signature"].write_text(base64.b64encode(signature).decode("ascii"), encoding="ascii")
    _refresh_trust(repo)


def _verify(repo: Path) -> dict:
    p = _paths(repo)
    return verify_checkpoint(
        repo=repo,
        manifest_path=p["manifest"],
        signature_path=p["signature"],
        public_key_path=p["public"],
        trust_path=p["trust"],
    )


def test_committed_checkpoint_verifies():
    root = repo_root()
    result = verify_checkpoint(
        repo=root,
        manifest_path=root / "artifacts/checkpoints/g2/phase2-storage-checkpoint.json",
        signature_path=root / "artifacts/checkpoints/g2/phase2-storage-checkpoint.sig",
        public_key_path=root / "artifacts/checkpoints/g2/phase2-storage-public-key.pem",
        trust_path=root / ".github/phase2-checkpoint-trust.json",
    )
    assert result["status"] == "pass"
    assert result["evidence_test_count"] == 116


def test_fresh_checkpoint_verifies(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    assert _verify(repo)["checkpoint_id"]


def test_unknown_manifest_field_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    value = strict_json_load(p["manifest"], require_canonical=True)
    value["unexpected"] = "x"
    write_canonical_json(p["manifest"], value)
    _resign(repo, key, recompute_id=False)
    with pytest.raises(PreflightError, match="keys mismatch"):
        _verify(repo)


def test_duplicate_json_key_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    p = _paths(repo)
    p["manifest"].write_text('{"checkpoint_id":"x","checkpoint_id":"y","checkpoint":{}}')
    with pytest.raises(PreflightError, match="duplicate JSON key"):
        _verify(repo)


def test_noncanonical_json_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    p = _paths(repo)
    value = strict_json_load(p["manifest"], require_canonical=True)
    p["manifest"].write_text(json.dumps(value, indent=2), encoding="utf-8")
    with pytest.raises(PreflightError, match="not byte-for-byte canonical"):
        _verify(repo)


def test_checkpoint_id_mismatch_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    value = strict_json_load(p["manifest"], require_canonical=True)
    value["checkpoint_id"] = "0" * 64
    write_canonical_json(p["manifest"], value)
    _resign(repo, key, recompute_id=False)
    with pytest.raises(PreflightError, match="checkpoint_id"):
        _verify(repo)


def test_corrupt_signature_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    _paths(repo)["signature"].write_text(base64.b64encode(b"x" * 64).decode("ascii"))
    with pytest.raises(PreflightError, match="signature verification failed"):
        _verify(repo)


def test_non_base64_signature_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    _paths(repo)["signature"].write_text("not base64!")
    with pytest.raises(PreflightError, match="strict base64"):
        _verify(repo)


def test_corrupt_public_key_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    _paths(repo)["public"].write_text("not a key")
    with pytest.raises(PreflightError, match="invalid checkpoint public key"):
        _verify(repo)


def test_public_key_fingerprint_mismatch_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    value = strict_json_load(p["manifest"], require_canonical=True)
    value["checkpoint"]["public_key_sha256"] = "0" * 64
    write_canonical_json(p["manifest"], value)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="fingerprint"):
        _verify(repo)


def test_trust_record_mismatch_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    p = _paths(repo)
    trust = strict_json_load(p["trust"], require_canonical=True)
    trust["repository"] = "attacker/repo"
    write_canonical_json(p["trust"], trust)
    with pytest.raises(PreflightError, match="trust mismatch"):
        _verify(repo)


def test_evidence_digest_mismatch_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    _paths(repo)["evidence"].write_text("{}")
    with pytest.raises(PreflightError, match="evidence digest"):
        _verify(repo)


def test_evidence_path_escape_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["test_evidence"]["path"] = "../../outside.json"
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="escapes repository"):
        _verify(repo)


def test_baseline_not_ancestor_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "checkout", "--orphan", "divergent"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "rm", "-rf", "."], cwd=repo, check=True, stdout=subprocess.DEVNULL)
    (repo / "other.txt").write_text("other")
    subprocess.run(["git", "add", "other.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-m", "divergent"], cwd=repo, check=True, stdout=subprocess.DEVNULL)
    # Restore untracked verification artifacts removed by git rm.
    source = repo_root()
    shutil.copytree(source / "artifacts/checkpoints/g2", repo / "artifacts/checkpoints/g2", dirs_exist_ok=True)
    (repo / ".github").mkdir(exist_ok=True)
    shutil.copy2(source / ".github/phase2-checkpoint-trust.json", repo / ".github/phase2-checkpoint-trust.json")
    with pytest.raises(PreflightError, match="not an ancestor"):
        _verify(repo)


def test_tree_sha_mismatch_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["baseline_tree_sha"] = "0" * 40
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="tree sha mismatch"):
        _verify(repo)


def test_tree_listing_digest_mismatch_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["baseline_tree_listing_sha256"] = "0" * 64
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="tree listing"):
        _verify(repo)


def test_unknown_schema_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["schema_version"] = "phase2-storage-checkpoint-v999"
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="unsupported checkpoint schema"):
        _verify(repo)


def test_raw_number_rejected(tmp_path):
    repo, _ = _make_signed_repo(tmp_path)
    p = _paths(repo)
    raw = p["manifest"].read_text()
    raw = raw.replace('"tracked_file_count":"55"', '"tracked_file_count":55')
    p["manifest"].write_text(raw)
    with pytest.raises(PreflightError, match="raw JSON number forbidden"):
        _verify(repo)


def test_tracked_file_count_mismatch_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["tracked_file_count"] = "999"
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="tracked file count"):
        _verify(repo)


def test_regression_count_below_minimum_rejected(tmp_path):
    repo, key = _make_signed_repo(tmp_path)
    p = _paths(repo)
    evidence = strict_json_load(p["evidence"], require_canonical=True)
    evidence["test_count"] = "1"
    write_canonical_json(p["evidence"], evidence)
    manifest = strict_json_load(p["manifest"], require_canonical=True)
    manifest["checkpoint"]["test_evidence"]["sha256"] = sha256_file(p["evidence"])
    write_canonical_json(p["manifest"], manifest)
    _resign(repo, key)
    with pytest.raises(PreflightError, match="below required minimum"):
        _verify(repo)
