#!/usr/bin/env python3
"""Verify the signed Phase 2 storage checkpoint and its local Git inputs."""
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from .preflight_common import (
        PreflightError, ensure_within, find_repo_root, git, git_object_exists,
        git_tree_listing, require_exact_keys, sha256_bytes, sha256_file,
        strict_json_load,
    )
except ImportError:  # direct script execution
    from preflight_common import (
        PreflightError, ensure_within, find_repo_root, git, git_object_exists,
        git_tree_listing, require_exact_keys, sha256_bytes, sha256_file,
        strict_json_load,
    )
from wiki_spike.canonical import canonical_bytes

DOMAIN = b"wiki.phase2.checkpoint.v1"
SCHEMA_VERSION = "phase2-storage-checkpoint-v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")

MANIFEST_KEYS = {"checkpoint", "checkpoint_id"}
CHECKPOINT_KEYS = {
    "acceptance",
    "baseline_commit",
    "baseline_tree_listing_sha256",
    "baseline_tree_sha",
    "checkpoint_scope",
    "created_at",
    "public_key_sha256",
    "repository",
    "schema_version",
    "signer_key_id",
    "signing_domain",
    "test_evidence",
    "tracked_file_count",
}
ACCEPTANCE_KEYS = {
    "minimum_regression_tests",
    "package_install",
    "secret_scan",
    "warnings_as_errors",
}
EVIDENCE_REF_KEYS = {"path", "sha256"}
TRUST_KEYS = {
    "baseline_commit",
    "checkpoint_id",
    "public_key_sha256",
    "repository",
    "schema_version",
}
EVIDENCE_KEYS = {
    "baseline_commit",
    "commands",
    "result",
    "schema_version",
    "test_count",
}


def _framed(payload: bytes) -> bytes:
    return DOMAIN + b"\x00" + payload




def _run_regression(repo: Path) -> subprocess.CompletedProcess[str]:
    command = [
        str(Path(__import__("sys").executable)), "-m", "pytest",
        "-W", "error", "-q", "--ignore=tests/phase3",
    ]
    with tempfile.NamedTemporaryFile(mode="w+", encoding="utf-8", delete=False) as capture:
        capture_path = Path(capture.name)
        result = subprocess.run(
            command, cwd=str(repo), text=True, stdout=capture,
            stderr=subprocess.STDOUT, check=False,
        )
    try:
        output = capture_path.read_text("utf-8")
    finally:
        capture_path.unlink(missing_ok=True)
    return subprocess.CompletedProcess(command, result.returncode, output, None)

def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightError(f"{label} must be a non-empty string")
    return value


def verify_checkpoint(
    *,
    repo: Path,
    manifest_path: Path,
    signature_path: Path,
    public_key_path: Path,
    trust_path: Path,
    run_tests: bool = False,
) -> dict[str, Any]:
    manifest_path = ensure_within(repo, manifest_path)
    signature_path = ensure_within(repo, signature_path)
    public_key_path = ensure_within(repo, public_key_path)
    trust_path = ensure_within(repo, trust_path)

    manifest = strict_json_load(manifest_path, require_canonical=True)
    if not isinstance(manifest, dict):
        raise PreflightError("checkpoint manifest must be an object")
    require_exact_keys(manifest, MANIFEST_KEYS, label="checkpoint manifest")
    checkpoint = manifest["checkpoint"]
    if not isinstance(checkpoint, dict):
        raise PreflightError("checkpoint must be an object")
    require_exact_keys(checkpoint, CHECKPOINT_KEYS, label="checkpoint")

    acceptance = checkpoint["acceptance"]
    if not isinstance(acceptance, dict):
        raise PreflightError("acceptance must be an object")
    require_exact_keys(acceptance, ACCEPTANCE_KEYS, label="acceptance")
    for key in ACCEPTANCE_KEYS:
        _require_string(acceptance[key], f"acceptance.{key}")

    evidence_ref = checkpoint["test_evidence"]
    if not isinstance(evidence_ref, dict):
        raise PreflightError("test_evidence must be an object")
    require_exact_keys(evidence_ref, EVIDENCE_REF_KEYS, label="test_evidence")

    schema_version = _require_string(checkpoint["schema_version"], "schema_version")
    if schema_version != SCHEMA_VERSION:
        raise PreflightError(f"unsupported checkpoint schema: {schema_version}")
    if checkpoint["checkpoint_scope"] != "phase2-storage":
        raise PreflightError("checkpoint_scope must be phase2-storage")
    if checkpoint["signing_domain"] != DOMAIN.decode("ascii"):
        raise PreflightError("unexpected signing domain")

    baseline_commit = _require_string(checkpoint["baseline_commit"], "baseline_commit")
    tree_sha = _require_string(checkpoint["baseline_tree_sha"], "baseline_tree_sha")
    tree_listing_sha = _require_string(
        checkpoint["baseline_tree_listing_sha256"], "baseline_tree_listing_sha256"
    )
    public_key_sha = _require_string(checkpoint["public_key_sha256"], "public_key_sha256")
    checkpoint_id = _require_string(manifest["checkpoint_id"], "checkpoint_id")
    evidence_sha = _require_string(evidence_ref["sha256"], "test_evidence.sha256")
    if not HEX40.fullmatch(baseline_commit) or not HEX40.fullmatch(tree_sha):
        raise PreflightError("commit and tree ids must be lowercase 40-character Git object ids")
    for label, value in {
        "checkpoint_id": checkpoint_id,
        "tree listing sha": tree_listing_sha,
        "public key sha": public_key_sha,
        "evidence sha": evidence_sha,
    }.items():
        if not HEX64.fullmatch(value):
            raise PreflightError(f"{label} must be lowercase sha256")

    expected_checkpoint_id = sha256_bytes(canonical_bytes(checkpoint))
    if checkpoint_id != expected_checkpoint_id:
        raise PreflightError("checkpoint_id does not match canonical checkpoint payload")

    trust = strict_json_load(trust_path, require_canonical=True)
    if not isinstance(trust, dict):
        raise PreflightError("trust file must be an object")
    require_exact_keys(trust, TRUST_KEYS, label="checkpoint trust")
    if trust["schema_version"] != "phase2-checkpoint-trust-v1":
        raise PreflightError("unsupported trust schema")
    for field in ("baseline_commit", "checkpoint_id", "public_key_sha256", "repository"):
        expected = checkpoint[field] if field in checkpoint else manifest[field]
        if trust[field] != expected:
            raise PreflightError(f"trust mismatch: {field}")

    try:
        public_key_obj = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (ValueError, TypeError) as exc:
        raise PreflightError("invalid checkpoint public key") from exc
    if not isinstance(public_key_obj, Ed25519PublicKey):
        raise PreflightError("checkpoint public key must be Ed25519")
    raw_public = public_key_obj.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if sha256_bytes(raw_public) != public_key_sha:
        raise PreflightError("public key fingerprint mismatch")

    try:
        signature = base64.b64decode(signature_path.read_text("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PreflightError("signature is not strict base64") from exc
    try:
        public_key_obj.verify(signature, _framed(manifest_path.read_bytes()))
    except InvalidSignature as exc:
        raise PreflightError("checkpoint signature verification failed") from exc

    if not git_object_exists(repo, f"{baseline_commit}^{{commit}}"):
        raise PreflightError("baseline commit is not available locally")
    actual_tree = git(repo, ["show", "-s", "--format=%T", baseline_commit]).stdout.strip()
    if actual_tree != tree_sha:
        raise PreflightError("baseline tree sha mismatch")
    listing = git_tree_listing(repo, baseline_commit)
    if sha256_bytes(listing) != tree_listing_sha:
        raise PreflightError("baseline tree listing digest mismatch")
    actual_file_count = str(sum(1 for item in listing.split(b"\x00") if item))
    if actual_file_count != checkpoint["tracked_file_count"]:
        raise PreflightError("tracked file count mismatch")
    if git(repo, ["merge-base", "--is-ancestor", baseline_commit, "HEAD"], check=False).returncode != 0:
        raise PreflightError("baseline commit is not an ancestor of HEAD")

    evidence_path = ensure_within(repo, evidence_ref["path"])
    if sha256_file(evidence_path) != evidence_sha:
        raise PreflightError("test evidence digest mismatch")
    evidence = strict_json_load(evidence_path, require_canonical=True)
    if not isinstance(evidence, dict):
        raise PreflightError("test evidence must be an object")
    require_exact_keys(evidence, EVIDENCE_KEYS, label="test evidence")
    if evidence["schema_version"] != "phase2-storage-test-evidence-v1":
        raise PreflightError("unsupported evidence schema")
    if evidence["baseline_commit"] != baseline_commit:
        raise PreflightError("evidence baseline mismatch")
    if evidence["result"] != "pass":
        raise PreflightError("evidence result is not pass")
    minimum = int(acceptance["minimum_regression_tests"])
    evidence_count = int(evidence["test_count"])
    if evidence_count < minimum:
        raise PreflightError("baseline regression test count below required minimum")

    runtime_test_count: int | None = None
    if run_tests:
        result = _run_regression(repo)
        if result.returncode != 0:
            raise PreflightError(f"runtime regression failed:\n{result.stdout}")
        matches = re.findall(r"(\d+) passed", result.stdout)
        if not matches:
            raise PreflightError("could not parse pytest pass count")
        runtime_test_count = int(matches[-1])
        if runtime_test_count < minimum:
            raise PreflightError("runtime regression count below checkpoint minimum")

    return {
        "baseline_commit": baseline_commit,
        "checkpoint_id": checkpoint_id,
        "evidence_test_count": evidence_count,
        "repository": checkpoint["repository"],
        "runtime_test_count": runtime_test_count,
        "status": "pass",
        "tree_sha": tree_sha,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument(
        "--manifest", default="artifacts/checkpoints/g2/phase2-storage-checkpoint.json"
    )
    parser.add_argument(
        "--signature", default="artifacts/checkpoints/g2/phase2-storage-checkpoint.sig"
    )
    parser.add_argument(
        "--public-key", default="artifacts/checkpoints/g2/phase2-storage-public-key.pem"
    )
    parser.add_argument("--trust", default=".github/phase2-checkpoint-trust.json")
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        result = verify_checkpoint(
            repo=repo,
            manifest_path=Path(args.manifest),
            signature_path=Path(args.signature),
            public_key_path=Path(args.public_key),
            trust_path=Path(args.trust),
            run_tests=args.run_tests,
        )
    except PreflightError as exc:
        if args.json:
            print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(
            "PASS: Phase 2 checkpoint "
            f"{result['checkpoint_id']} at {result['baseline_commit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
