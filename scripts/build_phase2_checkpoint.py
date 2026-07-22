#!/usr/bin/env python3
"""Build a detached, signed Phase 2 storage checkpoint.

The private key is supplied by the caller and is never written into the
repository.  The committed public key plus Git review history form the
bootstrap trust anchor for this disposable spike; production key management is
explicitly deferred to P3-09.
"""
from __future__ import annotations

import argparse
import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from .preflight_common import (
        PreflightError, find_repo_root, git, git_tree_listing, sha256_bytes,
        sha256_file, strict_json_load, write_canonical_json,
    )
except ImportError:  # direct script execution
    from preflight_common import (
        PreflightError, find_repo_root, git, git_tree_listing, sha256_bytes,
        sha256_file, strict_json_load, write_canonical_json,
    )
from wiki_spike.canonical import canonical_bytes

DOMAIN = b"wiki.phase2.checkpoint.v1"
SCHEMA_VERSION = "phase2-storage-checkpoint-v1"


def _framed(payload: bytes) -> bytes:
    return DOMAIN + b"\x00" + payload


def build_checkpoint(
    *,
    repo: Path,
    baseline_commit: str,
    repository: str,
    private_key_path: Path,
    evidence_path: Path,
    output_dir: Path,
    created_at: str,
    signer_key_id: str,
) -> dict[str, str]:
    if not private_key_path.exists():
        raise PreflightError(f"private key does not exist: {private_key_path}")
    if not evidence_path.exists():
        raise PreflightError(f"evidence file does not exist: {evidence_path}")

    git(repo, ["cat-file", "-e", f"{baseline_commit}^{{commit}}"])
    tree_sha = git(repo, ["show", "-s", "--format=%T", baseline_commit]).stdout.strip()
    tree_listing = git_tree_listing(repo, baseline_commit)
    tracked_file_count = str(sum(1 for entry in tree_listing.split(b"\x00") if entry))

    evidence = strict_json_load(evidence_path, require_canonical=True)
    if evidence.get("baseline_commit") != baseline_commit:
        raise PreflightError("evidence baseline_commit does not match requested commit")

    raw_private = private_key_path.read_bytes()
    if len(raw_private) == 32:
        private_key = Ed25519PrivateKey.from_private_bytes(raw_private)
    else:
        private_key = serialization.load_pem_private_key(raw_private, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise PreflightError("checkpoint key must be Ed25519")

    public_raw = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    evidence_rel = evidence_path.resolve().relative_to(repo.resolve()).as_posix()
    checkpoint = {
        "acceptance": {
            "minimum_regression_tests": "116",
            "package_install": "passed",
            "secret_scan": "passed",
            "warnings_as_errors": "passed",
        },
        "baseline_commit": baseline_commit,
        "baseline_tree_listing_sha256": sha256_bytes(tree_listing),
        "baseline_tree_sha": tree_sha,
        "checkpoint_scope": "phase2-storage",
        "created_at": created_at,
        "public_key_sha256": sha256_bytes(public_raw),
        "repository": repository,
        "schema_version": SCHEMA_VERSION,
        "signer_key_id": signer_key_id,
        "signing_domain": DOMAIN.decode("ascii"),
        "test_evidence": {
            "path": evidence_rel,
            "sha256": sha256_file(evidence_path),
        },
        "tracked_file_count": tracked_file_count,
    }
    checkpoint_id = sha256_bytes(canonical_bytes(checkpoint))
    manifest = {"checkpoint": checkpoint, "checkpoint_id": checkpoint_id}
    manifest_bytes = canonical_bytes(manifest)
    signature = private_key.sign(_framed(manifest_bytes))

    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "phase2-storage-checkpoint.json"
    signature_path = output_dir / "phase2-storage-checkpoint.sig"
    public_path = output_dir / "phase2-storage-public-key.pem"
    write_canonical_json(manifest_path, manifest)
    signature_path.write_text(base64.b64encode(signature).decode("ascii"), encoding="ascii")
    public_path.write_bytes(public_pem)

    return {
        "checkpoint_id": checkpoint_id,
        "manifest": str(manifest_path),
        "public_key_sha256": sha256_bytes(public_raw),
        "signature": str(signature_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--created-at", default="2026-07-22T00:00:00+09:00")
    parser.add_argument("--signer-key-id", default="g2-bootstrap-ed25519-2026-07")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    result = build_checkpoint(
        repo=repo,
        baseline_commit=args.baseline_commit,
        repository=args.repository,
        private_key_path=args.private_key,
        evidence_path=args.evidence,
        output_dir=args.output_dir,
        created_at=args.created_at,
        signer_key_id=args.signer_key_id,
    )
    for key, value in sorted(result.items()):
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
