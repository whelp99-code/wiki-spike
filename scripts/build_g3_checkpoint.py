#!/usr/bin/env python3
"""Build the signed, non-self-referential Phase 3 G3 checkpoint.

The private Ed25519 key is caller-supplied and never written to the repository.
The checkpoint binds a deterministic source inventory that explicitly excludes the
checkpoint bytes/signature/trust themselves, avoiding a self-referential hash.
"""
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

try:
    from .p3_12_conformance import (
        CONTRACT_RELEASE,
        REQUIRED_GATE_IDS,
        load_and_validate_matrix,
        source_inventory,
        validate_required_adrs,
    )
    from .preflight_common import (
        PreflightError,
        find_repo_root,
        sha256_bytes,
        sha256_file,
        strict_json_load,
        write_canonical_json,
    )
except ImportError:
    from p3_12_conformance import (
        CONTRACT_RELEASE,
        REQUIRED_GATE_IDS,
        load_and_validate_matrix,
        source_inventory,
        validate_required_adrs,
    )
    from preflight_common import (
        PreflightError,
        find_repo_root,
        sha256_bytes,
        sha256_file,
        strict_json_load,
        write_canonical_json,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

CHECKPOINT_VERSION = "phase3-g3-checkpoint-v1"
TRUST_VERSION = "phase3-g3-trust-v1"
SIGNING_DOMAIN = b"wiki.phase3.checkpoint.v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = path.read_bytes()
    if len(raw) == 32:
        return Ed25519PrivateKey.from_private_bytes(raw)
    key = serialization.load_pem_private_key(raw, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise PreflightError("G3 checkpoint private key must be Ed25519")
    return key


def build_g3_checkpoint(
    *,
    repo: Path,
    private_key_path: Path,
    output_dir: Path,
    matrix_path: Path,
    repository: str,
    lineage_anchor_commit: str,
    created_at: str,
    signer_key_id: str,
    minimum_phase3_tests: str,
    minimum_total_tests: str,
) -> dict[str, str]:
    if not private_key_path.is_file():
        raise PreflightError("G3 checkpoint private key does not exist")
    if not HEX40.fullmatch(lineage_anchor_commit):
        raise PreflightError("lineage anchor must be a lowercase SHA-1 commit id")
    if not re.fullmatch(r"[1-9][0-9]*", minimum_phase3_tests):
        raise PreflightError("minimum_phase3_tests must be a positive integer string")
    if not re.fullmatch(r"[1-9][0-9]*", minimum_total_tests):
        raise PreflightError("minimum_total_tests must be a positive integer string")

    matrix = load_and_validate_matrix(repo, matrix_path)
    del matrix  # validation is the load-bearing effect
    adrs = validate_required_adrs(repo)

    inventory = source_inventory(repo)
    output_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = output_dir / "phase3-source-inventory.json"
    write_canonical_json(inventory_path, inventory)

    g2_manifest_path = repo / "artifacts/checkpoints/g2/phase2-storage-checkpoint.json"
    g2_manifest = strict_json_load(g2_manifest_path, require_canonical=True)
    g2_checkpoint_id = g2_manifest.get("checkpoint_id")
    if not isinstance(g2_checkpoint_id, str):
        raise PreflightError("G2 checkpoint id is missing")

    key = _load_private_key(private_key_path)
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key_sha256 = sha256_bytes(public_raw)

    checkpoint = {
        "schema_version": CHECKPOINT_VERSION,
        "checkpoint_scope": "phase3-core",
        "contract_release": CONTRACT_RELEASE,
        "repository": repository,
        "lineage_anchor_commit": lineage_anchor_commit,
        "created_at": created_at,
        "g2_checkpoint_id": g2_checkpoint_id,
        "source_root": inventory["source_root"],
        "source_inventory_ref": {
            "path": inventory_path.relative_to(repo).as_posix(),
            "sha256": sha256_file(inventory_path),
        },
        "requirements_matrix_ref": {
            "path": matrix_path.relative_to(repo).as_posix(),
            "sha256": sha256_file(matrix_path),
        },
        "public_api_sha256": sha256_file(repo / "src/wiki_spike/memory_core/__init__.py"),
        "required_gate_ids": sorted(REQUIRED_GATE_IDS),
        "required_adr_paths": list(adrs),
        "acceptance": {
            "minimum_phase3_tests": minimum_phase3_tests,
            "minimum_total_tests": minimum_total_tests,
            "warnings_as_errors": "required",
            "package_smoke": "required",
            "negative_fixture": "required",
            "clean_room_recovery": "required",
        },
        "signer_key_id": signer_key_id,
        "public_key_sha256": public_key_sha256,
        "signing_domain": SIGNING_DOMAIN.decode("ascii"),
    }
    checkpoint_id = sha256_bytes(canonical_bytes(checkpoint))
    manifest = {"checkpoint": checkpoint, "checkpoint_id": checkpoint_id}
    manifest_path = output_dir / "phase3-g3-checkpoint.json"
    signature_path = output_dir / "phase3-g3-checkpoint.sig"
    public_path = output_dir / "phase3-g3-public-key.pem"
    trust_path = repo / ".github/phase3-g3-checkpoint-trust.json"

    write_canonical_json(manifest_path, manifest)
    signature = key.sign(SIGNING_DOMAIN + b"\x00" + manifest_path.read_bytes())
    signature_path.write_text(base64.b64encode(signature).decode("ascii"), encoding="ascii")
    public_path.write_bytes(public_pem)
    write_canonical_json(
        trust_path,
        {
            "schema_version": TRUST_VERSION,
            "repository": repository,
            "contract_release": CONTRACT_RELEASE,
            "checkpoint_id": checkpoint_id,
            "source_root": inventory["source_root"],
            "public_key_sha256": public_key_sha256,
        },
    )
    return {
        "checkpoint_id": checkpoint_id,
        "source_root": inventory["source_root"],
        "manifest": manifest_path.as_posix(),
        "signature": signature_path.as_posix(),
        "public_key": public_path.as_posix(),
        "trust": trust_path.as_posix(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts/checkpoints/g3"))
    parser.add_argument("--matrix", type=Path, default=Path("artifacts/conformance/phase3/G3/requirements.json"))
    parser.add_argument("--repository", default="whelp99-code/wiki-spike")
    parser.add_argument("--lineage-anchor-commit", required=True)
    parser.add_argument("--created-at", default="2026-07-22T22:00:00+09:00")
    parser.add_argument("--signer-key-id", default="g3-bootstrap-ed25519-2026-07")
    parser.add_argument("--minimum-phase3-tests", required=True)
    parser.add_argument("--minimum-total-tests", required=True)
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    output_dir = args.output_dir if args.output_dir.is_absolute() else repo / args.output_dir
    matrix_path = args.matrix if args.matrix.is_absolute() else repo / args.matrix
    private_key = args.private_key if args.private_key.is_absolute() else Path.cwd() / args.private_key
    try:
        result = build_g3_checkpoint(
            repo=repo,
            private_key_path=private_key,
            output_dir=output_dir,
            matrix_path=matrix_path,
            repository=args.repository,
            lineage_anchor_commit=args.lineage_anchor_commit,
            created_at=args.created_at,
            signer_key_id=args.signer_key_id,
            minimum_phase3_tests=args.minimum_phase3_tests,
            minimum_total_tests=args.minimum_total_tests,
        )
    except (PreflightError, OSError, ValueError, TypeError) as exc:
        print(f"FAIL: {exc}")
        return 1
    for key, value in sorted(result.items()):
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
