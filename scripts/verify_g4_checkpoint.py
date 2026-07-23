#!/usr/bin/env python3
"""Verify the signed Phase 4 G4 checkpoint and delta source inventory."""
from __future__ import annotations

import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))
from wiki_spike.memory_core.contracts import canonical_bytes

DOMAIN = b"wiki.phase4.checkpoint.v1\x00"
MANIFEST = Path("artifacts/checkpoints/g4/phase4-g4-checkpoint.json")
SIGNATURE = Path("artifacts/checkpoints/g4/phase4-g4-checkpoint.sig")
PUBLIC_KEY = Path("artifacts/checkpoints/g4/phase4-g4-public-key.pem")
TRUST = Path(".github/phase4-g4-checkpoint-trust.json")


class G4VerificationError(RuntimeError):
    pass


def _load_canonical(path: Path) -> dict:
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except Exception as exc:
        raise G4VerificationError(f"invalid JSON: {path}") from exc
    if canonical_bytes(value) != raw:
        raise G4VerificationError(f"non-canonical JSON: {path}")
    if not isinstance(value, dict):
        raise G4VerificationError(f"object required: {path}")
    return value


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def verify(repo: Path, *, require_git: bool = False) -> dict[str, object]:
    manifest_path = repo / MANIFEST
    manifest = _load_canonical(manifest_path)
    if set(manifest) != {"checkpoint", "checkpoint_id"}:
        raise G4VerificationError("checkpoint top-level fields mismatch")
    checkpoint = manifest["checkpoint"]
    if not isinstance(checkpoint, dict):
        raise G4VerificationError("checkpoint must be an object")
    expected_id = sha256(canonical_bytes(checkpoint)).hexdigest()
    if manifest["checkpoint_id"] != expected_id:
        raise G4VerificationError("checkpoint_id mismatch")
    if checkpoint.get("schema_version") != "phase4-g4-checkpoint-v1":
        raise G4VerificationError("unsupported checkpoint schema")
    if checkpoint.get("signing_domain") != "wiki.phase4.checkpoint.v1":
        raise G4VerificationError("signing domain mismatch")

    trust = _load_canonical(repo / TRUST)
    for field in ("checkpoint_id", "contract_release", "public_key_sha256", "source_root"):
        expected = manifest["checkpoint_id"] if field == "checkpoint_id" else checkpoint[field]
        if trust.get(field) != expected:
            raise G4VerificationError(f"trust mismatch: {field}")

    pub_obj = serialization.load_pem_public_key((repo / PUBLIC_KEY).read_bytes())
    if not isinstance(pub_obj, Ed25519PublicKey):
        raise G4VerificationError("G4 key must be Ed25519")
    raw_pub = pub_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if sha256(raw_pub).hexdigest() != checkpoint["public_key_sha256"]:
        raise G4VerificationError("public key fingerprint mismatch")
    try:
        signature = base64.b64decode((repo / SIGNATURE).read_text("ascii"), validate=True)
        pub_obj.verify(signature, DOMAIN + manifest_path.read_bytes())
    except (ValueError, InvalidSignature) as exc:
        raise G4VerificationError("checkpoint signature invalid") from exc

    inventory_ref = checkpoint["source_inventory_ref"]
    inventory_path = repo / inventory_ref["path"]
    if _sha(inventory_path) != inventory_ref["sha256"]:
        raise G4VerificationError("inventory digest mismatch")
    inventory = _load_canonical(inventory_path)
    entries = inventory.get("entries")
    if not isinstance(entries, list) or not entries:
        raise G4VerificationError("inventory entries missing")
    roots = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "byte_length"}:
            raise G4VerificationError("inventory entry fields mismatch")
        path_text = entry["path"]
        if not isinstance(path_text, str) or path_text.startswith("/") or ".." in Path(path_text).parts:
            raise G4VerificationError("unsafe inventory path")
        if path_text in seen:
            raise G4VerificationError("duplicate inventory path")
        seen.add(path_text)
        path = repo / path_text
        if not path.is_file() or path.is_symlink():
            raise G4VerificationError(f"inventory file unavailable: {path_text}")
        if _sha(path) != entry["sha256"] or str(path.stat().st_size) != entry["byte_length"]:
            raise G4VerificationError(f"inventory file mismatch: {path_text}")
        roots.append(entry)
    root = sha256(canonical_bytes({"entries": roots})).hexdigest()
    if root != checkpoint["source_root"] or root != inventory.get("source_root"):
        raise G4VerificationError("source_root mismatch")

    api = repo / "src/wiki_spike/memory_runtime/phase4_api.py"
    if _sha(api) != checkpoint["public_api_sha256"]:
        raise G4VerificationError("public API digest mismatch")
    required = [f"P4-{number:02d}" for number in range(3, 15)]
    if checkpoint.get("required_work_units") != required:
        raise G4VerificationError("required work unit list mismatch")

    if require_git:
        parent = checkpoint["parent_main_commit"]
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", parent, "HEAD"], cwd=repo,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if result.returncode != 0:
            raise G4VerificationError("parent main commit is not an ancestor")

    return {
        "status": "pass",
        "checkpoint_id": manifest["checkpoint_id"],
        "contract_release": checkpoint["contract_release"],
        "source_root": root,
        "verified_files": len(entries),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    parser.add_argument("--require-git", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = verify(args.repo_root.resolve(), require_git=args.require_git)
    except (G4VerificationError, OSError, KeyError, TypeError, ValueError) as exc:
        if args.json:
            print(json.dumps({"status": "fail", "error": str(exc)}, sort_keys=True))
        else:
            print(f"FAIL: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else f"PASS: G4 {result['checkpoint_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
