#!/usr/bin/env python3
"""Verify the signed Phase 3 G3 checkpoint and all statically bound inputs."""
from __future__ import annotations

import argparse
import base64
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    from .build_g3_checkpoint import CHECKPOINT_VERSION, SIGNING_DOMAIN, TRUST_VERSION
    from .p3_12_conformance import (
        CONTRACT_RELEASE,
        REQUIRED_GATE_IDS,
        load_and_validate_matrix,
        validate_negative_fixture,
        validate_required_adrs,
        verify_inventory,
    )
    from .preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        git,
        git_object_exists,
        require_exact_keys,
        sha256_bytes,
        sha256_file,
        strict_json_load,
    )
except ImportError:
    from build_g3_checkpoint import CHECKPOINT_VERSION, SIGNING_DOMAIN, TRUST_VERSION
    from p3_12_conformance import (
        CONTRACT_RELEASE,
        REQUIRED_GATE_IDS,
        load_and_validate_matrix,
        validate_negative_fixture,
        validate_required_adrs,
        verify_inventory,
    )
    from preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        git,
        git_object_exists,
        require_exact_keys,
        sha256_bytes,
        sha256_file,
        strict_json_load,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MANIFEST_KEYS = {"checkpoint", "checkpoint_id"}
CHECKPOINT_KEYS = {
    "schema_version", "checkpoint_scope", "contract_release", "repository",
    "lineage_anchor_commit", "created_at", "g2_checkpoint_id", "source_root",
    "source_inventory_ref", "requirements_matrix_ref", "public_api_sha256",
    "required_gate_ids", "required_adr_paths", "acceptance", "signer_key_id",
    "public_key_sha256", "signing_domain",
}
REFERENCE_KEYS = {"path", "sha256"}
ACCEPTANCE_KEYS = {
    "minimum_phase3_tests", "minimum_total_tests", "warnings_as_errors",
    "package_smoke", "negative_fixture", "clean_room_recovery",
}
TRUST_KEYS = {
    "schema_version", "repository", "contract_release", "checkpoint_id",
    "source_root", "public_key_sha256",
}


def _positive_count(value: object, label: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise PreflightError(f"{label} must be a positive integer string")
    return int(value)


def _sorted_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PreflightError(f"{label} must be an array of non-empty strings")
    result = tuple(value)
    if tuple(sorted(set(result))) != result:
        raise PreflightError(f"{label} must be sorted and unique")
    return result


def _collect_test_count(repo: Path, target: str) -> int:
    result = subprocess.run(
        [str(Path(__import__("sys").executable)), "-m", "pytest", "--collect-only", "-q", target],
        cwd=repo,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise PreflightError(f"pytest collection failed for {target}:\n{result.stdout}")
    matches = re.findall(r"(\d+) tests? collected", result.stdout)
    if not matches:
        # pytest -q can print one node per line and no summary in some versions.
        nodes = [line for line in result.stdout.splitlines() if "::test" in line]
        if nodes:
            return len(nodes)
        raise PreflightError(f"could not parse collected test count for {target}")
    return int(matches[-1])


def verify_g3_checkpoint(
    *,
    repo: Path,
    manifest_path: Path | None = None,
    signature_path: Path | None = None,
    public_key_path: Path | None = None,
    trust_path: Path | None = None,
    negative_fixture_path: Path | None = None,
    verify_git_lineage: bool = True,
    verify_test_counts: bool = True,
) -> dict[str, Any]:
    manifest_path = ensure_within(repo, manifest_path or Path("artifacts/checkpoints/g3/phase3-g3-checkpoint.json"))
    signature_path = ensure_within(repo, signature_path or Path("artifacts/checkpoints/g3/phase3-g3-checkpoint.sig"))
    public_key_path = ensure_within(repo, public_key_path or Path("artifacts/checkpoints/g3/phase3-g3-public-key.pem"))
    trust_path = ensure_within(repo, trust_path or Path(".github/phase3-g3-checkpoint-trust.json"))
    fixture_path = ensure_within(repo, negative_fixture_path or Path("tests/phase3/fixtures/g3-negative-gate.json"))

    manifest = strict_json_load(manifest_path, require_canonical=True)
    if not isinstance(manifest, dict):
        raise PreflightError("G3 manifest must be an object")
    require_exact_keys(manifest, MANIFEST_KEYS, label="G3 manifest")
    checkpoint = manifest["checkpoint"]
    if not isinstance(checkpoint, dict):
        raise PreflightError("G3 checkpoint must be an object")
    require_exact_keys(checkpoint, CHECKPOINT_KEYS, label="G3 checkpoint")

    if checkpoint["schema_version"] != CHECKPOINT_VERSION:
        raise PreflightError("unsupported G3 checkpoint version")
    if checkpoint["checkpoint_scope"] != "phase3-core":
        raise PreflightError("G3 checkpoint scope mismatch")
    if checkpoint["contract_release"] != CONTRACT_RELEASE:
        raise PreflightError("G3 contract release mismatch")
    if checkpoint["signing_domain"] != SIGNING_DOMAIN.decode("ascii"):
        raise PreflightError("G3 signing domain mismatch")
    if checkpoint["repository"] != "whelp99-code/wiki-spike":
        raise PreflightError("G3 repository binding mismatch")

    checkpoint_id = manifest["checkpoint_id"]
    if not isinstance(checkpoint_id, str) or not HEX64.fullmatch(checkpoint_id):
        raise PreflightError("invalid G3 checkpoint id")
    if sha256_bytes(canonical_bytes(checkpoint)) != checkpoint_id:
        raise PreflightError("G3 checkpoint id mismatch")

    trust = strict_json_load(trust_path, require_canonical=True)
    if not isinstance(trust, dict):
        raise PreflightError("G3 trust record must be an object")
    require_exact_keys(trust, TRUST_KEYS, label="G3 trust record")
    if trust["schema_version"] != TRUST_VERSION:
        raise PreflightError("unsupported G3 trust version")
    for key in ("repository", "contract_release", "checkpoint_id", "source_root", "public_key_sha256"):
        expected = checkpoint[key] if key in checkpoint else checkpoint_id
        if key == "checkpoint_id":
            expected = checkpoint_id
        if trust[key] != expected:
            raise PreflightError(f"G3 trust mismatch: {key}")

    try:
        public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    except (ValueError, TypeError) as exc:
        raise PreflightError("invalid G3 public key") from exc
    if not isinstance(public_key, Ed25519PublicKey):
        raise PreflightError("G3 public key must be Ed25519")
    public_raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if sha256_bytes(public_raw) != checkpoint["public_key_sha256"]:
        raise PreflightError("G3 public key fingerprint mismatch")
    try:
        signature = base64.b64decode(signature_path.read_text("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise PreflightError("G3 signature is not strict base64") from exc
    try:
        public_key.verify(signature, SIGNING_DOMAIN + b"\x00" + manifest_path.read_bytes())
    except InvalidSignature as exc:
        raise PreflightError("G3 checkpoint signature verification failed") from exc

    g2 = strict_json_load(repo / "artifacts/checkpoints/g2/phase2-storage-checkpoint.json", require_canonical=True)
    if g2.get("checkpoint_id") != checkpoint["g2_checkpoint_id"]:
        raise PreflightError("G3 does not bind the committed G2 checkpoint")

    for label in ("source_inventory_ref", "requirements_matrix_ref"):
        ref = checkpoint[label]
        if not isinstance(ref, dict):
            raise PreflightError(f"{label} must be an object")
        require_exact_keys(ref, REFERENCE_KEYS, label=label)
        if not isinstance(ref["path"], str) or not isinstance(ref["sha256"], str) or not HEX64.fullmatch(ref["sha256"]):
            raise PreflightError(f"invalid {label}")
        path = ensure_within(repo, ref["path"])
        if sha256_file(path) != ref["sha256"]:
            raise PreflightError(f"{label} digest mismatch")

    matrix_path = ensure_within(repo, checkpoint["requirements_matrix_ref"]["path"])
    matrix = load_and_validate_matrix(repo, matrix_path)
    validate_negative_fixture(repo, matrix, fixture_path)
    inventory_path = ensure_within(repo, checkpoint["source_inventory_ref"]["path"])
    inventory = strict_json_load(inventory_path, require_canonical=True)
    if not isinstance(inventory, dict):
        raise PreflightError("G3 source inventory must be an object")
    verified_inventory = verify_inventory(repo, inventory)
    if verified_inventory["source_root"] != checkpoint["source_root"]:
        raise PreflightError("G3 source root mismatch")

    if sha256_file(repo / "src/wiki_spike/memory_core/__init__.py") != checkpoint["public_api_sha256"]:
        raise PreflightError("G3 public API digest mismatch")
    gate_ids = _sorted_strings(checkpoint["required_gate_ids"], "required_gate_ids")
    if gate_ids != tuple(sorted(REQUIRED_GATE_IDS)):
        raise PreflightError("G3 required gate catalog mismatch")
    adrs = _sorted_strings(checkpoint["required_adr_paths"], "required_adr_paths")
    if adrs != validate_required_adrs(repo):
        raise PreflightError("G3 ADR registry mismatch")

    acceptance = checkpoint["acceptance"]
    if not isinstance(acceptance, dict):
        raise PreflightError("G3 acceptance must be an object")
    require_exact_keys(acceptance, ACCEPTANCE_KEYS, label="G3 acceptance")
    for field in ("warnings_as_errors", "package_smoke", "negative_fixture", "clean_room_recovery"):
        if acceptance[field] != "required":
            raise PreflightError(f"G3 acceptance weakens required gate: {field}")
    minimum_phase3 = _positive_count(acceptance["minimum_phase3_tests"], "minimum_phase3_tests")
    minimum_total = _positive_count(acceptance["minimum_total_tests"], "minimum_total_tests")

    anchor = checkpoint["lineage_anchor_commit"]
    if not isinstance(anchor, str) or not HEX40.fullmatch(anchor):
        raise PreflightError("invalid G3 lineage anchor")
    if verify_git_lineage:
        if not git_object_exists(repo, f"{anchor}^{{commit}}"):
            raise PreflightError("G3 lineage anchor is not available locally")
        if git(repo, ["merge-base", "--is-ancestor", anchor, "HEAD"], check=False).returncode != 0:
            raise PreflightError("G3 lineage anchor is not an ancestor of HEAD")
    if verify_test_counts:
        phase3_count = _collect_test_count(repo, "tests/phase3")
        total_count = _collect_test_count(repo, ".")
        if phase3_count < minimum_phase3 or total_count < minimum_total:
            raise PreflightError(
                f"G3 test inventory below checkpoint minimum: phase3={phase3_count}, total={total_count}"
            )
    else:
        phase3_count = minimum_phase3
        total_count = minimum_total

    return {
        "status": "pass",
        "checkpoint_id": checkpoint_id,
        "contract_release": CONTRACT_RELEASE,
        "source_root": checkpoint["source_root"],
        "phase3_test_count": str(phase3_count),
        "total_test_count": str(total_count),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--no-git-lineage", action="store_true")
    parser.add_argument("--no-test-counts", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        result = verify_g3_checkpoint(
            repo=repo,
            verify_git_lineage=not args.no_git_lineage,
            verify_test_counts=not args.no_test_counts,
        )
    except (PreflightError, OSError, ValueError, TypeError, KeyError) as exc:
        if args.json:
            import json
            print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"FAIL: {exc}")
        return 1
    if args.json:
        import json
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"PASS: G3 {result['contract_release']} checkpoint {result['checkpoint_id']} "
            f"source_root={result['source_root']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
