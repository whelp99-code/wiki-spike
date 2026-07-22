#!/usr/bin/env python3
"""Verify the immutable Phase 3 G3 release consumed by Phase 4.

The current checkout may evolve after G3.  P4 therefore verifies the signed G3
checkpoint and contract files in an immutable annotated tag worktree, while also
requiring the frozen public contract files in the current checkout to remain
byte-for-byte unchanged.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tempfile
from typing import Any, Iterator, Mapping, Sequence

try:
    from .preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        git,
        require_exact_keys,
        sha256_file,
        strict_json_load,
    )
except ImportError:
    from preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        git,
        require_exact_keys,
        sha256_file,
        strict_json_load,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

PIN_SCHEMA_VERSION = "phase4-phase3-contract-pin-v1"
EXPECTED_REPOSITORY = "whelp99-code/wiki-spike"
EXPECTED_RELEASE = "phase3-core-v1.0.0"
EXPECTED_TAG = "phase3-core-v1.0.0"
EXPECTED_TAG_OBJECT = "691a12eb3556771acc0678acd1844b495da68bd7"
EXPECTED_COMMIT = "fa7523344008c8c5bfbcc6aca790f297524f33dc"
EXPECTED_G3_CHECKPOINT = "379297f172ebf60a30dd4bce8b8e1dc139ff249ea72b2561879af5807afed832"
EXPECTED_G3_SOURCE_ROOT = "222887e2d7551661efa151ab02a9fc6cdae573fd19850a510667f2e34a7517ef"
EXPECTED_PUBLIC_API = "58e963e949d813f2f0f112d876cf098097e9bfad40b918ab4d6bafdb3d277011"
EXPECTED_STATUS_CHECKS = (
    "phase3-g3-conformance / G3 conformance checkpoint",
    "phase3-preflight / P3-00 preflight",
)
EXPECTED_ALLOWED_MODULES = (
    "wiki_spike.memory_core.contracts",
    "wiki_spike.memory_core.ports",
)
EXPECTED_CONTRACT_FILES: dict[str, tuple[str, str]] = {
    "artifacts/checkpoints/g3/phase3-g3-checkpoint.json": (
        "4fc911645d1a49196eabaeffb8920b03ed08e614c96a1158cd0483fd0f8c9d75", "2060"
    ),
    "artifacts/conformance/phase3/G3/report.md": (
        "a1159c9c71ca05974c2c77b2a7af010716eaf8bcf024a090cb3f4cedb5ee7529", "1298"
    ),
    "artifacts/conformance/phase3/G3/requirements.json": (
        "efc6a9d5409af49c599200873fd63b17a1c004003176ebf62ed6df83bebfe266", "7170"
    ),
    "docs/releases/phase3-core-v1.0.0.md": (
        "bd2e5222ffb7af9ebcef14c146c8728c040eb4eb3b092c15a46f02da844215c7", "799"
    ),
    "schemas/phase3/core-contracts.schema.json": (
        "3a701ba37b99728e8298303d48c2c77500a50e5173aa727fae0dd99bf38b6ef2", "3722"
    ),
    "src/wiki_spike/memory_core/__init__.py": (
        "58e963e949d813f2f0f112d876cf098097e9bfad40b918ab4d6bafdb3d277011", "8028"
    ),
    "src/wiki_spike/memory_core/contracts.py": (
        "683c665b9fbbf909a8c1d664a9a30266b60e52385c881fe6098216e4364b2e69", "11871"
    ),
    "src/wiki_spike/memory_core/ports.py": (
        "3e4570000457f015f8f0fcfd4f1e99527596d6f1b677abb968d137d41d081f65", "752"
    ),
}

TOP_KEYS = {"pin", "pin_id"}
PIN_KEYS = {
    "schema_version", "repository", "contract_release", "release_tag",
    "release_tag_object", "release_commit", "tag_object_type", "g3_checkpoint_id",
    "g3_source_root", "public_api_sha256", "required_status_checks",
    "allowed_runtime_core_modules", "contract_files",
}
FILE_KEYS = {"path", "sha256", "byte_length"}


def _sorted_strings(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PreflightError(f"{label} must be an array of non-empty strings")
    result = tuple(value)
    if tuple(sorted(set(result))) != result:
        raise PreflightError(f"{label} must be sorted and unique")
    return result


def _safe_relative(path: object) -> str:
    if not isinstance(path, str) or not path or "\\" in path:
        raise PreflightError("contract file path must be a canonical POSIX relative path")
    pure = PurePosixPath(path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PreflightError(f"unsafe contract file path: {path!r}")
    return path


def _load_pin(path: Path) -> tuple[dict[str, Any], str]:
    value = strict_json_load(path, require_canonical=True)
    if not isinstance(value, dict):
        raise PreflightError("Phase 3 contract pin must be an object")
    require_exact_keys(value, TOP_KEYS, label="Phase 3 contract pin")
    pin = value["pin"]
    if not isinstance(pin, dict):
        raise PreflightError("pin must be an object")
    require_exact_keys(pin, PIN_KEYS, label="Phase 3 contract pin body")
    pin_id = value["pin_id"]
    if not isinstance(pin_id, str) or len(pin_id) != 64:
        raise PreflightError("invalid Phase 3 contract pin id")
    if sha256(canonical_bytes(pin)).hexdigest() != pin_id:
        raise PreflightError("Phase 3 contract pin id mismatch")
    return dict(pin), pin_id


def _validate_expected_pin(pin: Mapping[str, Any]) -> tuple[dict[str, tuple[str, str]], tuple[str, ...]]:
    expected_scalars = {
        "schema_version": PIN_SCHEMA_VERSION,
        "repository": EXPECTED_REPOSITORY,
        "contract_release": EXPECTED_RELEASE,
        "release_tag": EXPECTED_TAG,
        "release_tag_object": EXPECTED_TAG_OBJECT,
        "release_commit": EXPECTED_COMMIT,
        "tag_object_type": "tag",
        "g3_checkpoint_id": EXPECTED_G3_CHECKPOINT,
        "g3_source_root": EXPECTED_G3_SOURCE_ROOT,
        "public_api_sha256": EXPECTED_PUBLIC_API,
    }
    for key, expected in expected_scalars.items():
        if pin.get(key) != expected:
            raise PreflightError(f"Phase 3 contract pin mismatch: {key}")

    checks = _sorted_strings(pin["required_status_checks"], "required_status_checks")
    if checks != EXPECTED_STATUS_CHECKS:
        raise PreflightError("required Phase 3 status checks mismatch")
    modules = _sorted_strings(pin["allowed_runtime_core_modules"], "allowed_runtime_core_modules")
    if modules != EXPECTED_ALLOWED_MODULES:
        raise PreflightError("allowed Runtime Core modules mismatch")

    raw_files = pin["contract_files"]
    if not isinstance(raw_files, list):
        raise PreflightError("contract_files must be an array")
    files: dict[str, tuple[str, str]] = {}
    previous = ""
    for raw in raw_files:
        if not isinstance(raw, dict):
            raise PreflightError("contract file entry must be an object")
        require_exact_keys(raw, FILE_KEYS, label="contract file entry")
        path = _safe_relative(raw["path"])
        digest = raw["sha256"]
        length = raw["byte_length"]
        if path <= previous:
            raise PreflightError("contract file paths must be strictly sorted")
        previous = path
        if not isinstance(digest, str) or len(digest) != 64:
            raise PreflightError(f"invalid contract digest: {path}")
        if not isinstance(length, str) or not length.isdigit() or (length.startswith("0") and length != "0"):
            raise PreflightError(f"invalid contract byte length: {path}")
        files[path] = (digest, length)
    if files != EXPECTED_CONTRACT_FILES:
        raise PreflightError("pinned Phase 3 contract file catalog mismatch")
    return files, modules


def verify_release_tag(repo: Path, *, tag: str, expected_tag_object: str, expected_commit: str) -> None:
    tag_ref = f"refs/tags/{tag}"
    object_type = git(repo, ["cat-file", "-t", tag_ref], check=False)
    if object_type.returncode != 0 or object_type.stdout.strip() != "tag":
        raise PreflightError(f"{tag} must be an annotated tag")
    tag_object = git(repo, ["rev-parse", tag_ref]).stdout.strip()
    if tag_object != expected_tag_object:
        raise PreflightError("Phase 3 release tag object mismatch")
    commit = git(repo, ["rev-list", "-n", "1", tag_ref]).stdout.strip()
    if commit != expected_commit:
        raise PreflightError("Phase 3 release tag commit mismatch")


def _verify_contract_files(root: Path, files: Mapping[str, tuple[str, str]], *, label: str) -> None:
    for relative, (expected_digest, expected_length) in files.items():
        path = ensure_within(root, relative)
        if not path.is_file() or path.is_symlink():
            raise PreflightError(f"{label} contract file missing or unsafe: {relative}")
        actual_length = str(path.stat().st_size)
        if actual_length != expected_length:
            raise PreflightError(f"{label} contract byte length mismatch: {relative}")
        if sha256_file(path) != expected_digest:
            raise PreflightError(f"{label} contract digest mismatch: {relative}")


@contextmanager
def release_worktree(repo: Path, commit: str) -> Iterator[Path]:
    parent = Path(tempfile.mkdtemp(prefix="wiki-p3-release-"))
    target = parent / "release"
    added = False
    try:
        result = subprocess.run(
            ["git", "worktree", "add", "--detach", str(target), commit],
            cwd=repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise PreflightError(f"cannot create Phase 3 release worktree: {result.stderr.strip()}")
        added = True
        yield target
    finally:
        if added:
            subprocess.run(
                ["git", "worktree", "remove", "--force", str(target)],
                cwd=repo,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            subprocess.run(
                ["git", "worktree", "prune"], cwd=repo,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
        shutil.rmtree(parent, ignore_errors=True)


def _run_release(command: Sequence[str], release: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONHOME", None)
    env["PYTHONPATH"] = str(release / "src")
    env["PYTHONHASHSEED"] = "0"
    result = subprocess.run(
        list(command), cwd=release, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        raise PreflightError(
            f"Phase 3 release command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout[-4000:]}"
        )
    return result


def verify_contract_pin(
    *,
    repo: Path,
    pin_path: Path | None = None,
    run_release_commands: bool = True,
) -> dict[str, Any]:
    repo = repo.resolve()
    pin_path = ensure_within(repo, pin_path or Path(".github/phase4-g3-contract-pin.json"))
    pin, pin_id = _load_pin(pin_path)
    files, modules = _validate_expected_pin(pin)

    verify_release_tag(
        repo, tag=EXPECTED_TAG, expected_tag_object=EXPECTED_TAG_OBJECT,
        expected_commit=EXPECTED_COMMIT,
    )
    # Frozen public files are immutable in both the current checkout and release.
    _verify_contract_files(repo, files, label="current checkout")

    with release_worktree(repo, EXPECTED_COMMIT) as release:
        _verify_contract_files(release, files, label="release tag")
        checkpoint_result: dict[str, Any] | None = None
        if run_release_commands:
            checkpoint = _run_release(
                [
                    str(Path(__import__("sys").executable)),
                    "scripts/verify_g3_checkpoint.py", "--no-test-counts", "--json",
                ],
                release,
            )
            try:
                checkpoint_result = json.loads(checkpoint.stdout)
            except json.JSONDecodeError as exc:
                raise PreflightError("G3 verifier did not emit JSON") from exc
            if checkpoint_result.get("status") != "pass":
                raise PreflightError("G3 checkpoint verifier did not pass")
            if checkpoint_result.get("checkpoint_id") != EXPECTED_G3_CHECKPOINT:
                raise PreflightError("G3 verifier checkpoint id mismatch")
            if checkpoint_result.get("source_root") != EXPECTED_G3_SOURCE_ROOT:
                raise PreflightError("G3 verifier source root mismatch")
            if checkpoint_result.get("contract_release") != EXPECTED_RELEASE:
                raise PreflightError("G3 verifier contract release mismatch")
            _run_release(
                [
                    str(Path(__import__("sys").executable)),
                    "scripts/p3_12_conformance.py", "--verify-only",
                ],
                release,
            )

    return {
        "status": "pass",
        "pin_id": pin_id,
        "contract_release": EXPECTED_RELEASE,
        "release_tag": EXPECTED_TAG,
        "release_tag_object": EXPECTED_TAG_OBJECT,
        "release_commit": EXPECTED_COMMIT,
        "g3_checkpoint_id": EXPECTED_G3_CHECKPOINT,
        "g3_source_root": EXPECTED_G3_SOURCE_ROOT,
        "contract_file_count": str(len(files)),
        "allowed_runtime_core_modules": list(modules),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--pin", type=Path, default=None)
    parser.add_argument("--no-release-commands", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        result = verify_contract_pin(
            repo=repo,
            pin_path=args.pin,
            run_release_commands=not args.no_release_commands,
        )
    except (PreflightError, OSError, ValueError, TypeError, KeyError) as exc:
        if args.json:
            print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"FAIL: {exc}")
        return 1
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(
            f"PASS: Phase 3 contract pin {result['pin_id']} "
            f"tag={result['release_tag']} commit={result['release_commit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
