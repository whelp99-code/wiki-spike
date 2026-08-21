#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=42"]
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      uv run scripts/second_brain_me_wiki_evidence.py --root /Volumes/DevSpace/me-wiki --out-dir artifacts/product-release/second-brain-v1/evidence
# 3. Or make executable and run:
#      chmod +x scripts/second_brain_me_wiki_evidence.py && ./scripts/second_brain_me_wiki_evidence.py --root /Volumes/DevSpace/me-wiki --out-dir artifacts/product-release/second-brain-v1/evidence
# ──────────────────
"""Metadata-only producer for me-wiki DB-03 body-free evidence artifacts.

Reads only git plumbing metadata (``git --no-optional-locks``) plus the source
root's lstat; it never opens a tracked source body. It writes the canonical
profile, fixture, and evidence JSON artifacts and refuses to overwrite them.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from wiki_spike.memory_core.me_wiki_source_evidence_profile import (
        MeWikiGitTreeV1,
        MeWikiTrackedTreeRow,
    )

type JsonValue = None | bool | str | list[JsonValue] | dict[str, JsonValue]

_ = sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

_GIT = "git"
SOURCE_NAME = "me-wiki"


class MeWikiEvidenceCliError(ValueError):
    """The CLI refused to produce me-wiki evidence safely."""


class _Arguments(argparse.Namespace):
    """Mutable parse target owned exclusively by argparse."""

    root: Path = Path()
    out_dir: Path = Path()


def _run_git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        [_GIT, "--no-optional-locks", "-C", str(root), *args],
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise MeWikiEvidenceCliError(
            f"git metadata refused: {' '.join(args)}: {completed.stderr.strip()}"
        )
    return completed.stdout


def _read_tracked_tree(root: Path) -> tuple[MeWikiGitTreeV1, str]:
    from wiki_spike.memory_core.me_wiki_source_evidence_profile import (
        MeWikiGitTreeV1,
        MeWikiTrackedTreeRow,
    )

    head = _run_git(root, "rev-parse", "HEAD").strip()
    status = _run_git(root, "status", "--porcelain=v1")
    if status != "":
        raise MeWikiEvidenceCliError("source worktree is not clean")
    listing = _run_git(root, "ls-files", "-s")
    rows: list[MeWikiTrackedTreeRow] = []
    for line in listing.splitlines():
        parts = line.split()
        if len(parts) < 4:
            raise MeWikiEvidenceCliError("git ls-files output is malformed")
        rows.append(
            MeWikiTrackedTreeRow(parts[0], parts[1], parts[2], " ".join(parts[3:]))
        )
    rows.sort(key=lambda row: row.relative_path)
    return MeWikiGitTreeV1(head, tuple(rows)), head


def _atomic_write_new(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise MeWikiEvidenceCliError("output parent must be an existing directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise MeWikiEvidenceCliError("output already exists; overwrite refused") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _emit(path: Path, value: dict[str, JsonValue]) -> None:
    from wiki_spike.memory_core.contracts import canonical_bytes

    _atomic_write_new(path, canonical_bytes(value) + b"\n")


def _verify_source_tree_unchanged(root: Path, before: os.stat_result) -> None:
    try:
        after = os.lstat(root)
    except OSError as exc:
        raise MeWikiEvidenceCliError("source root vanished during production") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise MeWikiEvidenceCliError("source tree metadata changed during production")


def _arguments() -> _Arguments:
    parser = argparse.ArgumentParser(
        description="Produce body-free me-wiki DB-03 evidence from git metadata only."
    )
    _ = parser.add_argument("--root", required=True, type=Path)
    _ = parser.add_argument("--out-dir", required=True, type=Path)
    arguments = _Arguments()
    _ = parser.parse_args(namespace=arguments)
    return arguments


def _sanitized(message: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in message)


def main() -> int:
    from wiki_spike.memory_core.errors import CoreContractError
    from wiki_spike.memory_core.me_wiki_source_evidence import (
        MeWikiSourceEvidenceV1,
    )
    from wiki_spike.memory_core.me_wiki_source_evidence_fixture import (
        build_synthetic_fixture,
    )
    from wiki_spike.memory_core.me_wiki_source_evidence_profile import (
        MeWikiSourceProfileV1,
    )

    arguments = _arguments()
    root = arguments.root
    try:
        before = os.lstat(root)
    except OSError as exc:
        raise MeWikiEvidenceCliError("source root does not exist or is inaccessible") from exc
    try:
        git_tree, head = _read_tracked_tree(root)
        fixture = build_synthetic_fixture(head)
        profile = MeWikiSourceProfileV1.create(
            str(root), git_tree, fixture.fixture_digest
        )
        evidence = MeWikiSourceEvidenceV1.create(profile)
        _verify_source_tree_unchanged(root, before)
        out_dir = arguments.out_dir
        _emit(out_dir / "me-wiki-source-profile-v1.json", profile.to_mapping())
        _emit(out_dir / "me-wiki-mapping-fixture-v1.json", fixture.to_mapping())
        _emit(out_dir / "me-wiki-source-evidence-v1.json", evidence.to_mapping())
    except (CoreContractError, MeWikiEvidenceCliError, OSError) as exc:
        print(f"me-wiki evidence refused: {_sanitized(str(exc))}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
