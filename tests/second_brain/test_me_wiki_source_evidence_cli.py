"""Body-free CLI auxiliary surface for me-wiki DB-03 evidence production.

Drives the metadata-only producer against the real /Volumes/DevSpace/me-wiki
working tree and asserts machine-safe outcomes: body_reads == 0, clean git
metadata, canonical artifacts, unchanged source tree, and no temp residue.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.me_wiki_source_evidence import (
    MeWikiSourceEvidenceV1,
)
from wiki_spike.memory_core.me_wiki_source_evidence_fixture import (
    MeWikiMappingFixtureV1,
)
from wiki_spike.memory_core.me_wiki_source_evidence_profile import (
    MeWikiSourceProfileV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "second_brain_me_wiki_evidence.py"
SOURCE = Path("/Volumes/DevSpace/me-wiki")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _read(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def _git_status(source: Path) -> str:
    completed = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(source), "status", "--porcelain=v1"],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.stdout


def test_cli_produces_body_free_artifacts_and_leaves_no_residue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os

    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "0")
    out_dir = tmp_path / "evidence"
    out_dir.mkdir()
    before_root = os.lstat(SOURCE)
    assert _git_status(SOURCE) == ""

    result = _run("--root", str(SOURCE), "--out-dir", str(out_dir))

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    profile_path = out_dir / "me-wiki-source-profile-v1.json"
    fixture_path = out_dir / "me-wiki-mapping-fixture-v1.json"
    evidence_path = out_dir / "me-wiki-source-evidence-v1.json"
    assert profile_path.is_file()
    assert fixture_path.is_file()
    assert evidence_path.is_file()

    profile = MeWikiSourceProfileV1.from_mapping(_read(profile_path))
    fixture = MeWikiMappingFixtureV1.from_mapping(_read(fixture_path))
    evidence = MeWikiSourceEvidenceV1.from_mapping(_read(evidence_path))

    assert profile.source_name == "me-wiki"
    assert profile.source_root == str(SOURCE)
    assert profile.body_reads == "0"
    assert profile.source_mutation is False
    assert profile.import_requested is False
    assert profile.serve_requested is False
    assert profile.promote_requested is False
    assert profile.git_head == "7c8b927a6168bc7757b13d064efdbe41c03a0e1c"
    assert profile.tracked_count == "17"
    assert profile.fixture_digest == fixture.fixture_digest
    assert evidence.state == "CONTRACT_AND_SYNTHETIC_FIXTURE_ONLY"
    assert evidence.authorized_go is False
    assert evidence.body_reads == "0"
    assert evidence.profile_digest == profile.profile_digest
    assert evidence.fixture_digest == fixture.fixture_digest

    after_root = os.lstat(SOURCE)
    assert (before_root.st_dev, before_root.st_ino, before_root.st_mode,
            before_root.st_size, before_root.st_mtime_ns) == (
        after_root.st_dev, after_root.st_ino, after_root.st_mode,
        after_root.st_size, after_root.st_mtime_ns,
    )
    assert _git_status(SOURCE) == ""
    assert list(out_dir.glob(".*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []

    # The producer is idempotent-safe but must refuse to overwrite.
    refused = _run("--root", str(SOURCE), "--out-dir", str(out_dir))
    assert refused.returncode != 0
    assert "overwrite" in refused.stderr


def test_cli_refuses_when_source_tree_is_dirty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("GIT_OPTIONAL_LOCKS", "0")
    # A non-me-wiki synthetic dirty source proves the fail-closed dirty gate.
    dirty = tmp_path / "dirty-source"
    dirty.mkdir()
    _ = subprocess.run(
        ["git", "init", "-q", str(dirty)], check=True, capture_output=True, text=True
    )
    _ = subprocess.run(
        ["git", "-C", str(dirty), "config", "user.email", "evidence@example.invalid"],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = subprocess.run(
        ["git", "-C", str(dirty), "config", "user.name", "Evidence"],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = (dirty / "note.md").write_text("dirty body", encoding="utf-8")
    _ = subprocess.run(
        ["git", "-C", str(dirty), "add", "note.md"],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = subprocess.run(
        ["git", "-C", str(dirty), "commit", "-qm", "seed"],
        check=True,
        capture_output=True,
        text=True,
    )
    _ = (dirty / "note.md").write_text("mutated body", encoding="utf-8")

    result = _run("--root", str(dirty), "--out-dir", str(tmp_path / "out"))
    assert result.returncode != 0
    assert "not clean" in result.stderr
    assert not (tmp_path / "out").exists()


def test_cli_rejects_invalid_inputs_before_any_write(tmp_path: Path) -> None:
    out_dir = tmp_path / "evidence"
    out_dir.mkdir()
    missing = _run("--root", str(tmp_path / "no-such-root"), "--out-dir", str(out_dir))
    assert missing.returncode != 0
    assert not list(out_dir.iterdir())
    bad_out = _run("--root", str(SOURCE), "--out-dir", str(tmp_path / "no-out-dir"))
    assert bad_out.returncode != 0
