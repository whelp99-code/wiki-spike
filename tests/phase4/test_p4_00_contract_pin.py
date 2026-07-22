from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import tempfile

import pytest

from scripts.preflight_common import PreflightError, strict_json_load, write_canonical_json
from scripts.verify_phase3_contract_pin import (
    EXPECTED_COMMIT,
    EXPECTED_CONTRACT_FILES,
    EXPECTED_TAG,
    EXPECTED_TAG_OBJECT,
    _verify_contract_files,
    release_worktree,
    verify_contract_pin,
    verify_release_tag,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_runtime import (
    PHASE3_CONTRACT_RELEASE,
    PHASE3_G3_CHECKPOINT_ID,
    ProjectionPort,
)


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def pin_value() -> dict:
    return strict_json_load(root() / ".github/phase4-g3-contract-pin.json", require_canonical=True)


def write_pin(path: Path, value: dict) -> None:
    write_canonical_json(path, value)


@contextmanager
def temporary_pin(value: dict):
    directory = root() / ".ci" / "p4-00-tests"
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, suffix=".json", delete=False) as handle:
        path = Path(handle.name)
    try:
        write_pin(path, value)
        yield path
    finally:
        path.unlink(missing_ok=True)


def recompute_pin_id(value: dict) -> None:
    value["pin_id"] = sha256(canonical_bytes(value["pin"])).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def make_tag_repo(tmp_path: Path, *, annotated: bool) -> tuple[Path, str, str]:
    repo = tmp_path / ("annotated" if annotated else "lightweight")
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
    (repo / "file.txt").write_text("content", encoding="utf-8")
    subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "base"], cwd=repo, check=True)
    commit = git(repo, "rev-parse", "HEAD")
    if annotated:
        subprocess.run(["git", "tag", "-a", "release", "-m", "release"], cwd=repo, check=True)
    else:
        subprocess.run(["git", "tag", "release"], cwd=repo, check=True)
    tag_object = git(repo, "rev-parse", "refs/tags/release")
    return repo, commit, tag_object


def test_committed_phase3_contract_pin_verifies_release_tag_and_g3():
    result = verify_contract_pin(repo=root())
    assert result["status"] == "pass"
    assert result["release_tag"] == EXPECTED_TAG
    assert result["release_tag_object"] == EXPECTED_TAG_OBJECT
    assert result["release_commit"] == EXPECTED_COMMIT
    assert result["contract_file_count"] == str(len(EXPECTED_CONTRACT_FILES))


def test_pin_id_tamper_is_rejected(tmp_path):
    value = pin_value()
    value["pin_id"] = "0" * 64
    with temporary_pin(value) as path:
        with pytest.raises(PreflightError, match="pin id mismatch"):
            verify_contract_pin(repo=root(), pin_path=path, run_release_commands=False)


def test_checkpoint_substitution_is_rejected_even_with_recomputed_pin_id(tmp_path):
    value = pin_value()
    value["pin"]["g3_checkpoint_id"] = "0" * 64
    recompute_pin_id(value)
    with temporary_pin(value) as path:
        with pytest.raises(PreflightError, match="g3_checkpoint_id"):
            verify_contract_pin(repo=root(), pin_path=path, run_release_commands=False)


def test_contract_catalog_substitution_is_rejected(tmp_path):
    value = pin_value()
    value["pin"]["contract_files"][0]["sha256"] = "0" * 64
    recompute_pin_id(value)
    with temporary_pin(value) as path:
        with pytest.raises(PreflightError, match="catalog mismatch"):
            verify_contract_pin(repo=root(), pin_path=path, run_release_commands=False)


def test_contract_file_digest_and_length_are_both_enforced(tmp_path):
    source = root() / "src/wiki_spike/memory_core/ports.py"
    target = tmp_path / "contract.py"
    target.write_bytes(source.read_bytes())
    digest = sha256(target.read_bytes()).hexdigest()
    _verify_contract_files(tmp_path, {"contract.py": (digest, str(target.stat().st_size))}, label="test")
    target.write_bytes(target.read_bytes() + b"\n")
    with pytest.raises(PreflightError, match="byte length mismatch"):
        _verify_contract_files(tmp_path, {"contract.py": (digest, str(source.stat().st_size))}, label="test")


def test_lightweight_release_tag_is_rejected(tmp_path):
    repo, commit, tag_object = make_tag_repo(tmp_path, annotated=False)
    with pytest.raises(PreflightError, match="annotated tag"):
        verify_release_tag(repo, tag="release", expected_tag_object=tag_object, expected_commit=commit)


def test_annotated_release_tag_is_accepted(tmp_path):
    repo, commit, tag_object = make_tag_repo(tmp_path, annotated=True)
    verify_release_tag(repo, tag="release", expected_tag_object=tag_object, expected_commit=commit)


def test_release_worktree_is_removed_on_exception():
    release_path: Path | None = None
    with pytest.raises(RuntimeError, match="intentional"):
        with release_worktree(root(), EXPECTED_COMMIT) as release:
            release_path = release
            assert release.is_dir()
            raise RuntimeError("intentional")
    assert release_path is not None
    assert not release_path.exists()


def test_runtime_facade_is_bound_to_signed_phase3_release():
    assert PHASE3_CONTRACT_RELEASE == "phase3-core-v1.0.0"
    assert PHASE3_G3_CHECKPOINT_ID == pin_value()["pin"]["g3_checkpoint_id"]
    assert getattr(ProjectionPort, "query_projection")
