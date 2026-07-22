from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess

import pytest

from scripts.check_runtime_boundaries import lint_runtime_boundaries
from scripts.preflight_common import PreflightError


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src/wiki_spike/memory_runtime").mkdir(parents=True)
    (repo / ".github").mkdir(parents=True)
    shutil.copy2(
        root() / ".github/phase4-runtime-boundaries.json",
        repo / ".github/phase4-runtime-boundaries.json",
    )
    return repo


def write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_repository_runtime_boundary_passes():
    assert lint_runtime_boundaries(root()) == []


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import wiki_spike.controlplane\n", "wiki_spike.controlplane"),
        ("from wiki_spike import cas\n", "wiki_spike"),
        ("import wiki_spike.memory_core\n", "wiki_spike.memory_core"),
        ("from wiki_spike.memory_core import MemoryCommandPort\n", "wiki_spike.memory_core"),
        ("from wiki_spike.memory_core.projections import ProjectionSource\n", "wiki_spike.memory_core.projections"),
        ("import importlib\nimportlib.import_module('wiki_spike.gitrepo')\n", "wiki_spike.gitrepo"),
        ("__import__('wiki_spike.signing')\n", "wiki_spike.signing"),
    ],
)
def test_storage_and_unpinned_core_imports_are_rejected(tmp_path, source, expected):
    repo = make_repo(tmp_path)
    write(repo, "src/wiki_spike/memory_runtime/bad.py", source)
    violations = lint_runtime_boundaries(repo)
    assert len(violations) == 1
    assert violations[0].imported_module == expected


def test_only_pinned_core_modules_and_runtime_relative_imports_are_allowed(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "src/wiki_spike/memory_runtime/local.py", "VALUE = 'ok'\n")
    write(
        repo,
        "src/wiki_spike/memory_runtime/good.py",
        "from wiki_spike.memory_core.contracts import QueryEnvelope\n"
        "from wiki_spike.memory_core.ports import MemoryQueryPort\n"
        "from .local import VALUE\n",
    )
    assert lint_runtime_boundaries(repo) == []


def test_nonconstant_dynamic_import_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    write(
        repo,
        "src/wiki_spike/memory_runtime/bad.py",
        "import importlib\nname = get_name()\nimportlib.import_module(name)\n",
    )
    violations = lint_runtime_boundaries(repo)
    assert violations[0].imported_module == "<dynamic-import>"


def test_runtime_syntax_error_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "src/wiki_spike/memory_runtime/bad.py", "def broken(:\n")
    with pytest.raises(PreflightError, match="cannot parse"):
        lint_runtime_boundaries(repo)


def test_runtime_symlink_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    target = repo / "target.py"
    target.write_text("pass\n", encoding="utf-8")
    link = repo / "src/wiki_spike/memory_runtime/link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(PreflightError, match="symlinked Runtime source"):
        lint_runtime_boundaries(repo)


def test_importing_runtime_facade_does_not_load_storage_implementations():
    script = r'''
import json, sys
import wiki_spike.memory_runtime
forbidden = [
    "wiki_spike.cas", "wiki_spike.controlplane", "wiki_spike.generation",
    "wiki_spike.gitrepo", "wiki_spike.publish", "wiki_spike.signing",
    "wiki_spike.workspace",
]
print(json.dumps([name for name in forbidden if name in sys.modules]))
'''
    env = os.environ.copy()
    env["PYTHONPATH"] = str(root() / "src")
    result = subprocess.run(
        [__import__("sys").executable, "-c", script],
        cwd=root(), env=env, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "[]"
