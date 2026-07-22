from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from scripts.check_architecture_boundaries import lint_boundaries
from scripts.preflight_common import PreflightError


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    (repo / "src/wiki_spike").mkdir(parents=True)
    shutil.copy2(root() / "architecture-boundaries.json", repo / "architecture-boundaries.json")
    return repo


def write(repo: Path, relative: str, content: str) -> None:
    path = repo / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def violations(repo: Path):
    return lint_boundaries(repo, repo / "architecture-boundaries.json")


def test_repository_boundaries_pass():
    assert violations(root()) == []


@pytest.mark.parametrize(
    ("relative", "content", "expected"),
    [
        ("src/wiki_spike/memory_runtime/a.py", "import wiki_spike.controlplane\n", "wiki_spike.controlplane"),
        ("src/wiki_spike/memory_runtime/a.py", "from wiki_spike.cas import ContentAddressedStore\n", "wiki_spike.cas"),
        ("src/wiki_spike/applications/a.py", "import wiki_spike.signing as signing\n", "wiki_spike.signing"),
        ("src/wiki_spike/connectors/a.py", "from wiki_spike.gitrepo import GitRepo\n", "wiki_spike.gitrepo"),
        ("src/wiki_spike/ui/a.py", "import wiki_spike.workspace\n", "wiki_spike.workspace"),
        ("src/wiki_spike/memory_runtime/a.py", "import importlib\nimportlib.import_module('wiki_spike.publish')\n", "wiki_spike.publish"),
        ("src/wiki_spike/memory_runtime/a.py", "__import__('wiki_spike.generation')\n", "wiki_spike.generation"),
        ("src/wiki_spike/memory_runtime/a.py", "from .. import controlplane\n", "wiki_spike.controlplane"),
        ("src/wiki_spike/cas.py", "import wiki_spike.memory_core\n", "wiki_spike.memory_core"),
        ("src/wiki_spike/memory_core/a.py", "import wiki_spike.memory_runtime\n", "wiki_spike.memory_runtime"),
        ("src/wiki_spike/memory_runtime/a.py", "import wiki_spike.applications\n", "wiki_spike.applications"),
    ],
)
def test_forbidden_imports_are_detected(tmp_path, relative, content, expected):
    repo = make_repo(tmp_path)
    write(repo, relative, content)
    found = violations(repo)
    assert len(found) == 1
    assert found[0].imported_module == expected


def test_comment_and_string_do_not_trigger(tmp_path):
    repo = make_repo(tmp_path)
    write(
        repo,
        "src/wiki_spike/memory_runtime/a.py",
        "# import wiki_spike.controlplane\nTEXT = 'import wiki_spike.cas'\n",
    )
    assert violations(repo) == []


def test_nonconstant_dynamic_import_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    write(
        repo,
        "src/wiki_spike/memory_runtime/a.py",
        "import importlib\nname = get_name()\nimportlib.import_module(name)\n",
    )
    found = violations(repo)
    assert len(found) == 1
    assert found[0].imported_module == "<dynamic-import>"


def test_syntax_error_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "src/wiki_spike/memory_runtime/a.py", "def broken(:\n")
    with pytest.raises(PreflightError, match="cannot parse"):
        violations(repo)


def test_symlinked_source_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    target = repo / "target.py"
    target.write_text("pass\n")
    link = repo / "src/wiki_spike/memory_runtime/link.py"
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(PreflightError, match="symlinked Python source"):
        violations(repo)
