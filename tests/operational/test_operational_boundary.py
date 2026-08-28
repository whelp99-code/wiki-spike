from __future__ import annotations

from pathlib import Path

from scripts.check_operational_boundary import check


def test_current_operational_package_is_local_only() -> None:
    root = Path(__file__).resolve().parents[2]
    assert check(root) == []


def test_boundary_rejects_network_process_and_internal_imports(tmp_path: Path) -> None:
    package = tmp_path / "src/wiki_spike/operational"
    package.mkdir(parents=True)
    (package / "bad.py").write_text(
        "import socket\nimport subprocess\nfrom wiki_spike.memory_runtime import orchestrator\n",
        encoding="utf-8",
    )
    reasons = {str(item["reason"]) for item in check(tmp_path)}
    assert "forbidden import: socket" in reasons
    assert "forbidden import: subprocess" in reasons
    assert any("imports internal layer" in reason for reason in reasons)


def test_boundary_allows_only_the_named_core_facade(tmp_path: Path) -> None:
    package = tmp_path / "src/wiki_spike/operational"
    package.mkdir(parents=True)
    (package / "store.py").write_text(
        "from wiki_spike.composition.local_second_brain import LocalMemoryStore\n",
        encoding="utf-8",
    )
    facade = tmp_path / "src/wiki_spike/composition/local_second_brain.py"
    facade.parent.mkdir(parents=True)
    facade.write_text(
        "from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase\n",
        encoding="utf-8",
    )
    assert check(tmp_path) == []


def test_boundary_rejects_a_parallel_operational_database(tmp_path: Path) -> None:
    package = tmp_path / "src/wiki_spike/operational"
    package.mkdir(parents=True)
    forbidden_ddl = "CREATE" + " TABLE memory(body TEXT)"
    (package / "store.py").write_text(
        "import sqlite3\nDDL = " + repr(forbidden_ddl) + "\n",
        encoding="utf-8",
    )
    reasons = {str(item["reason"]) for item in check(tmp_path)}
    assert "forbidden import: sqlite3" in reasons
    assert any("parallel engine" in reason for reason in reasons)
