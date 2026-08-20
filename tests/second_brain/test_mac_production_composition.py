"""Installed Mac production composition refuses storage and network constructors."""
from __future__ import annotations

import ast
from pathlib import Path

COMPOSITION = Path("src/wiki_spike/composition/mac_production.py")
PYPROJECT = Path("pyproject.toml")
BANNED_IMPORTS = {
    "http",
    "importlib",
    "multiprocessing",
    "requests",
    "socket",
    "sqlite3",
    "subprocess",
    "urllib",
    "wiki_spike.infrastructure.encrypted_cas",
    "wiki_spike.infrastructure.lifecycle_db",
    "wiki_spike.infrastructure.macos_keychain",
    "wiki_spike.infrastructure.macos_keychain_backend",
}


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"__import__", "eval", "exec"}:
                names.add(node.func.id)
    return names


def test_mac_production_does_not_import_storage_or_network_constructors() -> None:
    imported = _imported(COMPOSITION)
    assert BANNED_IMPORTS.isdisjoint(imported), sorted(imported & BANNED_IMPORTS)


def test_installed_wiki_entry_points_at_mac_production_main() -> None:
    assert 'wiki = "wiki_spike.composition.mac_production:main"' in PYPROJECT.read_text(
        encoding="utf-8"
    )
