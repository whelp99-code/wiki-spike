#!/usr/bin/env python3
"""Keep the supported operational package local-only and dependency-minimal."""
from __future__ import annotations

import ast
import argparse
import json
from pathlib import Path
import sys

FORBIDDEN_ROOTS = {
    "asyncio",
    "ctypes",
    "http",
    "importlib",
    "multiprocessing",
    "pickle",
    "requests",
    "shelve",
    "sqlite3",
    "socket",
    "subprocess",
    "urllib",
    "webbrowser",
}
FORBIDDEN_CALLS = {"__import__", "compile", "eval", "exec"}
ALLOWED_INTERNAL_IMPORTS = {
    "wiki_spike.composition.local_second_brain",
}


def check(root: Path) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    package = root / "src/wiki_spike/operational"
    for path in sorted(package.glob("*.py")):
        tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".", 1)[0]
                    if top in FORBIDDEN_ROOTS:
                        violations.append(
                            {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"forbidden import: {alias.name}"}
                        )
                    if (
                        alias.name.startswith("wiki_spike.")
                        and not alias.name.startswith("wiki_spike.operational")
                        and alias.name not in ALLOWED_INTERNAL_IMPORTS
                    ):
                        violations.append(
                            {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"operational package imports internal layer: {alias.name}"}
                        )
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                top = module.split(".", 1)[0]
                if node.level == 0 and top in FORBIDDEN_ROOTS:
                    violations.append(
                        {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"forbidden import: {module}"}
                    )
                if (
                    node.level == 0
                    and module.startswith("wiki_spike.")
                    and not module.startswith("wiki_spike.operational")
                    and module not in ALLOWED_INTERNAL_IMPORTS
                ):
                    violations.append(
                        {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"operational package imports internal layer: {module}"}
                    )
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in FORBIDDEN_CALLS:
                    violations.append(
                        {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"forbidden dynamic call: {node.func.id}"}
                    )
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"
                    and node.func.attr in {"system", "popen"}
                ):
                    violations.append(
                        {"path": str(path.relative_to(root)), "line": node.lineno, "reason": f"forbidden process call: os.{node.func.attr}"}
                    )
    façade = root / "src/wiki_spike/composition/local_second_brain.py"
    if façade.is_file():
        source = façade.read_text("utf-8")
        for forbidden in (
            "CREATE TABLE",
            "wiki_spike.operational",
            "wiki_spike.workspace",
            "wiki_spike.controlplane",
            "wiki_spike.generation",
            "wiki_spike.publish",
        ):
            if forbidden in source:
                violations.append(
                    {
                        "path": str(façade.relative_to(root)),
                        "line": 0,
                        "reason": f"core façade contains forbidden parallel/legacy dependency: {forbidden}",
                    }
                )
    compatibility = root / "src/wiki_spike/operational/store.py"
    if compatibility.is_file():
        source = compatibility.read_text("utf-8")
        for forbidden in ("CREATE TABLE", "sqlite3", "AESGCM", "Scrypt"):
            if forbidden in source:
                violations.append(
                    {
                        "path": str(compatibility.relative_to(root)),
                        "line": 0,
                        "reason": f"operational store reintroduced a parallel engine: {forbidden}",
                    }
                )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    violations = check(args.repo_root.resolve())
    result = {"status": "pass" if not violations else "fail", "violations": violations}
    print(json.dumps(result, sort_keys=True) if args.json else result)
    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
