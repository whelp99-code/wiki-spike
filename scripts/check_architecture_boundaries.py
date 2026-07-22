#!/usr/bin/env python3
"""AST-based architecture boundary enforcement for Phase 3 onward."""
from __future__ import annotations

import argparse
import ast
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

try:
    from .preflight_common import PreflightError, find_repo_root, strict_json_load
except ImportError:  # direct script execution
    from preflight_common import PreflightError, find_repo_root, strict_json_load


@dataclass(frozen=True)
class Violation:
    path: str
    line: int
    layer: str
    imported_module: str
    reason: str

    def render(self) -> str:
        return (
            f"{self.path}:{self.line}: [{self.layer}] forbidden import "
            f"{self.imported_module}: {self.reason}"
        )


def _module_for_path(repo: Path, path: Path) -> str:
    relative = path.resolve().relative_to((repo / "src").resolve())
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _package_for_module(module: str, path: Path) -> str:
    return module if path.name == "__init__.py" else module.rpartition(".")[0]


def _resolve_relative(package: str, level: int, module: str | None) -> str:
    if level <= 0:
        return module or ""
    package_parts = package.split(".") if package else []
    keep = len(package_parts) - level + 1
    if keep < 0:
        return ""
    base = package_parts[:keep]
    if module:
        base.extend(module.split("."))
    return ".".join(part for part in base if part)


def _imports(tree: ast.AST, module: str, path: Path) -> Iterable[tuple[str, int]]:
    package = _package_for_module(module, path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, node.lineno
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_relative(package, node.level, node.module)
            if base:
                yield base, node.lineno
            if node.module is None:
                for alias in node.names:
                    candidate = f"{base}.{alias.name}" if base else alias.name
                    yield candidate, node.lineno
        elif isinstance(node, ast.Call):
            name = None
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                name = "__import__"
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            ):
                name = "importlib.import_module"
            if name and node.args:
                if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    yield node.args[0].value, node.lineno
                else:
                    yield "<dynamic-import>", node.lineno


def _matches(module: str, forbidden: str) -> bool:
    return module == forbidden or module.startswith(forbidden + ".")


def _classify_layer(relative_path: str, layers: dict[str, list[str]]) -> str | None:
    # Longest matching prefix wins so memory_core/runtime/application override the
    # broad storage prefix ``src/wiki_spike``.
    candidates: list[tuple[int, str]] = []
    normalized = relative_path.replace("\\", "/")
    for layer, prefixes in layers.items():
        for prefix in prefixes:
            p = prefix.rstrip("/")
            if normalized == p or normalized.startswith(p + "/"):
                candidates.append((len(p), layer))
    if not candidates:
        return None
    return max(candidates)[1]


def lint_boundaries(repo: Path, config_path: Path) -> list[Violation]:
    config = strict_json_load(config_path, require_canonical=True)
    if not isinstance(config, dict) or config.get("schema_version") != "phase3-boundaries-v1":
        raise PreflightError("unsupported architecture boundary config")
    layers = config.get("layers")
    rules = config.get("rules")
    scan_roots = config.get("scan_roots")
    if not isinstance(layers, dict) or not isinstance(rules, list) or not isinstance(scan_roots, list):
        raise PreflightError("malformed architecture boundary config")

    violations: list[Violation] = []
    for scan_root in scan_roots:
        root = (repo / scan_root).resolve()
        if not root.exists():
            continue
        for path in sorted(root.rglob("*.py")):
            if path.is_symlink():
                raise PreflightError(f"symlinked Python source is not allowed: {path}")
            relative = path.relative_to(repo).as_posix()
            layer = _classify_layer(relative, layers)
            if layer is None:
                continue
            try:
                tree = ast.parse(path.read_text("utf-8"), filename=relative)
            except (SyntaxError, UnicodeDecodeError) as exc:
                raise PreflightError(f"cannot parse {relative}: {exc}") from exc
            module = _module_for_path(repo, path)
            for imported, line in _imports(tree, module, path):
                if imported == "<dynamic-import>" and layer in {"core", "runtime", "application"}:
                    violations.append(
                        Violation(
                            path=relative, line=line, layer=layer, imported_module=imported,
                            reason="non-constant dynamic imports are forbidden in protected layers",
                        )
                    )
                    continue
                for rule in rules:
                    if layer not in rule.get("from_layers", []):
                        continue
                    for forbidden in rule.get("forbidden_modules", []):
                        if _matches(imported, forbidden):
                            violations.append(
                                Violation(
                                    path=relative,
                                    line=line,
                                    layer=layer,
                                    imported_module=imported,
                                    reason=str(rule.get("reason", "boundary violation")),
                                )
                            )
    return sorted(violations, key=lambda item: (item.path, item.line, item.imported_module))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--config", default="architecture-boundaries.json")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = repo / config_path
    try:
        violations = lint_boundaries(repo, config_path)
    except PreflightError as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False) if args.json else f"FAIL: {exc}")
        return 2
    if violations:
        if args.json:
            print(json.dumps({"status": "fail", "violations": [v.__dict__ for v in violations]}, ensure_ascii=False, sort_keys=True))
        else:
            print("Architecture boundary violations:")
            for violation in violations:
                print(f"- {violation.render()}")
        return 1
    print(json.dumps({"status": "pass", "violations": []}) if args.json else "PASS: architecture boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
