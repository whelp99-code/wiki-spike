#!/usr/bin/env python3
"""Fail-closed import boundary for the Phase 4 Runtime package."""
from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Iterable, Mapping

try:
    from .preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        require_exact_keys,
        strict_json_load,
    )
except ImportError:
    from preflight_common import (
        PreflightError,
        ensure_within,
        find_repo_root,
        require_exact_keys,
        strict_json_load,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

POLICY_VERSION = "phase4-runtime-boundaries-v1"
TOP_KEYS = {"policy", "policy_id"}
POLICY_KEYS = {"schema_version", "runtime_root", "allowed_wiki_module_prefixes"}


@dataclass(frozen=True)
class RuntimeBoundaryViolation:
    path: str
    line: int
    imported_module: str
    reason: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: forbidden Runtime import {self.imported_module}: {self.reason}"


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
    parts = package.split(".") if package else []
    keep = len(parts) - level + 1
    if keep < 0:
        return ""
    result = parts[:keep]
    if module:
        result.extend(module.split("."))
    return ".".join(part for part in result if part)


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
                    yield f"{base}.{alias.name}" if base else alias.name, node.lineno
        elif isinstance(node, ast.Call):
            dynamic = False
            if isinstance(node.func, ast.Name) and node.func.id == "__import__":
                dynamic = True
            elif (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "import_module"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "importlib"
            ):
                dynamic = True
            if dynamic:
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    yield node.args[0].value, node.lineno
                else:
                    yield "<dynamic-import>", node.lineno


def _is_allowed(module: str, allowed: tuple[str, ...]) -> bool:
    return any(module == prefix or module.startswith(prefix + ".") for prefix in allowed)


def _load_policy(path: Path) -> tuple[dict[str, object], str]:
    value = strict_json_load(path, require_canonical=True)
    if not isinstance(value, dict):
        raise PreflightError("Runtime boundary policy must be an object")
    require_exact_keys(value, TOP_KEYS, label="Runtime boundary policy")
    policy = value["policy"]
    if not isinstance(policy, dict):
        raise PreflightError("Runtime boundary policy body must be an object")
    require_exact_keys(policy, POLICY_KEYS, label="Runtime boundary policy body")
    policy_id = value["policy_id"]
    if not isinstance(policy_id, str) or len(policy_id) != 64:
        raise PreflightError("invalid Runtime boundary policy id")
    if sha256(canonical_bytes(policy)).hexdigest() != policy_id:
        raise PreflightError("Runtime boundary policy id mismatch")
    if policy["schema_version"] != POLICY_VERSION:
        raise PreflightError("unsupported Runtime boundary policy version")
    return dict(policy), policy_id


def lint_runtime_boundaries(repo: Path, policy_path: Path | None = None) -> list[RuntimeBoundaryViolation]:
    repo = repo.resolve()
    policy_path = ensure_within(repo, policy_path or Path(".github/phase4-runtime-boundaries.json"))
    policy, _ = _load_policy(policy_path)
    runtime_root_value = policy["runtime_root"]
    allowed_value = policy["allowed_wiki_module_prefixes"]
    if runtime_root_value != "src/wiki_spike/memory_runtime":
        raise PreflightError("unexpected Runtime root")
    if not isinstance(allowed_value, list) or any(not isinstance(item, str) or not item for item in allowed_value):
        raise PreflightError("allowed Runtime modules must be non-empty strings")
    allowed = tuple(allowed_value)
    if tuple(sorted(set(allowed))) != allowed:
        raise PreflightError("allowed Runtime modules must be sorted and unique")
    expected = (
        "wiki_spike.memory_core.contracts",
        "wiki_spike.memory_core.ports",
        "wiki_spike.memory_runtime",
    )
    if allowed != expected:
        raise PreflightError("Runtime allowlist differs from the P4-00 contract")

    runtime_root = ensure_within(repo, runtime_root_value)
    if not runtime_root.is_dir() or runtime_root.is_symlink():
        raise PreflightError("Runtime root is missing or unsafe")
    violations: list[RuntimeBoundaryViolation] = []
    for path in sorted(runtime_root.rglob("*.py")):
        if path.is_symlink():
            raise PreflightError(f"symlinked Runtime source is not allowed: {path}")
        relative = path.relative_to(repo).as_posix()
        try:
            tree = ast.parse(path.read_text("utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise PreflightError(f"cannot parse Runtime source {relative}: {exc}") from exc
        module = _module_for_path(repo, path)
        for imported, line in _imports(tree, module, path):
            if imported == "<dynamic-import>":
                violations.append(RuntimeBoundaryViolation(
                    relative, line, imported,
                    "non-constant dynamic imports are forbidden in Runtime",
                ))
                continue
            if imported == "wiki_spike" or imported.startswith("wiki_spike."):
                if not _is_allowed(imported, allowed):
                    violations.append(RuntimeBoundaryViolation(
                        relative, line, imported,
                        "Runtime may import only its own package and pinned Core contracts/ports",
                    ))
    return sorted(violations, key=lambda item: (item.path, item.line, item.imported_module))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--policy", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        violations = lint_runtime_boundaries(repo, args.policy)
    except (PreflightError, OSError, ValueError, TypeError, KeyError) as exc:
        if args.json:
            print(json.dumps({"status": "fail", "error": str(exc)}, ensure_ascii=False))
        else:
            print(f"FAIL: {exc}")
        return 2
    if violations:
        if args.json:
            print(json.dumps({
                "status": "fail",
                "violations": [item.__dict__ for item in violations],
            }, ensure_ascii=False, sort_keys=True))
        else:
            print("Runtime boundary violations:")
            for violation in violations:
                print(f"- {violation.render()}")
        return 1
    if args.json:
        print(json.dumps({"status": "pass", "violations": []}))
    else:
        print("PASS: Phase 4 Runtime boundaries")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
