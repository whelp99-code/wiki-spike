"""Shared helpers for the Phase 3 preflight gate.

This module deliberately depends only on the Python standard library and the
already-published ``wiki_spike.canonical`` contract.  It is imported by CI
scripts and tests; it is not part of the runtime package API.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterable, Sequence

try:
    from wiki_spike.canonical import CanonicalizationError, canonical_bytes
except ModuleNotFoundError:  # direct execution from a source checkout
    source_root = Path(__file__).resolve().parents[1] / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from wiki_spike.canonical import CanonicalizationError, canonical_bytes


class PreflightError(RuntimeError):
    """A deterministic preflight validation failure."""


def find_repo_root(start: str | Path | None = None) -> Path:
    current = Path(start or __file__).resolve()
    if current.is_file():
        current = current.parent
    for candidate in (current, *current.parents):
        if (candidate / ".git").exists() or (
            (candidate / "pyproject.toml").exists() and (candidate / "src").exists()
        ):
            return candidate
    raise PreflightError(f"cannot locate repository root from {current}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path) -> str:
    p = Path(path)
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise PreflightError(f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def _reject_raw_numbers(value: Any, path: str = "$") -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, (int, float)):
        raise PreflightError(f"raw JSON number forbidden at {path}; encode as a canonical string")
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_raw_numbers(child, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_raw_numbers(child, f"{path}.{key}")
        return
    raise PreflightError(f"unsupported JSON value at {path}: {type(value)!r}")


def strict_json_loads(text: str, *, require_canonical: bool = False) -> Any:
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise PreflightError(f"invalid JSON: {exc}") from exc
    _reject_raw_numbers(value)
    if require_canonical:
        try:
            encoded = canonical_bytes(value)
        except CanonicalizationError as exc:
            raise PreflightError(str(exc)) from exc
        if text.encode("utf-8") != encoded:
            raise PreflightError("JSON file is not byte-for-byte canonical UTF-8")
    return value


def strict_json_load(path: str | Path, *, require_canonical: bool = False) -> Any:
    p = Path(path)
    try:
        raw = p.read_bytes()
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PreflightError(f"JSON is not UTF-8: {p}") from exc
    return strict_json_loads(text, require_canonical=require_canonical)


def write_canonical_json(path: str | Path, value: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        payload = canonical_bytes(value)
    except CanonicalizationError as exc:
        raise PreflightError(str(exc)) from exc
    p.write_bytes(payload)


def run(
    command: Sequence[str],
    *,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    result = subprocess.run(
        list(command),
        cwd=str(cwd) if cwd else None,
        env=merged_env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        joined = " ".join(command)
        raise PreflightError(
            f"command failed ({result.returncode}): {joined}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def git(repo: str | Path, args: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["git", *args], cwd=repo, check=check)


def git_object_exists(repo: str | Path, object_name: str) -> bool:
    return git(repo, ["cat-file", "-e", object_name], check=False).returncode == 0


def git_tree_listing(repo: str | Path, commit: str) -> bytes:
    result = subprocess.run(
        ["git", "ls-tree", "-r", "-z", commit],
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise PreflightError(result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def tracked_paths(repo: str | Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise PreflightError(result.stderr.decode("utf-8", errors="replace"))
    items = [item for item in result.stdout.split(b"\x00") if item]
    return [Path(os.fsdecode(item)) for item in items]


def ensure_within(root: str | Path, candidate: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate_path = Path(candidate)
    if not candidate_path.is_absolute():
        candidate_path = root_path / candidate_path
    resolved = candidate_path.resolve()
    try:
        resolved.relative_to(root_path)
    except ValueError as exc:
        raise PreflightError(f"path escapes repository root: {candidate}") from exc
    return resolved


def require_exact_keys(mapping: dict[str, Any], expected: Iterable[str], *, label: str) -> None:
    expected_set = set(expected)
    actual_set = set(mapping)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    if missing or extra:
        raise PreflightError(f"{label} keys mismatch; missing={missing}, extra={extra}")


def python_executable() -> str:
    return sys.executable
