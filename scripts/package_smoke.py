#!/usr/bin/env python3
"""Build and install the wheel in an isolated smoke-test environment."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

try:
    from .preflight_common import PreflightError, find_repo_root, sha256_file
except ImportError:  # direct script execution
    from preflight_common import PreflightError, find_repo_root, sha256_file

FORBIDDEN_WHEEL_NAMES = {
    ".env",
    "signing.key",
    "control.sqlite",
}
FORBIDDEN_WHEEL_SUFFIXES = {".key", ".sqlite", ".sqlite3"}


def _run(
    command: list[str], *, cwd: Path, check: bool = True
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    result = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        raise PreflightError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _ensure_pip(*, python: Path, cwd: Path) -> None:
    present = _run([str(python), "-m", "pip", "--version"], cwd=cwd, check=False)
    if present.returncode == 0:
        return
    _run([str(python), "-m", "ensurepip", "--upgrade"], cwd=cwd)


def _inspect_wheel(wheel: Path) -> list[str]:
    violations: list[str] = []
    with zipfile.ZipFile(wheel) as archive:
        for name in archive.namelist():
            base = Path(name).name
            suffix = Path(name).suffix.lower()
            if base in FORBIDDEN_WHEEL_NAMES or suffix in FORBIDDEN_WHEEL_SUFFIXES:
                violations.append(name)
            if name.startswith(("tests/", "artifacts/", ".git/")):
                violations.append(name)
            data = archive.read(name)
            if (b"-----BEGIN " + b"PRIVATE KEY-----") in data or b"sk-ant-" in data:
                violations.append(name + " (secret material)")
    return sorted(set(violations))


def package_smoke(repo: Path) -> dict[str, str]:
    build_python = Path(__import__("sys").executable)
    _ensure_pip(python=build_python, cwd=repo)
    with tempfile.TemporaryDirectory(prefix="wiki-pkg-smoke-") as temp_dir:
        temp = Path(temp_dir)
        dist = temp / "dist"
        dist.mkdir()
        _run(
            [
                os.fspath(build_python),
                "-m",
                "pip",
                "wheel",
                ".",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(dist),
            ],
            cwd=repo,
        )
        wheels = sorted(dist.glob("*.whl"))
        if len(wheels) != 1:
            raise PreflightError(f"expected one wheel, found {len(wheels)}")
        wheel = wheels[0]
        violations = _inspect_wheel(wheel)
        if violations:
            raise PreflightError(f"wheel contains forbidden files/material: {violations}")

        venv = temp / "venv"
        _run(
            [os.fspath(Path(__import__("sys").executable)), "-m", "venv", "--system-site-packages", str(venv)],
            cwd=repo,
        )
        if os.name == "nt":
            python = venv / "Scripts" / "python.exe"
            wiki = venv / "Scripts" / "wiki.exe"
        else:
            python = venv / "bin" / "python"
            wiki = venv / "bin" / "wiki"
        _ensure_pip(python=python, cwd=repo)
        _run([str(python), "-m", "pip", "install", "--force-reinstall", "--no-deps", str(wheel)], cwd=repo)
        _run([str(python), "-c", "import wiki_spike; print(wiki_spike.__name__)"], cwd=repo)
        help_result = _run([str(wiki), "--help"], cwd=repo)
        if "usage" not in help_result.stdout.lower():
            raise PreflightError("installed wiki console script did not emit usage")
        return {
            "status": "pass",
            "wheel": wheel.name,
            "wheel_sha256": sha256_file(wheel),
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        result = package_smoke(repo)
    except PreflightError as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}) if args.json else f"FAIL: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True) if args.json else f"PASS: package smoke ({result['wheel']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
