#!/usr/bin/env python3
"""Build and install the wheel in an isolated smoke-test environment."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
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
        # macOS exposes TemporaryDirectory under /var, which is itself a
        # system symlink to /private/var.  Resolve the harness-owned temp root
        # before exercising the product's intentional symlink-ancestor guard.
        temp = Path(temp_dir).resolve()
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
            wiki_memory = venv / "Scripts" / "wiki-memory.exe"
            wiki_support = venv / "Scripts" / "wiki-memory-support.exe"
            wiki_read = venv / "Scripts" / "wiki-memory-read.exe"
        else:
            python = venv / "bin" / "python"
            wiki = venv / "bin" / "wiki"
            wiki_memory = venv / "bin" / "wiki-memory"
            wiki_support = venv / "bin" / "wiki-memory-support"
            wiki_read = venv / "bin" / "wiki-memory-read"
        _ensure_pip(python=python, cwd=repo)
        _run([str(python), "-m", "pip", "install", "--force-reinstall", "--no-deps", str(wheel)], cwd=repo)
        _run([str(python), "-c", "import wiki_spike; print(wiki_spike.__name__)"], cwd=repo)
        help_result = _run([str(wiki), "--help"], cwd=repo)
        if "usage" not in help_result.stdout.lower():
            raise PreflightError("installed wiki console script did not emit usage")

        workspace = temp / "operational-workspace"
        backup = temp / "operational.wkbak"
        passphrase_file = temp / "backup-passphrase.txt"
        restored = temp / "restored-workspace"
        passphrase_file.write_text("package smoke backup passphrase 2026\n", encoding="utf-8")
        os.chmod(passphrase_file, 0o600)

        init_result = _run(
            [str(wiki_support), "--root", str(workspace), "--json", "init"],
            cwd=repo,
        )
        init_payload = json.loads(init_result.stdout)
        if (
            init_payload.get("operational_ready") is not True
            or init_payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE"
            or init_payload.get("parallel_memory_database") is not False
        ):
            raise PreflightError("installed support CLI failed core initialization")

        remember_result = _run(
            [
                str(wiki_support),
                "--root",
                str(workspace),
                "--json",
                "remember",
                "--text",
                "package smoke memory",
                "--title",
                "Package smoke",
            ],
            cwd=repo,
        )
        remembered = json.loads(remember_result.stdout)
        memory_id = remembered.get("memory_id")
        if not isinstance(memory_id, str) or remembered.get("source_name") != "Package smoke":
            raise PreflightError("installed wiki failed encrypted remember")

        recall_result = _run(
            [
                str(wiki_support),
                "--root",
                str(workspace),
                "--json",
                "recall",
                "package smoke",
            ],
            cwd=repo,
        )
        recalled = json.loads(recall_result.stdout)
        if not isinstance(recalled, list) or not recalled or recalled[0].get("memory_id") != memory_id:
            raise PreflightError("installed support CLI failed core recall")

        read_result = _run(
            [
                str(wiki_read),
                "--root",
                str(workspace),
                "--request",
                json.dumps(
                    {
                        "tool": "memory_source",
                        "params": {"memory_id": memory_id},
                    },
                    sort_keys=True,
                ),
            ],
            cwd=repo,
        )
        read_payload = json.loads(read_result.stdout)
        if (
            read_payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE"
            or read_payload.get("memory", {}).get("memory_id") != memory_id
            or read_payload.get("citation", {}).get("authority")
            != "ENCRYPTED_LIFECYCLE_CORE"
        ):
            raise PreflightError("installed read-only AI tool did not use the core authority")

        _run(
            [
                str(wiki_support),
                "--root",
                str(workspace),
                "--json",
                "backup",
                str(backup),
                "--passphrase-file",
                str(passphrase_file),
            ],
            cwd=repo,
        )
        _run(
            [
                str(wiki_support),
                "--root",
                str(restored),
                "--json",
                "restore",
                str(backup),
                "--passphrase-file",
                str(passphrase_file),
            ],
            cwd=repo,
        )
        doctor_result = _run(
            [str(wiki_support), "--root", str(restored), "--json", "doctor"],
            cwd=repo,
        )
        doctor_payload = json.loads(doctor_result.stdout)
        if (
            doctor_payload.get("operational_ready") is not True
            or doctor_payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE"
            or doctor_payload.get("parallel_memory_database") is not False
        ):
            raise PreflightError("installed wiki failed restored deep verification")
        if sys.platform == "darwin":
            desktop_root = temp / "desktop-workspace"
            desktop_result = _run(
                [str(wiki_memory), "--check", "--root", str(desktop_root)],
                cwd=repo,
            )
            desktop_payload = json.loads(desktop_result.stdout)
            if (
                desktop_payload.get("operational_ready") is not True
                or desktop_payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE"
                or desktop_payload.get("parallel_memory_database") is not False
            ):
                raise PreflightError("installed wiki-memory desktop check failed")
        return {
            "status": "pass",
            "wheel": wheel.name,
            "wheel_sha256": sha256_file(wheel),
            "operational_smoke": "pass",
            "core_authority": "pass",
            "read_only_ai": "pass",
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
