#!/usr/bin/env python3
"""Build a double-clickable local Wiki Memory.app without network access.

The bundle contains only the transitive ``wiki_spike`` modules required by the
desktop surface and the existing encrypted lifecycle authority. It does not ship
the legacy storage stack, connectors, model routes, or unrelated phase tooling.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import plistlib
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

APP_NAME = "Wiki Memory"
BUNDLE_ID = "kr.baeruro.wikimemory"
DEFAULT_PYTHON = Path("/Library/Frameworks/Python.framework/Versions/3.12/bin/python3")
PYTHON_FRAMEWORK_DEPENDENCY = "/Library/Frameworks/Python.framework/Versions/3.12/Python"


class BuildError(RuntimeError):
    pass


def _run(command: list[str], *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if result.returncode != 0:
        raise BuildError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )
    return result


def _copy_package(source: Path, destination: Path) -> None:
    if not source.is_dir():
        raise BuildError(f"package directory is missing: {source}")
    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )


PRODUCT_ENTRY_MODULES = (
    "wiki_spike.operational.desktop",
    "wiki_spike.operational.desktop_service",
    "wiki_spike.operational.store",
    "wiki_spike.operational.agent",
)


def _module_path(source_root: Path, module: str) -> Path | None:
    candidate = source_root.joinpath(*module.split("."))
    module_file = candidate.with_suffix(".py")
    if module_file.is_file():
        return module_file
    package_file = candidate / "__init__.py"
    return package_file if package_file.is_file() else None


def _resolve_relative_import(
    current_module: str,
    current_path: Path,
    level: int,
    imported_module: str | None,
) -> str:
    package_parts = current_module.split(".")
    if current_path.name != "__init__.py":
        package_parts.pop()
    keep = len(package_parts) - level + 1
    if keep < 0:
        return ""
    resolved = package_parts[:keep]
    if imported_module:
        resolved.extend(imported_module.split("."))
    return ".".join(resolved)


def _product_module_closure(source_root: Path) -> tuple[str, ...]:
    pending = list(PRODUCT_ENTRY_MODULES)
    discovered: set[str] = set()
    while pending:
        module = pending.pop()
        if module in discovered:
            continue
        path = _module_path(source_root, module)
        if path is None:
            raise BuildError(f"product module is missing: {module}")
        discovered.add(module)
        try:
            tree = ast.parse(path.read_text("utf-8"), filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise BuildError(f"cannot inspect product module {module}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("wiki_spike"):
                        pending.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                base = (
                    _resolve_relative_import(module, path, node.level, node.module)
                    if node.level
                    else (node.module or "")
                )
                if not base.startswith("wiki_spike"):
                    continue
                pending.append(base)
                for alias in node.names:
                    candidate = f"{base}.{alias.name}"
                    if _module_path(source_root, candidate) is not None:
                        pending.append(candidate)
    return tuple(sorted(discovered))


def _copy_product_modules(source_root: Path, python_root: Path) -> tuple[str, ...]:
    modules = _product_module_closure(source_root)
    module_set = set(modules)
    package_root = python_root / "wiki_spike"
    package_root.mkdir(parents=True, exist_ok=True)
    copied_initializers: set[Path] = set()
    for module in modules:
        source = _module_path(source_root, module)
        assert source is not None
        relative = source.relative_to(source_root)
        destination = python_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

        # Ensure every package parent is importable. Parent __init__ modules
        # that are not themselves in the closure are replaced by an inert
        # namespace: importing memory_core.contracts must not pull the entire
        # development API exported by memory_core/__init__.py into the app.
        current = source.parent
        while current != source_root.parent and current.is_relative_to(source_root):
            initializer = current / "__init__.py"
            if initializer.is_file() and initializer not in copied_initializers:
                target = python_root / initializer.relative_to(source_root)
                target.parent.mkdir(parents=True, exist_ok=True)
                package_module = ".".join(current.relative_to(source_root).parts)
                if package_module in module_set:
                    shutil.copy2(initializer, target)
                else:
                    target.write_text(
                        '"""Minimal namespace for the bundled Wiki Memory product."""\n',
                        encoding="utf-8",
                    )
                copied_initializers.add(initializer)
            if current == source_root:
                break
            current = current.parent

        # Package data is load-bearing for schema/resource validation, but
        # unrelated Python modules in that package are not copied.
        if source.name == "__init__.py":
            for data in source.parent.rglob("*"):
                if (
                    not data.is_file()
                    or data.suffix in {".py", ".pyc", ".pyo"}
                    or "__pycache__" in data.parts
                ):
                    continue
                target = python_root / data.relative_to(source_root)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(data, target)
    return modules


def _runtime_ignore(directory: str, names: list[str]) -> set[str]:
    """Exclude build-only material while preserving a runnable Python/Tk runtime."""
    ignored = {
        name
        for name in names
        if name in {"_CodeSignature", "__pycache__", "site-packages"}
        or name.endswith((".pyc", ".pyo"))
    }
    # Headers, manuals, and bundled package installers are not used by the app.
    current = Path(directory)
    if current.name == "3.12":
        ignored.update(name for name in names if name in {"share", "bin", "etc"})
    if current.name == "python3.12":
        ignored.update(
            name
            for name in names
            if name in {"ensurepip", "idlelib", "test", "turtledemo", "venv"}
        )
    return ignored


def _bundle_python_runtime(source_python: Path, frameworks: Path) -> tuple[Path, Path]:
    """Copy and relocate the Python/Tk runtime into the application bundle."""
    source_version = source_python.parents[1]
    if source_version.name != "3.12":
        raise BuildError(f"unexpected Python framework layout: {source_python}")
    runtime_root = frameworks / "Python.framework" / "Versions" / source_version.name
    runtime_root.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(
        source_version,
        runtime_root,
        symlinks=True,
        ignore=_runtime_ignore,
    )
    framework_root = runtime_root.parents[1]
    current = framework_root / "Versions" / "Current"
    current.symlink_to(source_version.name)
    (framework_root / "Python").symlink_to("Versions/Current/Python")
    (framework_root / "Resources").symlink_to("Versions/Current/Resources")
    (framework_root / "Headers").symlink_to("Versions/Current/Headers")
    executable = runtime_root / "Resources" / "Python.app" / "Contents" / "MacOS" / "Python"
    if not executable.is_file():
        raise BuildError("bundled Python.app executable is missing")
    install_name_tool = Path("/usr/bin/install_name_tool")
    if not install_name_tool.is_file():
        raise BuildError("install_name_tool is required to relocate Python")
    _run(
        [
            str(install_name_tool),
            "-change",
            PYTHON_FRAMEWORK_DEPENDENCY,
            "@executable_path/../../../../Python",
            str(executable),
        ]
    )
    codesign = Path("/usr/bin/codesign")
    if codesign.is_file():
        # The PSF binary arrives with Hardened Runtime/library validation.
        # After relocation it must share the app's ad-hoc boundary so bundled
        # cryptography/cffi extensions are loadable without a separate install.
        _run([str(codesign), "--force", "--sign", "-", str(executable)])
    return runtime_root, executable


def _python_details(python: Path) -> dict[str, str]:
    result = _run(
        [
            str(python),
            "-c",
            (
                "import json,sys,tkinter,cryptography,_cffi_backend,cffi,pycparser; "
                "print(json.dumps({'version':sys.version.split()[0],"
                "'tk':str(tkinter.TkVersion),'cryptography':cryptography.__version__,"
                "'cryptography_path':cryptography.__file__,"
                "'cffi_backend_path':_cffi_backend.__file__,"
                "'cffi_path':cffi.__file__,'pycparser_path':pycparser.__file__}))"
            ),
        ]
    )
    value = json.loads(result.stdout)
    if not str(value["version"]).startswith("3.12."):
        raise BuildError(f"Python 3.12 is required, got {value['version']}")
    return {key: str(item) for key, item in value.items()}


def build_app(
    repo: Path,
    output: Path,
    *,
    python: Path = DEFAULT_PYTHON,
    verify: bool = True,
    standalone: bool = True,
) -> dict[str, str]:
    repo = repo.resolve()
    output = output.expanduser().resolve()
    python = python.expanduser().resolve()
    if sys.platform != "darwin":
        raise BuildError("Wiki Memory.app can only be built on macOS")
    if not python.is_file():
        raise BuildError(f"Python runtime is missing: {python}")
    details = _python_details(python)

    if output.exists():
        if output.is_symlink() or not output.is_dir() or output.suffix != ".app":
            raise BuildError(f"refusing to replace non-app output: {output}")
        shutil.rmtree(output)

    contents = output / "Contents"
    macos = contents / "MacOS"
    resources = contents / "Resources"
    frameworks = contents / "Frameworks"
    python_root = resources / "python"
    for directory in (macos, python_root):
        directory.mkdir(parents=True, exist_ok=True)

    source_package = repo / "src" / "wiki_spike"
    product_modules = _copy_product_modules(source_package.parent, python_root)

    cryptography_init = Path(details["cryptography_path"]).resolve()
    _copy_package(cryptography_init.parent, python_root / "cryptography")
    cffi_backend = Path(details["cffi_backend_path"]).resolve()
    shutil.copy2(cffi_backend, python_root / cffi_backend.name)
    _copy_package(Path(details["cffi_path"]).resolve().parent, python_root / "cffi")
    _copy_package(Path(details["pycparser_path"]).resolve().parent, python_root / "pycparser")

    runtime_root: Path | None = None
    bundled_python: Path | None = None
    if standalone:
        runtime_root, bundled_python = _bundle_python_runtime(python, frameworks)

    launcher = macos / APP_NAME
    launcher_lines = [
        "#!/bin/bash",
        "set -euo pipefail",
        'CONTENTS="$(cd "$(dirname "$0")/.." && pwd)"',
        'RESOURCES="$CONTENTS/Resources"',
    ]
    if standalone:
        launcher_lines.extend(
            [
                'RUNTIME="$CONTENTS/Frameworks/Python.framework/Versions/3.12"',
                'PYTHON="$RUNTIME/Resources/Python.app/Contents/MacOS/Python"',
                'export PYTHONHOME="$RUNTIME"',
                'export DYLD_LIBRARY_PATH="$RUNTIME/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"',
                'export TCL_LIBRARY="$RUNTIME/lib/tcl8.6"',
                'export TK_LIBRARY="$RUNTIME/lib/tk8.6"',
            ]
        )
    else:
        launcher_lines.append(f"PYTHON={json.dumps(str(python))}")
    launcher_lines.extend(
        [
            'if [[ ! -x "$PYTHON" ]]; then',
            "  /usr/bin/osascript -e 'display alert \"Wiki Memory를 실행할 수 없습니다\" message \"앱 파일이 손상되었습니다. Wiki Memory를 다시 설치해 주세요.\" as critical' || true",
            "  exit 2",
            "fi",
            "export PYTHONNOUSERSITE=1",
            "export PYTHONDONTWRITEBYTECODE=1",
            'export PYTHONPATH="$RESOURCES/python"',
            'exec "$PYTHON" -m wiki_spike.operational.desktop "$@"',
            "",
        ]
    )
    launcher.write_text("\n".join(launcher_lines), encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    version = "0.1.0"
    plist = {
        "CFBundleDevelopmentRegion": "ko",
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": "1",
        "LSApplicationCategoryType": "public.app-category.productivity",
        "LSMinimumSystemVersion": "13.0",
        "NSHighResolutionCapable": True,
        "NSHumanReadableCopyright": "Local-only personal memory",
        "NSPrincipalClass": "NSApplication",
    }
    with (contents / "Info.plist").open("wb") as handle:
        plistlib.dump(plist, handle, sort_keys=True)
    (contents / "PkgInfo").write_bytes(b"APPL????")
    (resources / "build-manifest.json").write_text(
        json.dumps(
            {
                "app": APP_NAME,
                "bundle_id": BUNDLE_ID,
                "version": version,
                "python": details["version"],
                "tk": details["tk"],
                "cryptography": details["cryptography"],
                "runtime_mode": "bundled" if standalone else "system",
                "runtime_root": (
                    "Contents/Frameworks/Python.framework/Versions/3.12"
                    if runtime_root is not None
                    else str(python)
                ),
                "network_enabled": False,
                "external_models_enabled": False,
                "authority": "ENCRYPTED_LIFECYCLE_CORE",
                "parallel_memory_database": False,
                "read_only_ai_recall": True,
                "product_module_count": str(len(product_modules)),
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    signature = "not-available"
    codesign = Path("/usr/bin/codesign")
    if codesign.is_file():
        _run([str(codesign), "--force", "--deep", "--sign", "-", str(output)])
        _run([str(codesign), "--verify", "--deep", "--strict", str(output)])
        signature = "ad-hoc-verified"

    if verify:
        with tempfile.TemporaryDirectory(prefix="wiki-memory-app-check-") as temporary:
            root = Path(temporary) / "data"
            checked = _run([str(launcher), "--check", "--root", str(root)])
            payload = json.loads(checked.stdout)
            if payload.get("operational_ready") is not True:
                raise BuildError("built app did not report operational readiness")
            if payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE":
                raise BuildError("built app did not use the existing encrypted authority")
            if payload.get("parallel_memory_database") is not False:
                raise BuildError("built app reported a parallel memory database")
            ui_root = Path(temporary) / "ui-data"
            _run(
                [
                    str(launcher),
                    "--root",
                    str(ui_root),
                    "--demo",
                    "--ui-smoke",
                ]
            )
            read_request = json.dumps(
                {
                    "tool": "memory_recall",
                    "params": {"query": "복구 일정", "limit": "10"},
                },
                ensure_ascii=False,
            )
            read_result = _run(
                [
                    str(launcher),
                    "--read-only-request",
                    read_request,
                    "--root",
                    str(ui_root),
                ]
            )
            read_payload = json.loads(read_result.stdout)
            if (
                read_payload.get("authority") != "ENCRYPTED_LIFECYCLE_CORE"
                or not read_payload.get("results")
            ):
                raise BuildError("built app and read-only AI surface did not share authority")

    return {
        "status": "pass",
        "app": str(output),
        "version": version,
        "python": details["version"],
        "tk": details["tk"],
        "cryptography": details["cryptography"],
        "verified": str(bool(verify)).lower(),
        "ui_smoke": "pass" if verify else "not-run",
        "signature": signature,
        "runtime_mode": "bundled" if standalone else "system",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, default=Path("dist") / f"{APP_NAME}.app")
    parser.add_argument("--python", type=Path, default=DEFAULT_PYTHON)
    parser.add_argument("--no-verify", action="store_true")
    parser.add_argument("--thin", action="store_true", help="do not bundle Python (development only)")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    repo = args.repo_root.resolve()
    output = args.output if args.output.is_absolute() else repo / args.output
    try:
        result = build_app(
            repo,
            output,
            python=args.python,
            verify=not args.no_verify,
            standalone=not args.thin,
        )
    except (BuildError, OSError, ValueError, json.JSONDecodeError) as exc:
        payload = {"status": "fail", "error": str(exc)}
        print(json.dumps(payload, ensure_ascii=False) if args.json else f"FAIL: {exc}")
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True) if args.json else f"PASS: {result['app']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
