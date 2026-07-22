#!/usr/bin/env python3
"""Phase 3 G3 conformance matrix, source inventory, and evidence runner.

The committed matrix is declarative, but it cannot introduce arbitrary commands.
Gate IDs are resolved through the closed catalog in this module.  Evidence stores
only command names, hashes, counts and status; command output stays in CI logs.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import Any, Iterable, Mapping, Sequence

try:
    from .preflight_common import (
        PreflightError,
        find_repo_root,
        sha256_file,
        strict_json_load,
        write_canonical_json,
    )
except ImportError:  # direct script execution
    from preflight_common import (
        PreflightError,
        find_repo_root,
        sha256_file,
        strict_json_load,
        write_canonical_json,
    )

from wiki_spike.memory_core.contracts import canonical_bytes

MATRIX_VERSION = "phase3-conformance-matrix-v1"
INVENTORY_VERSION = "phase3-source-inventory-v1"
EVIDENCE_VERSION = "phase3-g3-evidence-v1"
CONTRACT_RELEASE = "phase3-core-v1.0.0"
REQUIREMENT_IDS = tuple(f"P3-F-{index:03d}" for index in range(1, 21))
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The gate catalog is intentionally closed.  A matrix file can select these
# identifiers, but cannot cause arbitrary command execution.
GATE_COMMANDS: dict[str, tuple[str, ...]] = {
    "g2_checkpoint": (sys.executable, "scripts/verify_phase2_checkpoint.py"),
    "boundary_lint": (sys.executable, "scripts/check_architecture_boundaries.py"),
    "secret_scan": (sys.executable, "scripts/scan_secrets.py"),
    "p3_00": (
        sys.executable, "-m", "pytest", "-W", "error", "-q",
        "tests/phase3/test_p3_00_architecture_boundaries.py",
        "tests/phase3/test_p3_00_checkpoint.py",
        "tests/phase3/test_p3_00_ci_tooling.py",
        "tests/phase3/test_p3_00_secret_scan.py",
    ),
    "p3_01": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_01_contracts.py"),
    "p3_02": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_02_policy.py"),
    "p3_03": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_03_command_gateway.py"),
    "p3_04": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_04_query_gateway.py"),
    "p3_05": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_05_changeset_publication.py"),
    "p3_06": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_06_projection_coordinator.py"),
    "p3_07": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_07_operational_events.py"),
    "p3_08": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_08_plugin_gateway.py"),
    "p3_09": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_09_schema_kind_key_registry.py"),
    "p3_10": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_10_recovery.py"),
    "p3_11": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_11_operability_privacy.py"),
    "p3_12": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3/test_p3_12_conformance.py"),
    "full_phase3": (sys.executable, "-m", "pytest", "-W", "error", "-q", "tests/phase3"),
    "full_regression": (sys.executable, "-m", "pytest", "-W", "error", "-q"),
    "package_smoke": (sys.executable, "scripts/package_smoke.py", "--json"),
    "g3_checkpoint": (sys.executable, "scripts/verify_g3_checkpoint.py"),
}

REQUIRED_GATE_IDS = tuple(GATE_COMMANDS)
REQUIREMENT_MANDATORY_GATES: dict[str, frozenset[str]] = {
    "P3-F-001": frozenset({"p3_05", "p3_10"}),
    "P3-F-002": frozenset({"p3_01"}),
    "P3-F-003": frozenset({"p3_03"}),
    "P3-F-004": frozenset({"p3_03", "p3_05"}),
    "P3-F-005": frozenset({"p3_02", "p3_08"}),
    "P3-F-006": frozenset({"p3_02"}),
    "P3-F-007": frozenset({"p3_02", "p3_11"}),
    "P3-F-008": frozenset({"p3_01", "p3_05"}),
    "P3-F-009": frozenset({"p3_04", "p3_06"}),
    "P3-F-010": frozenset({"p3_06"}),
    "P3-F-011": frozenset({"p3_07"}),
    "P3-F-012": frozenset({"p3_08"}),
    "P3-F-013": frozenset({"p3_09"}),
    "P3-F-014": frozenset({"p3_09", "p3_10"}),
    "P3-F-015": frozenset({"p3_10"}),
    "P3-F-016": frozenset({"p3_11"}),
    "P3-F-017": frozenset({"p3_11"}),
    "P3-F-018": frozenset({"p3_11"}),
    "P3-F-019": frozenset({"p3_00", "boundary_lint"}),
    "P3-F-020": frozenset({"p3_12", "g3_checkpoint"}),
}
REQUIRED_ADRS = tuple(f"docs/adr/ADR-{index:04d}-" for index in range(1, 11))

# Paths in the G3 source root.  Generated checkpoint bytes/signature/trust and
# dynamic CI evidence are excluded to avoid self-reference and nondeterminism.
SOURCE_PREFIXES = (
    "src/wiki_spike/",
    "tests/phase3/",
    "schemas/phase3/",
    "docs/adr/",
    "docs/adversarial/",
    "scripts/",
)
SOURCE_EXACT = {
    "architecture-boundaries.json",
    "pyproject.toml",
    ".github/workflows/phase3-preflight.yml",
    ".github/workflows/phase3-g3-conformance.yml",
    "artifacts/conformance/phase3/P3-00/report.md",
    "artifacts/conformance/phase3/P3-11/report.md",
    "artifacts/conformance/phase3/G3/requirements.json",
    "artifacts/conformance/phase3/G3/report.md",
    "docs/releases/phase3-core-v1.0.0.md",
}
SOURCE_EXCLUDED_PREFIXES = (
    "artifacts/checkpoints/g3/",
    "artifacts/conformance/phase3/G3/logs/",
    "artifacts/conformance/phase3/G3/runs/",
)
SOURCE_EXCLUDED_NAMES = {"__pycache__", ".pytest_cache"}
SOURCE_EXCLUDED_SUFFIXES = {".pyc", ".pyo"}


@dataclass(frozen=True)
class GateExecution:
    gate_id: str
    command: tuple[str, ...]
    status: str
    exit_code: str
    output_sha256: str
    passed_tests: str | None
    log_path: str

    def to_mapping(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "command": list(self.command),
            "status": self.status,
            "exit_code": self.exit_code,
            "output_sha256": self.output_sha256,
            "passed_tests": self.passed_tests,
            "log_path": self.log_path,
        }


def _exact_keys(data: Mapping[str, Any], allowed: set[str], required: set[str], label: str) -> None:
    unknown = set(data) - allowed
    missing = required - set(data)
    if unknown:
        raise PreflightError(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise PreflightError(f"missing {label} fields: {sorted(missing)}")


def _string_list(value: object, label: str, *, nonempty: bool = True) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PreflightError(f"{label} must be an array of non-empty strings")
    result = tuple(value)
    if nonempty and not result:
        raise PreflightError(f"{label} must not be empty")
    if tuple(sorted(set(result))) != result:
        raise PreflightError(f"{label} must be sorted and unique")
    return result


def _safe_relative(path: str, label: str) -> PurePosixPath:
    if "\\" in path:
        raise PreflightError(f"{label} must use POSIX separators: {path}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise PreflightError(f"{label} is not a canonical relative path: {path}")
    return pure


def validate_matrix(repo: Path, matrix: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(
        matrix,
        {"matrix_version", "phase", "contract_release", "requirements"},
        {"matrix_version", "phase", "contract_release", "requirements"},
        "matrix",
    )
    if matrix["matrix_version"] != MATRIX_VERSION:
        raise PreflightError("unsupported Phase 3 conformance matrix version")
    if matrix["phase"] != "3" or matrix["contract_release"] != CONTRACT_RELEASE:
        raise PreflightError("matrix phase or contract release mismatch")
    requirements = matrix["requirements"]
    if not isinstance(requirements, list):
        raise PreflightError("requirements must be an array")

    seen: list[str] = []
    gates_seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for raw in requirements:
        if not isinstance(raw, dict):
            raise PreflightError("each requirement must be an object")
        _exact_keys(
            raw,
            {"requirement_id", "title", "implementation_paths", "test_paths", "evidence_paths", "gate_ids"},
            {"requirement_id", "title", "implementation_paths", "test_paths", "evidence_paths", "gate_ids"},
            "requirement",
        )
        rid = raw["requirement_id"]
        title = raw["title"]
        if not isinstance(rid, str) or not isinstance(title, str) or not title:
            raise PreflightError("requirement_id and title must be non-empty strings")
        seen.append(rid)
        implementation_paths = _string_list(raw["implementation_paths"], f"{rid}.implementation_paths")
        test_paths = _string_list(raw["test_paths"], f"{rid}.test_paths")
        evidence_paths = _string_list(raw["evidence_paths"], f"{rid}.evidence_paths")
        gate_ids = _string_list(raw["gate_ids"], f"{rid}.gate_ids")
        for gate_id in gate_ids:
            if gate_id not in GATE_COMMANDS:
                raise PreflightError(f"{rid} references unknown gate: {gate_id}")
            gates_seen.add(gate_id)
        mandatory = REQUIREMENT_MANDATORY_GATES.get(rid)
        if mandatory is None or not mandatory.issubset(set(gate_ids)):
            raise PreflightError(
                f"{rid} is missing mandatory gates: {sorted((mandatory or frozenset()) - set(gate_ids))}"
            )
        for label, paths in (
            ("implementation", implementation_paths),
            ("test", test_paths),
            ("evidence", evidence_paths),
        ):
            for relative in paths:
                _safe_relative(relative, f"{rid}.{label}")
                full = repo / relative
                if not full.is_file() or full.is_symlink():
                    raise PreflightError(f"{rid} references missing or unsafe {label} path: {relative}")
        if any(not path.startswith("tests/phase3/") for path in test_paths):
            raise PreflightError(f"{rid} test paths must stay under tests/phase3")
        normalized.append({
            "requirement_id": rid,
            "title": title,
            "implementation_paths": list(implementation_paths),
            "test_paths": list(test_paths),
            "evidence_paths": list(evidence_paths),
            "gate_ids": list(gate_ids),
        })

    if tuple(seen) != REQUIREMENT_IDS:
        raise PreflightError(f"requirement coverage/order mismatch: {seen}")
    # Every per-PR test gate must be represented.  Global gate requirements are
    # verified separately by the checkpoint.
    expected_per_pr = {f"p3_{index:02d}" for index in range(0, 13)}
    missing_per_pr = sorted(expected_per_pr - gates_seen)
    if missing_per_pr:
        raise PreflightError(f"matrix does not cover per-PR gates: {missing_per_pr}")
    return {
        "matrix_version": MATRIX_VERSION,
        "phase": "3",
        "contract_release": CONTRACT_RELEASE,
        "requirements": normalized,
    }


def load_and_validate_matrix(repo: Path, path: Path) -> dict[str, Any]:
    matrix = strict_json_load(path, require_canonical=True)
    if not isinstance(matrix, dict):
        raise PreflightError("matrix must be an object")
    return validate_matrix(repo, matrix)


def _is_source_path(relative: str) -> bool:
    if relative in SOURCE_EXACT:
        return True
    return any(relative.startswith(prefix) for prefix in SOURCE_PREFIXES)


def source_inventory(repo: Path) -> dict[str, Any]:
    entries: list[dict[str, str]] = []
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(repo).as_posix()
        if any(part in SOURCE_EXCLUDED_NAMES for part in path.parts):
            continue
        if path.suffix in SOURCE_EXCLUDED_SUFFIXES:
            continue
        if any(relative.startswith(prefix) for prefix in SOURCE_EXCLUDED_PREFIXES):
            continue
        if not _is_source_path(relative):
            continue
        payload = path.read_bytes()
        entries.append({
            "path": relative,
            "sha256": sha256(payload).hexdigest(),
            "byte_length": str(len(payload)),
        })
    if not entries:
        raise PreflightError("Phase 3 source inventory is empty")
    body = {"inventory_version": INVENTORY_VERSION, "entries": entries}
    root = sha256(canonical_bytes(body)).hexdigest()
    return {**body, "source_root": root}


def verify_inventory(repo: Path, inventory: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(
        inventory,
        {"inventory_version", "entries", "source_root"},
        {"inventory_version", "entries", "source_root"},
        "source inventory",
    )
    if inventory["inventory_version"] != INVENTORY_VERSION:
        raise PreflightError("unsupported source inventory version")
    entries = inventory["entries"]
    if not isinstance(entries, list):
        raise PreflightError("source inventory entries must be an array")
    previous = ""
    for entry in entries:
        if not isinstance(entry, dict):
            raise PreflightError("source inventory entry must be an object")
        _exact_keys(entry, {"path", "sha256", "byte_length"}, {"path", "sha256", "byte_length"}, "inventory entry")
        path = entry["path"]
        digest = entry["sha256"]
        length = entry["byte_length"]
        if not isinstance(path, str) or not isinstance(digest, str) or not isinstance(length, str):
            raise PreflightError("source inventory values must be strings")
        _safe_relative(path, "source inventory path")
        if path <= previous:
            raise PreflightError("source inventory paths must be strictly sorted")
        previous = path
        if not HEX64.fullmatch(digest) or not re.fullmatch(r"0|[1-9][0-9]*", length):
            raise PreflightError("invalid source inventory digest or byte length")
    body = {"inventory_version": INVENTORY_VERSION, "entries": entries}
    expected_root = sha256(canonical_bytes(body)).hexdigest()
    if inventory["source_root"] != expected_root:
        raise PreflightError("source inventory root mismatch")
    current = source_inventory(repo)
    if current != dict(inventory):
        raise PreflightError("Phase 3 source files do not match signed source inventory")
    return current


def validate_required_adrs(repo: Path) -> tuple[str, ...]:
    paths = tuple(sorted(path.relative_to(repo).as_posix() for path in (repo / "docs/adr").glob("ADR-*.md")))
    for prefix in REQUIRED_ADRS:
        matches = [path for path in paths if path.startswith(prefix)]
        if len(matches) != 1:
            raise PreflightError(f"expected exactly one ADR matching {prefix}, got {matches}")
    return paths


def apply_negative_fixture(matrix: Mapping[str, Any], fixture: Mapping[str, Any]) -> dict[str, Any]:
    _exact_keys(
        fixture,
        {"fixture_version", "operation", "requirement_id", "gate_id"},
        {"fixture_version", "operation", "requirement_id", "gate_id"},
        "negative fixture",
    )
    if fixture["fixture_version"] != "phase3-g3-negative-fixture-v1":
        raise PreflightError("unsupported negative fixture version")
    if fixture["operation"] != "remove_gate":
        raise PreflightError("unsupported negative fixture operation")
    result = json.loads(json.dumps(matrix))
    found = False
    for requirement in result["requirements"]:
        if requirement["requirement_id"] == fixture["requirement_id"]:
            gate = fixture["gate_id"]
            if gate not in requirement["gate_ids"]:
                raise PreflightError("negative fixture gate is not present")
            requirement["gate_ids"].remove(gate)
            found = True
    if not found:
        raise PreflightError("negative fixture requirement is not present")
    return result


def validate_negative_fixture(repo: Path, matrix: Mapping[str, Any], fixture_path: Path) -> None:
    fixture = strict_json_load(fixture_path, require_canonical=True)
    if not isinstance(fixture, dict):
        raise PreflightError("negative fixture must be an object")
    mutated = apply_negative_fixture(matrix, fixture)
    try:
        validate_matrix(repo, mutated)
    except PreflightError:
        return
    raise PreflightError("negative fixture did not make the G3 gate fail")


def _run(command: Sequence[str], repo: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo / "src")
    env["PYTHONHASHSEED"] = "0"
    return subprocess.run(
        list(command),
        cwd=repo,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def run_gates(
    repo: Path,
    *,
    log_dir: Path,
    gate_ids: Iterable[str] = REQUIRED_GATE_IDS,
    skip_package_smoke: bool = False,
) -> tuple[GateExecution, ...]:
    log_dir.mkdir(parents=True, exist_ok=True)
    executions: list[GateExecution] = []
    for gate_id in gate_ids:
        if gate_id not in GATE_COMMANDS:
            raise PreflightError(f"unknown gate requested: {gate_id}")
        if gate_id == "package_smoke" and skip_package_smoke:
            executions.append(GateExecution(
                gate_id=gate_id,
                command=GATE_COMMANDS[gate_id],
                status="skipped",
                exit_code="0",
                output_sha256=sha256(b"local-offline-skip").hexdigest(),
                passed_tests=None,
                log_path="",
            ))
            continue
        command = GATE_COMMANDS[gate_id]
        result = _run(command, repo)
        output = result.stdout or ""
        log_path = log_dir / f"{gate_id}.log"
        log_path.write_text(output, encoding="utf-8")
        matches = re.findall(r"(\d+) passed", output)
        execution = GateExecution(
            gate_id=gate_id,
            command=command,
            status="pass" if result.returncode == 0 else "fail",
            exit_code=str(result.returncode),
            output_sha256=sha256(output.encode("utf-8")).hexdigest(),
            passed_tests=matches[-1] if matches else None,
            log_path=log_path.relative_to(repo).as_posix() if log_path.is_relative_to(repo) else log_path.name,
        )
        executions.append(execution)
        if result.returncode != 0:
            raise PreflightError(f"G3 gate failed: {gate_id}\n{output[-4000:]}")
    return tuple(executions)


def build_evidence(
    repo: Path,
    *,
    checkpoint_id: str,
    source_root: str,
    matrix_digest: str,
    executions: Sequence[GateExecution],
) -> dict[str, Any]:
    if not HEX64.fullmatch(checkpoint_id) or not HEX64.fullmatch(source_root) or not HEX64.fullmatch(matrix_digest):
        raise PreflightError("invalid G3 evidence binding digest")
    skipped = [item.gate_id for item in executions if item.status != "pass"]
    body = {
        "evidence_version": EVIDENCE_VERSION,
        "phase": "3",
        "contract_release": CONTRACT_RELEASE,
        "checkpoint_id": checkpoint_id,
        "source_root": source_root,
        "matrix_sha256": matrix_digest,
        "head_commit": _git_head(repo),
        "gate_executions": [item.to_mapping() for item in executions],
        "result": "pass" if not skipped else "incomplete",
    }
    return {**body, "evidence_id": sha256(canonical_bytes(body)).hexdigest()}


def _git_head(repo: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else "unavailable"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--matrix", type=Path, default=Path("artifacts/conformance/phase3/G3/requirements.json"))
    parser.add_argument("--inventory", type=Path, default=Path("artifacts/checkpoints/g3/phase3-source-inventory.json"))
    parser.add_argument("--negative-fixture", type=Path, default=Path("tests/phase3/fixtures/g3-negative-gate.json"))
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--run-gates", action="store_true")
    parser.add_argument("--skip-package-smoke", action="store_true")
    parser.add_argument("--log-dir", type=Path, default=Path("artifacts/conformance/phase3/G3/logs"))
    parser.add_argument("--evidence-out", type=Path, default=Path("artifacts/conformance/phase3/G3/runs/evidence.json"))
    args = parser.parse_args()
    repo = find_repo_root(args.repo_root)
    try:
        matrix_path = args.matrix if args.matrix.is_absolute() else repo / args.matrix
        inventory_path = args.inventory if args.inventory.is_absolute() else repo / args.inventory
        fixture_path = args.negative_fixture if args.negative_fixture.is_absolute() else repo / args.negative_fixture
        matrix = load_and_validate_matrix(repo, matrix_path)
        validate_required_adrs(repo)
        inventory = strict_json_load(inventory_path, require_canonical=True)
        if not isinstance(inventory, dict):
            raise PreflightError("source inventory must be an object")
        verified_inventory = verify_inventory(repo, inventory)
        validate_negative_fixture(repo, matrix, fixture_path)
        if args.run_gates:
            log_dir = args.log_dir if args.log_dir.is_absolute() else repo / args.log_dir
            executions = run_gates(repo, log_dir=log_dir, skip_package_smoke=args.skip_package_smoke)
            from verify_g3_checkpoint import verify_g3_checkpoint
            checkpoint = verify_g3_checkpoint(repo=repo)
            evidence = build_evidence(
                repo,
                checkpoint_id=checkpoint["checkpoint_id"],
                source_root=verified_inventory["source_root"],
                matrix_digest=sha256_file(matrix_path),
                executions=executions,
            )
            evidence_path = args.evidence_out if args.evidence_out.is_absolute() else repo / args.evidence_out
            write_canonical_json(evidence_path, evidence)
            if evidence["result"] != "pass":
                raise PreflightError("G3 evidence is incomplete")
            print(f"PASS: G3 conformance evidence {evidence['evidence_id']}")
        else:
            print(
                "PASS: G3 matrix/source/negative-fixture verification "
                f"({len(matrix['requirements'])} requirements, {verified_inventory['source_root']})"
            )
    except (PreflightError, OSError, ValueError, KeyError) as exc:
        print(f"FAIL: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
