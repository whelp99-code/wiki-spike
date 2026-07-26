"""Gate 8 dispatch-only evidence join integration tests.

Gate 1 is deliberately allowed to be produced at a different commit; the
conformance and canary lanes must bind to the same implementation commit.
"""
from __future__ import annotations

import hashlib
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
SRC = REPO_ROOT / "src"
for _p in (str(SCRIPTS), str(SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build_encrypted_lifecycle_bundle as builder  # noqa: E402
import join_gate8_evidence as joiner  # noqa: E402
import import_encrypted_lifecycle_bundle as importer  # noqa: E402

GATE1_COMMIT = "ab" * 20
COMMIT = "cd" * 20
ZERO64 = "0" * 64

MACOS26_PLATFORMS = {
    "self-hosted/macos-26/arm64/wiki-gate1-workstation",
    "self-hosted/macos-26/arm64/wiki-conformance-workstation",
    "self-hosted/macos-26/arm64/wiki-canary-workstation",
}
CLOSED_PLATFORMS = {"github-hosted/ubuntu-24.04/x86_64", *MACOS26_PLATFORMS}
OLD_MACOS15_PLATFORMS = (
    "self-hosted/macos-15/arm64/wiki-gate1-workstation",
    "self-hosted/macos-15/arm64/wiki-conformance-workstation",
    "self-hosted/macos-15/arm64/wiki-canary-workstation",
)


def test_platform_contract_is_exact_and_rejects_all_macos15_tokens():
    schema = json.loads(
        (REPO_ROOT / "schemas/encrypted-lifecycle/bundle-manifest-v1.schema.json").read_text()
    )
    schema_platforms = set(
        schema["definitions"]["bundleEnvelopeV1"]["properties"]["platform"]["enum"]
    )
    assert builder.PLATFORMS == CLOSED_PLATFORMS
    assert importer.PLATFORMS == CLOSED_PLATFORMS
    assert schema_platforms == CLOSED_PLATFORMS
    assert {spec["platform"] for spec in joiner.LANE_SPECS.values()} == MACOS26_PLATFORMS

    for old_platform in OLD_MACOS15_PLATFORMS:
        with pytest.raises(ValueError, match="closed token"):
            builder.validate_inputs(
                repository="owner/repository",
                producer_commit="a" * 40,
                contract_digest="b" * 64,
                toolchain_lock_digest="c" * 64,
                workflow_file_digest="d" * 64,
                workflow_run_id="1",
                workflow_run_attempt="1",
                platform_token=old_platform,
                produced_at="2026-07-26T00:00:00Z",
            )

_LANES = [
    (
        "gate1",
        "GATE1_DECISION",
        (
            "payload/gate1-decision.json",
            "payload/macos/sqlcipher-feasibility.json",
            "payload/ubuntu/import-receipt.json",
            "payload/vector-validation.json",
        ),
    ),
    ("conformance", "CONFORMANCE_PRE_CANARY", ("payload/conformance-pre-canary.json",)),
    ("canary", "CANARY_24H", ("payload/rollout-evidence.json",)),
]


def _payload(lane: str) -> bytes:
    payloads = {
        "gate1": {
            "schema": "wiki-gate1-decision-v1",
            "owners": [{"actor_id": "owner", "role": "ARCHITECT"}],
            "adr_refs": ["ADR-0001"],
            "profile_selection": "B",
            "metric_freeze": {
                "extraction_precision_min": "80",
                "extraction_recall_min": "80",
                "recall_p95_ms_advisory": "200",
                "candidate_p95_ms_advisory": "500",
            },
            "contract_digests": {"schemas/gate1.json": ZERO64},
            "residual_claims": [],
            "decided_at": "2026-01-01T00:00:00Z",
        },
        "conformance": {
            "schema": "wiki-gate8-conformance-report-v1",
            "conformant": True,
            "checks": {"suite": {"passed": True, "detail": "PASS"}},
            "implementation_commit": COMMIT,
        },
        "canary": {
            "schema": "wiki-gate8-canary-report-v1",
            "evidence_lane": "CANARY_24H",
            "healthy": True,
            "configured_duration_seconds": "86400",
            "interval_seconds": "900",
            "failure_count": "0",
            "probe_count": "97",
            "original_workflow_run_id": "1",
            "observed_duration_seconds": "86400.000",
            "produced_at": "2026-01-02T00:00:00Z",
            "started_at": "2026-01-01T00:00:00Z",
            "started_at_epoch": "1767225600.000",
            "finished_at": "2026-01-02T00:00:00Z",
            "finished_at_epoch": "1767312000.000",
            "probes": [
                {
                    "probe_index": str(index), "passed": True, "error": None,
                    "elapsed_seconds": "0.001",
                    "scheduled_at_epoch": f"{1767225600 + index * 900}.000",
                    "completed_at_epoch": f"{1767225600 + index * 900}.000",
                }
                for index in range(97)
            ],
            "provenance": {
                "repository": "wiki-spike/wiki-spike",
                "original_workflow_run_id": "1",
                "current_workflow_run_id": "1",
                "current_workflow_run_attempt": "1",
                "implementation_commit": COMMIT,
                "platform": "self-hosted/macos-26/arm64/wiki-canary-workstation",
                "workflow_file_digest": ZERO64,
                "contract_digest": ZERO64,
                "toolchain_lock_digest": ZERO64,
                "source_run_url": "https://github.example/wiki-spike/wiki-spike/actions/runs/canary/attempts/1",
            },
        },
    }
    return json.dumps(payloads[lane], sort_keys=True, separators=(",", ":")).encode("utf-8")


def _join_args(lanes: dict[str, Path], out_dir: Path) -> list[str]:
    args = [
        "--gate1", str(lanes["gate1"]),
        "--conformance", str(lanes["conformance"]),
        "--canary", str(lanes["canary"]),
        "--workspace-id", "ws-test-1",
        "--output-dir", str(out_dir),
        "--gate1-commit", GATE1_COMMIT,
        "--implementation-commit", COMMIT,
        "--contract-digest", ZERO64,
        "--toolchain-lock-digest", ZERO64,
    ]
    for lane in ("gate1", "conformance", "canary"):
        envelope = json.loads((lanes[lane] / "artifact-envelope.json").read_text(encoding="utf-8"))
        tar_path = next(lanes[lane].glob("*.tar"))
        args.extend((
            f"--{lane}-run-id", "1",
            f"--{lane}-run-attempt", "1",
            f"--{lane}-repository", "wiki-spike/wiki-spike",
            f"--{lane}-source-run-url", f"https://github.example/wiki-spike/wiki-spike/actions/runs/{lane}/attempts/1",
            f"--{lane}-artifact-name", envelope["artifact_name"],
            f"--{lane}-bundle-sha256", envelope["bundle_sha256"],
            f"--{lane}-workflow-digest", ZERO64,
        ))
    return args


def _build_lane(
    tmp_path: Path,
    lane: str,
    kind: str,
    payload_names: tuple[str, ...],
    payload_bytes: bytes,
    *,
    producer_commit: str,
) -> Path:
    payload_dir = tmp_path / f"payload-{lane}"
    payload_dir.mkdir()
    for payload_name in payload_names:
        payload_path = payload_dir / payload_name
        payload_path.parent.mkdir(parents=True, exist_ok=True)
        payload_path.write_bytes(payload_bytes)
    out_dir = tmp_path / f"bundle-{lane}"
    out_dir.mkdir()
    built = builder.build_bundle(
        input_dir=payload_dir,
        payload_names=list(payload_names),
        artifact_kind=kind,
        repository="wiki-spike/wiki-spike",
        producer_commit=producer_commit,
        contract_digest=ZERO64,
        toolchain_lock_digest=ZERO64,
        workflow_file_digest=ZERO64,
        workflow_run_id="1",
        workflow_run_attempt="1",
        platform_token={
            "GATE1_DECISION": "self-hosted/macos-26/arm64/wiki-gate1-workstation",
            "CONFORMANCE_PRE_CANARY": "self-hosted/macos-26/arm64/wiki-conformance-workstation",
            "CANARY_24H": "self-hosted/macos-26/arm64/wiki-canary-workstation",
        }[kind],
        produced_at="2026-01-01T00:00:00Z",
    )
    (out_dir / builder.ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
    (out_dir / builder.MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])
    tar_files = [
        (builder.ENVELOPE_ENTRY_PATH, built["envelope_bytes"]),
        (builder.MANIFEST_ENTRY_PATH, built["manifest_bytes"]),
    ]
    for rel, data in built["payload_bytes"].items():
        tar_files.append((rel, data))
    builder.write_deterministic_tar(out_dir / f"{built['artifact_name']}.tar", tar_files)
    return out_dir


@pytest.fixture()
def lane_dirs(tmp_path: Path) -> dict[str, Path]:
    return {
        lane: _build_lane(
            tmp_path,
            lane,
            kind,
            name,
            _payload(lane),
            producer_commit=GATE1_COMMIT if lane == "gate1" else COMMIT,
        )
        for lane, kind, name in _LANES
    }


def test_join_produces_verdict_free_manifest_and_evidence_join(tmp_path: Path, lane_dirs: dict[str, Path]):
    out_dir = tmp_path / "joined"
    rc = joiner.main(_join_args(lane_dirs, out_dir))
    assert rc == 0

    manifest = json.loads((out_dir / "pre-review-manifest.json").read_text(encoding="utf-8"))
    join = json.loads((out_dir / "evidence-join.json").read_text(encoding="utf-8"))

    # Verdict-free: no verdict/pass/fail field in the manifest.
    assert "verdict" not in json.dumps(manifest).lower()
    assert manifest["schema"] == "wiki-gate8-pre-review-manifest-v1"
    assert manifest["implementation_commit"] == COMMIT
    assert {b["lane"] for b in manifest["bundles"]} == {"gate1", "conformance", "canary"}

    # Evidence join preserves the three independent import receipts.
    assert join["schema"] == "wiki-gate8-evidence-join-v1"
    assert {r["lane"] for r in join["import_receipts"]} == {"gate1", "conformance", "canary"}
    assert join["manifest_digest"] == manifest["manifest_digest"]
    assert len(join["join_digest"]) == 64
    for r in join["import_receipts"]:
        assert r["receipt"]["verified"] is True
        assert r["receipt"]["source_run_url"].startswith("https://github.example/")
    for bundle in manifest["bundles"]:
        assert bundle["receipt"] == next(item["receipt"] for item in join["import_receipts"] if item["lane"] == bundle["lane"])


def test_join_rejects_conformance_canary_commit_mismatch(tmp_path: Path, lane_dirs: dict[str, Path]):
    bad = _build_lane(
        tmp_path,
        "canary-bad",
        "CANARY_24H",
        ("payload/rollout-evidence.json",),
        _payload("canary"),
        producer_commit="ef" * 20,
    )
    assert joiner.main(_join_args({**lane_dirs, "canary": bad}, tmp_path / "joined-bad")) == 1


def test_join_rejects_noncanonical_duration_schedule_and_provenance(tmp_path: Path, lane_dirs: dict[str, Path]):
    for field, value in (
        ("observed_duration_seconds", "86400"),
        ("started_at_epoch", "01767225600.000"),
        ("provenance", {}),
    ):
        payload = json.loads(_payload("canary"))
        payload[field] = value
        root = tmp_path / f"invalid-{field}"
        root.mkdir()
        bad = _build_lane(
            root, "canary", "CANARY_24H", ("payload/rollout-evidence.json",),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            producer_commit=COMMIT,
        )
        assert joiner.main(_join_args({**lane_dirs, "canary": bad}, tmp_path / f"joined-{field}")) == 1
def test_join_rejects_artifact_tuple_mismatch(tmp_path: Path, lane_dirs: dict[str, Path]):
    args = _join_args(lane_dirs, tmp_path / "wrong-tuple")
    args[args.index("--conformance-artifact-name") + 1] = "wrong-artifact"
    assert joiner.main(args) == 1
def test_join_rejects_swapped_lane_and_wrong_expected_tuple(tmp_path: Path, lane_dirs: dict[str, Path]):
    swapped = _join_args({**lane_dirs, "gate1": lane_dirs["conformance"], "conformance": lane_dirs["gate1"]}, tmp_path / "swapped")
    assert joiner.main(swapped) == 1

    wrong_digest = _join_args(lane_dirs, tmp_path / "wrong-digest")
    wrong_digest[wrong_digest.index("--contract-digest") + 1] = "1" * 64
    assert joiner.main(wrong_digest) == 1


def test_join_rejects_shortened_or_unhealthy_canary(tmp_path: Path, lane_dirs: dict[str, Path]):
    for field, value in (("configured_duration_seconds", "86399"), ("healthy", False)):
        payload = json.loads(_payload("canary"))
        payload[field] = value
        case_root = tmp_path / field
        case_root.mkdir()
        bad = _build_lane(
            case_root,
            "canary",
            "CANARY_24H",
        ("payload/rollout-evidence.json",),
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            producer_commit=COMMIT,
        )
        assert joiner.main(_join_args({**lane_dirs, "canary": bad}, tmp_path / f"bad-{field}")) == 1


def test_join_preserves_all_three_receipts(tmp_path: Path, lane_dirs: dict[str, Path]):
    out_dir = tmp_path / "receipts"
    assert joiner.main(_join_args(lane_dirs, out_dir)) == 0
    receipts = json.loads((out_dir / "evidence-join.json").read_text(encoding="utf-8"))["import_receipts"]
    assert len(receipts) == 3
    assert [item["lane"] for item in receipts] == ["gate1", "conformance", "canary"]
def test_join_rejects_non_passing_gate1_and_conformance_payloads(tmp_path: Path, lane_dirs: dict[str, Path]):
    for lane, field, value in (("gate1", "profile_selection", "X"), ("conformance", "conformant", False)):
        payload = json.loads(_payload(lane))
        payload[field] = value
        root = tmp_path / f"{lane}-{field}"
        root.mkdir()
        kind = next(kind for name, kind, _paths in _LANES if name == lane)
        paths = next(paths for name, _kind, paths in _LANES if name == lane)
        bad = _build_lane(
            root, lane, kind, paths,
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
            producer_commit=GATE1_COMMIT if lane == "gate1" else COMMIT,
        )
        assert joiner.main(_join_args({**lane_dirs, lane: bad}, tmp_path / f"bad-{lane}")) == 1

def test_join_rejects_external_repository_or_source_mismatch(tmp_path: Path, lane_dirs: dict[str, Path]):
    args = _join_args(lane_dirs, tmp_path / "wrong-source")
    args[args.index("--gate1-repository") + 1] = "other/repository"
    assert joiner.main(args) == 1
def _workflow_steps(path: Path) -> list[dict[str, str]]:
    """Parse the workflow step list needed by these contract tests."""
    steps: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    run_lines: list[str] = []
    in_run = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("      - name: "):
            if current is not None:
                if run_lines:
                    current["run"] = "\n".join(run_lines)
                steps.append(current)
            current = {"name": line.removeprefix("      - name: ").strip()}
            run_lines = []
            in_run = False
        elif current is not None and line.startswith("        uses: "):
            current["uses"] = line.removeprefix("        uses: ").strip()
        elif current is not None and line.startswith("        id: "):
            current["id"] = line.removeprefix("        id: ").strip()
        elif current is not None and line.startswith("          name: "):
            current["artifact_name"] = line.removeprefix("          name: ").strip()
        elif current is not None and line.startswith("          path: "):
            current["artifact_path"] = line.removeprefix("          path: ").strip()
        elif current is not None and line.startswith("        run: |"):
            in_run = True
        elif current is not None and in_run:
            if line.startswith("          "):
                run_lines.append(line.removeprefix("          "))
            elif line.strip():
                in_run = False
    if current is not None:
        if run_lines:
            current["run"] = "\n".join(run_lines)
        steps.append(current)
    return steps


def _step(steps: list[dict[str, str]], name: str) -> dict[str, str]:
    return next(step for step in steps if step["name"] == name)


def _command_arguments(run: str, executable: str) -> list[str]:
    lines = run.splitlines()
    index = next(index for index, line in enumerate(lines) if executable in line)
    command = lines[index]
    while command.rstrip().endswith("\\"):
        index += 1
        command += " " + lines[index].strip()
    return shlex.split(command.replace("\\", ""))[2:]


def test_dispatch_workflow_requires_explicit_lane_tuples_and_distinct_workflow_sources():
    workflow_path = REPO_ROOT / ".github/workflows/encrypted-lifecycle-evidence-join.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    assert re.search(r"(?m)^on:\n  workflow_dispatch:\n    inputs:", workflow)
    for lane in ("gate1", "conformance", "canary"):
        for field in ("run_id", "run_attempt", "artifact_name", "bundle_sha256"):
            assert re.search(rf"(?m)^      {lane}_{field}:", workflow)
    steps = _workflow_steps(workflow_path)
    join_args = _command_arguments(
        _step(steps, "Strict-import each explicit lane once and build verdict-free join")["run"],
        "scripts/join_gate8_evidence.py",
    )
    for lane in ("gate1", "conformance", "canary"):
        assert f"--{lane}-repository" in join_args
        assert f"--{lane}-source-run-url" in join_args
    assert {"encrypted-lifecycle-gate1-decision.yml", "encrypted-lifecycle-conformance.yml", "encrypted-lifecycle-canary.yml"} <= set(re.findall(r"encrypted-lifecycle-[\w-]+\.yml", workflow))


def test_workflow_contracts_pin_actions_bind_commits_and_upload_derived_artifacts():
    workflows = {
        "gate1": REPO_ROOT / ".github/workflows/encrypted-lifecycle-gate1-decision.yml",
        "conformance": REPO_ROOT / ".github/workflows/encrypted-lifecycle-conformance.yml",
        "canary": REPO_ROOT / ".github/workflows/encrypted-lifecycle-canary.yml",
        "join": REPO_ROOT / ".github/workflows/encrypted-lifecycle-evidence-join.yml",
        "feasibility": REPO_ROOT / ".github/workflows/encrypted-lifecycle-sqlcipher-feasibility.yml",
    }
    canonical = {
        "gate1": "inputs.gate1_commit",
        "conformance": "inputs.implementation_commit",
        "canary": "inputs.implementation_commit",
        "join": "IMPLEMENTATION_COMMIT",
        "feasibility": "inputs.implementation_commit",
    }
    for lane, path in workflows.items():
        steps = _workflow_steps(path)
        for step in steps:
            if "uses" in step:
                assert re.fullmatch(r"actions/(?:checkout|setup-python|download-artifact|upload-artifact)@[0-9a-f]{40}", step["uses"])
            if "run" in step:
                subprocess.run(["bash", "-n"], input=step["run"], text=True, check=True)
        verify = next(step["run"] for step in steps if step["name"].startswith("Verify"))
        assert "github.sha" in verify and canonical[lane] in verify
        assert "git symbolic-ref -q HEAD" in verify
        assert "git rev-parse HEAD" in verify and canonical[lane] in verify
    gate1_args = _command_arguments(
        _step(_workflow_steps(workflows["gate1"]), "Strictly import and bind exact Ubuntu tuple")["run"],
        "scripts/validate_encrypted_lifecycle_gate1_decision.py",
    )
    assert {"--producer-commit", "--contract-digest", "--toolchain-lock-digest"} <= set(gate1_args)

    canary_steps = _workflow_steps(workflows["canary"])
    bundle = _step(canary_steps, "Run exact 24-hour canary and build immutable bundle")
    upload = _step(canary_steps, "Upload immutable CANARY_24H bundle")
    assert bundle["id"] == "bundle"
    assert '["artifact_name"]' in bundle["run"]
    assert upload["artifact_name"] == "${{ steps.bundle.outputs.artifact_name }}"
    assert upload["artifact_path"] == "artifacts/encrypted-lifecycle/canary/${{ steps.bundle.outputs.artifact_name }}.tar"
