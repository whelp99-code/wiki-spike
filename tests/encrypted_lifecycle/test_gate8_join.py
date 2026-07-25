"""Gate 8 three-lane evidence join integration test.

Builds three immutable bundles (gate1/conformance/canary) bound to one
producer commit, runs scripts/join_gate8_evidence.py over them, and asserts
the verdict-free pre-review manifest + evidence join are produced correctly.
"""
from __future__ import annotations

import json
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

COMMIT = "ab" * 20
ZERO64 = "0" * 64

_LANES = [
    ("gate1", "GATE1_DECISION", "gate1-decision.json", b'{"schema":"wiki-gate1-decision-v1"}'),
    ("conformance", "CONFORMANCE_PRE_CANARY", "conformance-report.json", b'{"schema":"wiki-gate8-conformance-report-v1"}'),
    ("canary", "CANARY_24H", "canary-report.json", b'{"schema":"wiki-gate8-canary-report-v1"}'),
]


def _build_lane(tmp_path: Path, lane: str, kind: str, payload_name: str, payload_bytes: bytes) -> Path:
    payload_dir = tmp_path / f"payload-{lane}"
    payload_dir.mkdir()
    (payload_dir / payload_name).write_bytes(payload_bytes)
    out_dir = tmp_path / f"bundle-{lane}"
    out_dir.mkdir()
    built = builder.build_bundle(
        input_dir=payload_dir,
        payload_names=[payload_name],
        artifact_kind=kind,
        repository="wiki-spike",
        producer_commit=COMMIT,
        contract_digest=ZERO64,
        toolchain_lock_digest=ZERO64,
        workflow_file_digest=ZERO64,
        workflow_run_id="1",
        workflow_run_attempt="1",
        platform_token=f"self-hosted/macos-15/arm64/wiki-{lane}-workstation",
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
        lane: _build_lane(tmp_path, lane, kind, name, data)
        for lane, kind, name, data in _LANES
    }


def test_join_produces_verdict_free_manifest_and_evidence_join(tmp_path: Path, lane_dirs: dict[str, Path]):
    out_dir = tmp_path / "joined"
    rc = joiner.main([
        "--gate1", str(lane_dirs["gate1"]),
        "--conformance", str(lane_dirs["conformance"]),
        "--canary", str(lane_dirs["canary"]),
        "--workspace-id", "ws-test-1",
        "--output-dir", str(out_dir),
    ])
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


def test_join_rejects_producer_commit_mismatch(tmp_path: Path, lane_dirs: dict[str, Path]):
    # Rebuild the canary lane bound to a DIFFERENT commit.
    payload_dir = tmp_path / "payload-canary-bad"
    payload_dir.mkdir()
    (payload_dir / "canary-report.json").write_bytes(b'{"schema":"wiki-gate8-canary-report-v1"}')
    bad_dir = tmp_path / "bundle-canary-bad"
    bad_dir.mkdir()
    built = builder.build_bundle(
        input_dir=payload_dir,
        payload_names=["canary-report.json"],
        artifact_kind="CANARY_24H",
        repository="wiki-spike",
        producer_commit="cd" * 20,  # different commit
        contract_digest=ZERO64,
        toolchain_lock_digest=ZERO64,
        workflow_file_digest=ZERO64,
        workflow_run_id="1",
        workflow_run_attempt="1",
        platform_token="self-hosted/macos-15/arm64/wiki-canary-workstation",
        produced_at="2026-01-01T00:00:00Z",
    )
    (bad_dir / builder.ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
    (bad_dir / builder.MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])
    builder.write_deterministic_tar(
        bad_dir / f"{built['artifact_name']}.tar",
        [
            (builder.ENVELOPE_ENTRY_PATH, built["envelope_bytes"]),
            (builder.MANIFEST_ENTRY_PATH, built["manifest_bytes"]),
            *built["payload_bytes"].items(),
        ],
    )

    out_dir = tmp_path / "joined-bad"
    rc = joiner.main([
        "--gate1", str(lane_dirs["gate1"]),
        "--conformance", str(lane_dirs["conformance"]),
        "--canary", str(bad_dir),
        "--workspace-id", "ws-test-1",
        "--output-dir", str(out_dir),
    ])
    assert rc == 1
    assert not (out_dir / "pre-review-manifest.json").exists()
