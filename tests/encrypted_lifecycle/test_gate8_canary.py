"""Gate 8 24h canary runner tests (short-duration).

The production canary runs for exactly 24 hours on a self-hosted macOS runner;
these tests exercise the same probe/loop code with a short duration.
"""
from __future__ import annotations

import json
import sys
import time
from decimal import Decimal
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import run_encrypted_lifecycle_canary_24h as canary  # noqa: E402
from import_encrypted_lifecycle_bundle import import_bundle  # noqa: E402


def test_single_probe_roundtrip_passes():
    result = canary.run_probe(0)
    assert result["passed"] is True, result["error"]
    assert result["error"] is None


def test_secure_directory_creation_is_idempotent_but_rejects_symlinks(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    canary._require_secure_directory(state, create=True)

    link = tmp_path / "state-link"
    link.symlink_to(state, target_is_directory=True)
    with pytest.raises(ValueError, match="not a directory"):
        canary._require_secure_directory(link, create=True)


def test_short_canary_is_healthy_but_is_simulation():
    # duration 0 -> exactly one probe, no sleep.
    report = canary.run_canary(duration_seconds=0, interval_seconds=1)
    assert report["schema"] == canary.REPORT_SCHEMA
    assert report["evidence_lane"] == "CANARY_SIMULATION"
    assert report["healthy"] is True
    assert report["probe_count"] == "1"
    assert report["failure_count"] == "0"
    assert all(p["passed"] for p in report["probes"])


def test_wait_for_scheduled_probe_retries_an_early_wake(monkeypatch):
    wall_times = iter((100.999, 101.000))
    sleeps: list[float] = []
    monkeypatch.setattr(canary.time, "time", lambda: next(wall_times))
    monkeypatch.setattr(canary.time, "monotonic", lambda: 0.999)
    monkeypatch.setattr(canary.time, "sleep", sleeps.append)

    canary._wait_for_scheduled_probe(
        scheduled_at=Decimal("101.000"),
        last_observed=Decimal("100.000"),
        interval_seconds=10,
        monotonic_origin=0.0,
        wall_origin=Decimal("100.000"),
    )

    assert sleeps
    assert sleeps[0] >= 0.001


@pytest.mark.parametrize(
    ("now", "message"),
    ((Decimal("99.999"), "rollback"), (Decimal("111.000"), "skipped")),
)
def test_wait_for_scheduled_probe_rejects_clock_rollback_and_skipped_window(
    monkeypatch, now, message
):
    monkeypatch.setattr(canary.time, "time", lambda: float(now))
    monkeypatch.setattr(canary.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(
        canary.time,
        "sleep",
        lambda _delay: pytest.fail("invalid clock state must fail before sleeping"),
    )

    with pytest.raises(ValueError, match=message):
        canary._wait_for_scheduled_probe(
            scheduled_at=Decimal("101.000"),
            last_observed=Decimal("100.000"),
            interval_seconds=10,
            monotonic_origin=0.0,
            wall_origin=Decimal("100.000"),
        )


def test_canary_report_records_failures(monkeypatch):
    # A failing probe must mark the canary unhealthy (fail-closed reporting).
    def _failing_probe(_index: int) -> dict:
        return {"probe_index": "0", "passed": False, "error": "simulated", "elapsed_seconds": "0.001"}

    monkeypatch.setattr(canary, "run_probe", _failing_probe)
    report = canary.run_canary(duration_seconds=0, interval_seconds=1)
    assert report["healthy"] is False
    assert report["failure_count"] == "1"


def _production_report(*, observed_duration_seconds: str = "86400", probe_count: int = 97) -> dict:
    return {
        "configured_duration_seconds": "86400",
        "interval_seconds": "900",
        "observed_duration_seconds": observed_duration_seconds,
        "healthy": True,
        "failure_count": "0",
        "probe_count": str(probe_count),
        "probes": [
            {"probe_index": str(index), "passed": True}
            for index in range(probe_count)
        ],
    }


@pytest.mark.parametrize(
    ("duration_seconds", "interval_seconds"),
    [
        ("0", "900"),
        ("60", "900"),
        ("86400", "0"),
        ("86400", "60"),
        ("86400", "0900"),
    ],
)
def test_production_canary_rejects_non_exact_configuration(
    duration_seconds: str, interval_seconds: str
):
    with pytest.raises(ValueError):
        canary._require_production_canary_contract(
            _production_report(), duration_seconds, interval_seconds
        )


@pytest.mark.parametrize(
    "report",
    [
        _production_report(observed_duration_seconds="86399.999"),
        _production_report(probe_count=96),
        _production_report(probe_count=98),
        {
            **_production_report(),
            "probes": [
                *(_production_report()["probes"][:96]),
                {"probe_index": "95", "passed": True},
            ],
        },
        {
            **_production_report(),
            "probes": [
                *(_production_report()["probes"][:96]),
                {"probe_index": "96", "passed": False},
            ],
        },
    ],
)
def test_production_canary_rejects_insufficient_observed_coverage(report: dict):
    with pytest.raises(ValueError):
        canary._require_production_canary_contract(report, "86400", "900")


def test_production_canary_accepts_exact_observed_contract():
    report = _production_report()
    canary._require_production_canary_contract(report, "86400", "900")

def test_canary_workflow_is_a_dedicated_macos_producer():
    workflow = (
        REPO_ROOT / ".github/workflows/encrypted-lifecycle-canary.yml"
    ).read_text(encoding="utf-8")

    assert "runs-on: [self-hosted, macOS, ARM64, wiki-canary-workstation]" in workflow
    assert "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" in workflow
    assert "actions/setup-python@" not in workflow
    assert "Bind service-owned Python 3.12" in workflow
    assert 'python_bin="$(command -v python3.12)"' in workflow
    assert 'ln -sf "$python_bin" "$shim_dir/python3"' in workflow
    assert 'echo "$shim_dir" >> "$GITHUB_PATH"' in workflow
    assert "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02" in workflow
    assert "implementation_commit:" in workflow
    assert 'ref: ${{ inputs.implementation_commit }}' in workflow
    assert 'test "$(git symbolic-ref -q HEAD || true)" = ""' in workflow
    assert 'test "$(git rev-parse HEAD)" = "${{ inputs.implementation_commit }}"' in workflow
    assert 'test "$(uname -s)" = "Darwin"' in workflow
    assert 'test "$(uname -r | cut -d. -f1)" = "25"' in workflow
    assert 'case "$(sw_vers -productVersion)" in 26.*)' in workflow
    assert "26.*) ;; *)" in workflow
    assert 'test "$(uname -m)" = "arm64"' in workflow
    assert "import_bundle(Path(sys.argv[1]), expected=expected)" in workflow
    assert "canary-expected-tuple.json" in workflow
    assert 'path: artifacts/encrypted-lifecycle/canary/${{ steps.bundle.outputs.artifact_name }}.tar' in workflow
    assert "artifacts/encrypted-lifecycle/canary/*.tar" not in workflow
    assert "path: artifacts/encrypted-lifecycle/canary/canary-" not in workflow
    assert "--implementation-commit" in workflow
    assert "--durable-state-root" in workflow
    assert "CANARY_DURABLE_STATE_ROOT" in workflow
    assert "durable-resume-simulation-${{ github.run_id }}-${{ github.run_attempt }}" in workflow
    assert "resume_checkpoint_artifact_id" not in workflow
    assert "Download exact immutable resume checkpoint" not in workflow
    assert "Simulate durable interruption and automatic recovery" in workflow
    assert "--duration-seconds 4 --interval-seconds 2" in workflow
    assert "--duration-seconds 0" not in workflow
def test_checkpoint_rejects_tamper_reorder_stale_and_binding_mismatch(tmp_path):
    path = tmp_path / "checkpoint.json"
    binding = canary._checkpoint_binding(
        repository="owner/repo",
        workflow_run_id="1",
        workflow_run_attempt="1",
        implementation_commit="a" * 40,
        workflow_file_digest="b" * 64,
        contract_digest="c" * 64,
        toolchain_lock_digest="d" * 64,
        platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
    )
    started = time.time() - 1
    checkpoint = {
        "schema": canary.CHECKPOINT_SCHEMA,
        "binding": binding,
        "state": "incomplete",
        "duration_seconds": "900",
        "interval_seconds": "900",
        "started_at_epoch": canary._canonical_epoch(started),
        "deadline_at_epoch": canary._canonical_epoch(started + 900),
        "next_probe_index": "1",
        "next_probe_at_epoch": canary._canonical_epoch(started + 900),
        "last_observed_epoch": canary._canonical_epoch(started),
        "probes": [{
            "probe_index": "0", "passed": True, "error": None, "elapsed_seconds": "0.001",
            "scheduled_at_epoch": canary._canonical_epoch(started), "completed_at_epoch": canary._canonical_epoch(started),
        }],
        "probe_history_sha256": "",
        "prior_checkpoint_sha256": canary._CHECKPOINT_GENESIS_SHA256,
        "checkpoint_sha256": "",
    }
    canary._write_checkpoint(path, checkpoint)
    loaded = canary._load_checkpoint(path, binding, 900, 900)
    assert loaded["checkpoint_sha256"] == checkpoint["checkpoint_sha256"]
    wire = json.loads(path.read_text())
    assert isinstance(wire["next_probe_index"], str)
    assert all(isinstance(wire[field], str) for field in (
        "started_at_epoch", "deadline_at_epoch", "next_probe_at_epoch", "last_observed_epoch",
    ))

    raw_number = json.loads(path.read_text())
    raw_number["next_probe_index"] = 1
    path.write_text(json.dumps(raw_number))
    with pytest.raises(ValueError, match="canonical decimal string"):
        canary._load_checkpoint(path, binding, 900, 900)
    canary._write_checkpoint(path, checkpoint)

    tampered = json.loads(path.read_text())
    tampered["probes"][0]["passed"] = False
    path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="tampered"):
        canary._load_checkpoint(path, binding, 900, 900)

    canary._write_checkpoint(path, checkpoint)
    reordered = json.loads(path.read_text())
    reordered["probes"][0]["probe_index"] = "1"
    reordered["probe_history_sha256"] = canary.hashlib.sha256(
        canary.canonical_bytes(reordered["probes"])
    ).hexdigest()
    reordered["checkpoint_sha256"] = canary._canonical_checkpoint_digest(reordered)
    path.write_text(json.dumps(reordered))
    with pytest.raises(ValueError, match="reordered"):
        canary._load_checkpoint(path, binding, 900, 900)

    checkpoint["last_observed_epoch"] = canary._canonical_epoch(time.time() + 1)
    canary._write_checkpoint(path, checkpoint)
    with pytest.raises(ValueError, match="rollback"):
        canary._load_checkpoint(path, binding, 900, 900)
    for field, value in (
        ("repository", "other/repo"),
        ("original_workflow_run_id", "other-run"),
        ("implementation_commit", "e" * 40),
        ("workflow_file_digest", "e" * 64),
        ("contract_digest", "e" * 64),
        ("toolchain_lock_digest", "e" * 64),
        ("platform", "other-platform"),
    ):
        with pytest.raises(ValueError, match="bound"):
            canary._load_checkpoint(path, {**binding, field: value}, 900, 900)
def test_checkpoint_resume_accepts_new_attempt_but_rejects_cross_run_and_skipped_probe(tmp_path, monkeypatch):
    path = tmp_path / "checkpoint.json"
    binding = canary._checkpoint_binding(
        repository="owner/repo",
        workflow_run_id="original-run",
        workflow_run_attempt="1",
        implementation_commit="a" * 40,
        workflow_file_digest="b" * 64,
        contract_digest="c" * 64,
        toolchain_lock_digest="d" * 64,
        platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
    )
    started = 1_000.0
    checkpoint = {
        "schema": canary.CHECKPOINT_SCHEMA, "binding": binding, "state": "incomplete",
        "duration_seconds": "900", "interval_seconds": "900",
        "started_at_epoch": canary._canonical_epoch(started), "deadline_at_epoch": canary._canonical_epoch(started + 900),
        "next_probe_index": "0", "next_probe_at_epoch": canary._canonical_epoch(started),
        "last_observed_epoch": canary._canonical_epoch(started), "probes": [],
        "probe_history_sha256": "", "prior_checkpoint_sha256": canary._CHECKPOINT_GENESIS_SHA256,
        "checkpoint_sha256": "",
    }
    canary._write_checkpoint(path, checkpoint)
    monkeypatch.setattr(canary.time, "time", lambda: started + 1)
    resumed = canary._load_checkpoint(
        path, {**binding, "workflow_run_attempt": "2"}, 900, 900
    )
    assert "started_at_monotonic" not in resumed
    with pytest.raises(ValueError, match="bound"):
        canary._load_checkpoint(
            path, {**binding, "original_workflow_run_id": "other-run"}, 900, 900
        )

    monkeypatch.setattr(canary.time, "time", lambda: started + 900)
    with pytest.raises(ValueError, match="skipped"):
        canary._load_checkpoint(path, {**binding, "workflow_run_attempt": "2"}, 900, 900)
def test_durable_resume_advances_workflow_attempt_without_mutating_immutable_provenance(tmp_path, monkeypatch):
    class Clock:
        now = 1_000.0

        def time(self):
            return self.now

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    clock = Clock()
    monkeypatch.setattr(canary.time, "time", clock.time)
    monkeypatch.setattr(canary.time, "monotonic", clock.monotonic)
    monkeypatch.setattr(canary.time, "sleep", clock.sleep)
    monkeypatch.setattr(
        canary,
        "run_probe",
        lambda index: {
            "probe_index": str(index), "passed": True, "error": None, "elapsed_seconds": "0.000"
        },
    )
    root = tmp_path.resolve()
    attempt_one = canary._checkpoint_binding(
        repository="owner/repo",
        workflow_run_id="stable-run-id",
        workflow_run_attempt="1",
        implementation_commit="a" * 40,
        workflow_file_digest="b" * 64,
        contract_digest="c" * 64,
        toolchain_lock_digest="d" * 64,
        platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
    )
    with pytest.raises(InterruptedError, match="simulated interruption"):
        canary.run_canary(
            1, 1, durable_state_root=root, checkpoint_binding=attempt_one, interrupt_after_probe=0
        )

    attempt_two = {**attempt_one, "workflow_run_attempt": "2"}
    with pytest.raises(ValueError, match="reused"):
        canary._discover_durable_checkpoint(root, attempt_one, 1, 1)
    with pytest.raises(ValueError, match="skipped"):
        canary._discover_durable_checkpoint(
            root, {**attempt_one, "workflow_run_attempt": "3"}, 1, 1
        )
    with pytest.raises(ValueError, match="wrong binding"):
        canary._discover_durable_checkpoint(
            root, {**attempt_two, "platform": "other-platform"}, 1, 1
        )

    report = canary.run_canary(1, 1, durable_state_root=root, checkpoint_binding=attempt_two)
    assert report["probe_count"] == "2"
    state_dir = canary._durable_state_directory(root, attempt_two, create=False)
    terminal = canary._load_durable_chain(
        state_dir, canary._static_binding(attempt_two), 1, 1
    )
    assert terminal["binding"]["workflow_run_attempt"] == "2"
def test_durable_discovery_isolated_by_original_run_and_rejects_completed_replay(tmp_path):
    root = tmp_path.resolve()
    binding = canary._checkpoint_binding(
        repository="owner/repo", workflow_run_id="run-1", workflow_run_attempt="1",
        implementation_commit="a" * 40, workflow_file_digest="b" * 64,
        contract_digest="c" * 64, toolchain_lock_digest="d" * 64,
        platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
    )
    canary.run_canary(0, 1, durable_state_root=root, checkpoint_binding=binding)
    with pytest.raises(ValueError, match="cannot be replayed"):
        canary._discover_durable_checkpoint(root, binding, 0, 1)
    assert canary._discover_durable_checkpoint(
        root, {**binding, "original_workflow_run_id": "run-2"}, 0, 1
    ) is None
def _durable_checkpoint(
    binding: dict[str, str],
    *,
    state: str = "incomplete",
    prior: str = canary._CHECKPOINT_GENESIS_SHA256,
    next_probe_index: str = "1",
    passed: bool = True,
) -> dict:
    started = 1_000.0
    probes = [{
        "probe_index": "0",
        "passed": passed,
        "error": None if passed else "simulated",
        "elapsed_seconds": "0.001",
        "scheduled_at_epoch": canary._canonical_epoch(started),
        "completed_at_epoch": canary._canonical_epoch(started),
    }]
    return {
        "schema": canary.CHECKPOINT_SCHEMA,
        "binding": binding,
        "state": state,
        "duration_seconds": "0",
        "interval_seconds": "1",
        "started_at_epoch": canary._canonical_epoch(started),
        "deadline_at_epoch": canary._canonical_epoch(started),
        "next_probe_index": next_probe_index,
        "next_probe_at_epoch": canary._canonical_epoch(started),
        "last_observed_epoch": canary._canonical_epoch(started),
        "probes": probes,
        "probe_history_sha256": "",
        "prior_checkpoint_sha256": prior,
        "checkpoint_sha256": "",
    }


def _durable_chain_directory(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    binding = canary._checkpoint_binding(
        repository="owner/repo",
        workflow_run_id="run-1",
        workflow_run_attempt="1",
        implementation_commit="a" * 40,
        workflow_file_digest="b" * 64,
        contract_digest="c" * 64,
        toolchain_lock_digest="d" * 64,
        platform="self-hosted/macos-26/arm64/wiki-canary-workstation",
    )
    return canary._durable_state_directory(tmp_path.resolve(), binding, create=True), binding


def test_durable_chain_selects_same_index_terminal_successor_and_replays_completed(tmp_path, monkeypatch):
    state_dir, binding = _durable_chain_directory(tmp_path)
    incomplete = _durable_checkpoint(binding)
    canary._persist_durable_checkpoint(state_dir, incomplete)
    terminal = _durable_checkpoint(
        binding, state="terminal-issued", prior=incomplete["checkpoint_sha256"]
    )
    canary._persist_durable_checkpoint(state_dir, terminal)

    monkeypatch.setattr(canary.time, "time", lambda: 2_000.0)
    loaded = canary._load_durable_chain(state_dir, canary._static_binding(binding), 0, 1)
    assert loaded["checkpoint_sha256"] == terminal["checkpoint_sha256"]
    with pytest.raises(ValueError, match="cannot be replayed"):
        canary._discover_durable_checkpoint(tmp_path.resolve(), binding, 0, 1)


@pytest.mark.parametrize("kind", ["fork", "orphan", "cycle", "multiple-leaves"])
def test_durable_chain_rejects_non_linear_authenticated_graphs(tmp_path, kind):
    state_dir, binding = _durable_chain_directory(tmp_path)
    genesis = _durable_checkpoint(binding)
    canary._persist_durable_checkpoint(state_dir, genesis)

    if kind in {"fork", "multiple-leaves"}:
        first = _durable_checkpoint(
            binding, state="terminal-issued", prior=genesis["checkpoint_sha256"]
        )
        second = _durable_checkpoint(
            binding, state="failed", prior=genesis["checkpoint_sha256"], passed=False
        )
        canary._persist_durable_checkpoint(state_dir, first)
        canary._persist_durable_checkpoint(state_dir, second)
        expected = "fork"
    elif kind == "orphan":
        orphan = _durable_checkpoint(binding, state="terminal-issued", prior="f" * 64)
        canary._persist_durable_checkpoint(state_dir, orphan)
        expected = "orphan"
    else:
        cycle = _durable_checkpoint(binding, state="terminal-issued")
        canary._persist_durable_checkpoint(state_dir, cycle)
        path = state_dir / f"checkpoint-{cycle['next_probe_index']}-{cycle['checkpoint_sha256']}.json"
        wire = json.loads(path.read_text(encoding="utf-8"))
        wire["prior_checkpoint_sha256"] = wire["checkpoint_sha256"]
        path.write_text(json.dumps(wire), encoding="utf-8")
        expected = "tampered"

    with pytest.raises(ValueError, match=expected):
        canary._load_durable_chain(state_dir, canary._static_binding(binding), 0, 1)


def test_durable_chain_rejects_duplicate_checkpoint_digest(tmp_path):
    state_dir, binding = _durable_chain_directory(tmp_path)
    checkpoint = _durable_checkpoint(binding)
    canary._persist_durable_checkpoint(state_dir, checkpoint)
    duplicate = state_dir / f"checkpoint-1-{'0' * 64}.json"
    duplicate.write_bytes(
        canary.canonical_bytes({**checkpoint, "checkpoint_sha256": checkpoint["checkpoint_sha256"]})
    )
    duplicate.chmod(0o600)

    with pytest.raises(ValueError, match="filename is tampered|duplicate digest"):
        canary._load_durable_chain(state_dir, canary._static_binding(binding), 0, 1)
def test_producer_issues_exact_rollout_payload_and_strictly_imports_it(tmp_path, monkeypatch):
    report = {
        **_production_report(),
        "schema": canary.REPORT_SCHEMA,
        "evidence_lane": "CANARY_24H",
        "produced_at": "2026-01-01T00:00:00Z",
        "started_at": "2025-12-31T00:00:00Z",
        "finished_at": "2026-01-01T00:00:00Z",
    }
    monkeypatch.setattr(canary, "run_canary", lambda *_args, **_kwargs: dict(report))
    monkeypatch.setattr(
        canary.subprocess,
        "run",
        lambda *_args, **_kwargs: type("Result", (), {"returncode": 0, "stdout": "a" * 40 + "\n"})(),
    )
    output = tmp_path / "output"
    bundle = tmp_path / "bundle"
    assert canary.main([
        "--duration-seconds", "86400", "--interval-seconds", "900",
        "--output-dir", str(output), "--bundle-output-dir", str(bundle),
        "--durable-state-root", str(tmp_path),
        "--repository", "owner/repo", "--workflow-run-id", "1", "--workflow-run-attempt", "1",
        "--implementation-commit", "a" * 40, "--source-run-url", "https://example.test/run/1",
        "--platform", "self-hosted/macos-26/arm64/wiki-canary-workstation",
        "--contract-digest", "b" * 64, "--toolchain-lock-digest", "c" * 64,
        "--workflow-file-digest", "d" * 64,
    ]) == 0
    expected = json.loads((bundle / "canary-expected-tuple.json").read_text())
    archive = next(bundle.glob("*.tar"))
    receipt = import_bundle(archive, expected=expected)
    assert receipt["payload_paths"] == ["payload/rollout-evidence.json"]
    payload_path = output / "rollout-evidence.json"
    assert payload_path.is_file()
    assert payload_path.read_bytes() == canary.canonical_bytes(
        json.loads(payload_path.read_text(encoding="utf-8"))
    )