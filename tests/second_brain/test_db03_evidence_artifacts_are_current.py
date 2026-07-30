"""Committed evidence artifacts must describe the code that is actually here.

These artifacts exist to be cited: `gjc ultragoal review` reads the executorQa
file, and a reviewer reads the test and adversarial reports. That makes them
worse than useless when they go stale, because a stale artifact still looks like
evidence and still passes a validator that only checks its shape.

This is not hypothetical. The committed test report sat at 166 tests across six
suites for nine commits while the suite grew to ten suites, and the review
verdict kept passing against it the whole time. Nothing noticed, because nothing
compared the claim to reality.

So: declared counts are checked against a live run, and declared totals against
their own parts. The counts are the dangerous claim -- a reviewer reads "270
passed" and believes the suite that produced it exists.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = ROOT / "artifacts" / "second-brain"
TEST_REPORT = ARTIFACTS / "db03-migration-evidence-test-report.json"
ADVERSARIAL = ARTIFACTS / "db03-migration-evidence-adversarial-report.json"
EXECUTOR_QA = ARTIFACTS / "db03-migration-evidence-executor-qa.json"
TRANSCRIPT = ARTIFACTS / "db03-migration-evidence-cli-transcript.txt"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_the_test_report_totals_match_its_own_suites():
    report = load(TEST_REPORT)
    assert report["totalPassed"] == sum(s["passed"] for s in report["suites"])
    assert report["totalFailed"] == 0


@pytest.mark.parametrize("suite", [s["suite"] for s in load(TEST_REPORT)["suites"]])
def test_every_suite_the_report_names_still_exists(suite):
    assert (ROOT / suite).is_file(), f"{suite} is named in the test report but is gone"


SELF = f"tests/second_brain/{Path(__file__).name}"


def test_the_reported_pass_counts_match_a_live_run():
    """The claim that rotted last time: a count nobody re-measured.

    This suite is excluded from its own re-run. Including it makes the check
    spawn a copy of itself, which spawns another, and the run never terminates --
    which is exactly what happened the first time it was written. Its own count
    is still covered by the totals check above.
    """
    report = load(TEST_REPORT)
    stale = []
    for entry in report["suites"]:
        if entry["suite"] == SELF:
            continue
        result = subprocess.run(
            [sys.executable, "-m", "pytest", entry["suite"], "-q", "--no-header"],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, "PYTHONPATH": "src"},
        )
        assert result.returncode == 0, f"{entry['suite']} does not pass: {result.stdout[-300:]}"
        summary = (result.stdout or "").strip().splitlines()[-1]
        actual = int(summary.split()[0]) if summary.split()[0].isdigit() else -1
        if actual != entry["passed"]:
            stale.append(f"{entry['suite']}: report says {entry['passed']}, actual {actual}")
    assert not stale, (
        "committed test report is stale; regenerate it before citing it as evidence:\n  "
        + "\n  ".join(stale)
    )


def test_the_adversarial_report_declares_what_it_contains():
    report = load(ADVERSARIAL)
    cases = report["cases"]
    assert report["adversarial_case_count"] == len(cases)
    assert report["passed"] + report["failed"] == len(cases)
    assert report["failed"] == 0
    assert len({c["id"] for c in cases}) == len(cases)
    for case in cases:
        for key in ("id", "scenario", "expectedBehavior", "observed", "verdict"):
            assert case.get(key), f"case {case.get('id')} is missing {key}"


def test_the_mutation_tally_matches_the_committed_batch_reports():
    """The adversarial report summarises the batches; the batches must agree."""
    declared = load(ADVERSARIAL)["mutationAudits"]
    total_mutants = total_caught = 0
    assert (ROOT / declared["harness"]).is_file()
    table = json.loads((ROOT / declared["mutantTable"]).read_text(encoding="utf-8"))
    for batch in declared["batches"]:
        assert batch["batch"] in table, f"{batch['batch']} is not in the mutant table"
        assert len(table[batch["batch"]]["mutants"]) == batch["mutants"]
        path = ARTIFACTS / f"db03-migration-evidence-mutation-audit-{batch['batch']}.json"
        actual = load(path)
        assert actual["mutantCount"] == batch["mutants"], f"{path.name} mutant count drifted"
        assert actual["caught"] == batch["caught"], f"{path.name} caught count drifted"
        assert actual["survived"] == 0, f"{path.name} has survivors"
        assert actual["sourceRestoredCleanly"] is True
        total_mutants += actual["mutantCount"]
        total_caught += actual["caught"]
    assert declared["totalMutants"] == total_mutants
    assert declared["totalCaught"] == total_caught


def test_the_executor_qa_evidence_references_only_artifacts_that_exist():
    qa = load(EXECUTOR_QA)
    for ref in qa["artifactRefs"]:
        assert (ROOT / ref["path"]).is_file(), f"{ref['id']} points at a missing file"
    known = {ref["id"] for ref in qa["artifactRefs"]}
    for surface in qa["surfaceEvidence"]:
        assert set(surface["artifactRefs"]) <= known
    for case in qa["adversarialCases"]:
        assert set(case["artifactRefs"]) <= known


def test_the_executor_qa_case_list_matches_the_adversarial_report():
    qa, adversarial = load(EXECUTOR_QA), load(ADVERSARIAL)
    assert [c["id"] for c in qa["adversarialCases"]] == [c["id"] for c in adversarial["cases"]]


def test_the_executor_qa_evidence_still_discloses_its_own_provenance():
    """The two facts a reviewer must be able to discount, kept in the artifact."""
    qa = load(EXECUTOR_QA)
    assert "Leader-produced" in qa["evidence"]
    replay = json.loads((ROOT / "artifacts/second-brain/db03-migration-evidence-cli-replay.json")
                        .read_text(encoding="utf-8"))
    assert replay["replaySafe"] is False
    assert "self-approved" in replay["replayExempt"]["approvedBy"]


def test_the_cli_transcript_is_a_real_terminal_capture():
    raw = TRANSCRIPT.read_bytes()
    assert bytes([27]) in raw, "no terminal control sequences: not a PTY capture"
    assert b"BOTH REPLAYS OK" in raw
