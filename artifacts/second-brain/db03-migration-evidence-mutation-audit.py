#!/usr/bin/env python3.12
"""Mutation audit: does removing each guard actually break the tests?

A test suite that stays green when a guard is deleted is decoration. This
disables one guard at a time in the shipped source, runs the targeted suites,
and records whether the suite noticed. Every mutation is reverted with
an in-memory snapshot before the next one, and the files are verified unchanged at the end.
"""
from __future__ import annotations

import atexit
import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path("/tmp/wiki-spike-native-measurement")
CONTRACTS = REPO / "src/wiki_spike/memory_core/second_brain_migration_evidence_contracts.py"
COMMON = REPO / "scripts/second_brain_evidence_common.py"
FILES = [CONTRACTS, COMMON]
SUITES = [
    "tests/second_brain/test_migration_evidence_contracts.py",
    "tests/second_brain/test_migration_source_evidence_tool.py",
    "tests/second_brain/test_migration_source_evidence_red_team.py",
    "tests/second_brain/test_db03_doc_migration_agreement.py",
]

# (label, file, exact source substring, replacement that disables the guard)
MUTANTS = [
    ("count rejects non-ASCII digits", CONTRACTS,
     "if not isinstance(value, str) or len(value) > _MAX_COUNT_DIGITS or _DECIMAL.fullmatch(value) is None:",
     "if not isinstance(value, str) or not value.isdigit():"),
    ("zero-write proof (before == after)", CONTRACTS,
     "        if before != after:",
     "        if False:"),
    ("active_run_observed must be false", CONTRACTS,
     '"active_run_observed": _false(values["active_run_observed"], "active_run_observed"),',
     '"active_run_observed": values["active_run_observed"],'),
    ("absence_is_not_deletion must be true", CONTRACTS,
     '"absence_is_not_deletion": _true(\n                values["absence_is_not_deletion"], "absence_is_not_deletion"\n            ),',
     '"absence_is_not_deletion": values["absence_is_not_deletion"],'),
    ("tombstone samples forbidden when representation absent", CONTRACTS,
     '        if representation == "absent" and tombstones:',
     "        if False:"),
    ("history sample sets must be disjoint", CONTRACTS,
     "            if set(left) & set(right):",
     "            if False:"),
    ("six distinct export evidence documents", CONTRACTS,
     "        if len(set(evidence_digests)) != len(evidence_digests):",
     "        if False:"),
    ("six distinct bundle digests", CONTRACTS,
     "        if len(set(bound_digests)) != len(bound_digests):",
     "        if False:"),
    ("identifier charset on _text", CONTRACTS,
     "    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:",
     "    if not isinstance(value, str) or not value:"),
    ("count partition (unique + duplicate == candidate)", CONTRACTS,
     "        if int(unique_count) + int(duplicate_count) != int(candidate_count):",
     "        if False:"),
    ("symlink refusal in item_digests", COMMON,
     "        if path.is_symlink():",
     "        if False:"),
]


def run_suites() -> tuple[bool, str]:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", *SUITES, "-q", "--no-header", "-x"],
        cwd=REPO, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    return r.returncode == 0, (r.stdout or "")[-200:].strip().replace("\n", " ")


ORIGINAL = {path: path.read_text() for path in FILES}


def restore() -> None:
    """Restore from an in-memory snapshot.

    Never `git checkout`: that reverts to HEAD and silently destroys any
    uncommitted work in these files, including a fix being validated right now.
    """
    for path, text in ORIGINAL.items():
        if path.read_text() != text:
            path.write_text(text)


def _restore_on_exit() -> None:
    """Restore even if this process dies mid-mutation.

    A harness that leaves a disabled guard behind in the working tree is worse
    than no harness: the next run passes against mutated source and nobody
    notices. `finally` covers exceptions; atexit covers everything else.
    """
    restore()


atexit.register(_restore_on_exit)
def main() -> int:
    baseline_ok, baseline_note = run_suites()
    print(f"baseline suites pass: {baseline_ok}  ({baseline_note})")
    if not baseline_ok:
        print("baseline is red; aborting so results are meaningful")
        return 2

    results, survivors = [], []
    for label, path, needle, replacement in MUTANTS:
        src = path.read_text()
        if needle not in src:
            results.append({"guard": label, "status": "MUTANT_NOT_APPLIED",
                            "note": "source anchor not found"})
            survivors.append(label)
            print(f"  !! {label}: anchor not found")
            continue
        path.write_text(src.replace(needle, replacement, 1))
        try:
            caught, note = (lambda ok, n: (not ok, n))(*run_suites())
        finally:
            restore()
        results.append({"guard": label,
                        "status": "CAUGHT" if caught else "SURVIVED",
                        "note": note})
        if not caught:
            survivors.append(label)
        print(f"  {'CAUGHT  ' if caught else 'SURVIVED'} {label}")

    dirty = "" if all(p.read_text() == t for p, t in ORIGINAL.items()) else "modified"
    print(f"\nsource restored cleanly: {not dirty}")
    print(f"mutants: {len(MUTANTS)} | caught: {len(MUTANTS)-len(survivors)} | survived: {len(survivors)}")
    for s in survivors:
        print(f"  SURVIVOR: {s}")

    report = {
        "schemaVersion": 1,
        "kind": "algorithm-mutation-audit",
        "purpose": ("A guard whose removal leaves the suite green is decoration. Each guard is "
                    "disabled in the shipped source, the targeted suites are re-run, and the "
                    "result records whether the suite noticed. Every mutation is reverted."),
        "suites": SUITES,
        "mutantCount": len(MUTANTS),
        "caught": len(MUTANTS) - len(survivors),
        "survived": len(survivors),
        "sourceRestoredCleanly": not dirty,
        "results": results,
    }
    out = REPO / "artifacts/second-brain/db03-migration-evidence-mutation-audit.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"written_to: {out}")
    return 1 if (survivors or dirty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
