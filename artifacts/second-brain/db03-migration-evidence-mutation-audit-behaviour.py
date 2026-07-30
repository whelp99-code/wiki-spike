#!/usr/bin/env python3.12
"""Fourth mutation batch: behaviour, not just rejection.

The first three batches asked whether each guard, when deleted, causes a
failure. That only proves the tests notice bad input being accepted. It does not
prove they notice the tool computing the *wrong answer* from good input.

So this batch corrupts the computations: the set difference, the counts, the
sort orders, the constants the tool writes on the operator's behalf, and the
coherence call in the bundle command. A surviving mutant here means the suite
would not notice the tool quietly producing wrong evidence.
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
TOOL = REPO / "scripts/second_brain_migration_source_evidence.py"
FILES = [CONTRACTS, COMMON, TOOL]
SUITES = [
    "tests/second_brain/test_migration_evidence_contracts.py",
    "tests/second_brain/test_migration_source_evidence_tool.py",
    "tests/second_brain/test_migration_source_evidence_red_team.py",
    "tests/second_brain/test_db03_doc_migration_agreement.py",
    "tests/second_brain/test_evaluation_governance_tool.py",
]

MUTANTS = [
    # --- the computations the tool performs on real input ------------------
    ("uniqueness diff actually subtracts the canonical corpus", TOOL,
     "    unique = [digest for digest in candidates if digest not in canonical_set]",
     "    unique = list(candidates)"),
    ("duplicate count is candidates minus unique", TOOL,
     '        "duplicate_item_count": str(len(candidates) - len(unique)),',
     '        "duplicate_item_count": "0",'),
    ("canonical corpus digest is order-independent", TOOL,
     'return canonical_ledger_digest(CANONICAL_CORPUS_DOMAIN, {"item_digests": sorted(digests)})',
     'return canonical_ledger_digest(CANONICAL_CORPUS_DOMAIN, {"item_digests": list(digests)})'),
    ("item digests are emitted in sorted path order", COMMON,
     '    for path in sorted(directory.rglob("*")):',
     '    for path in list(directory.rglob("*")):'),
    # --- constants the tool writes on the operator's behalf ----------------
    ("tool writes active_run_observed false", TOOL,
     '        "active_run_observed": False,', '        "active_run_observed": True,'),
    ("tool writes write_capability_absent true", TOOL,
     '        "write_capability_absent": True,', '        "write_capability_absent": False,'),
    ("tool writes absence_is_not_deletion true", TOOL,
     '        "absence_is_not_deletion": True,', '        "absence_is_not_deletion": False,'),
    # --- provenance the tool derives rather than accepts -------------------
    ("bundle runs the coherence assertion", TOOL,
     "    assert_migration_evidence_bundle_coherent(evidence, snapshot, profile, diff, treatment)",
     "    pass"),
    ("snapshot instants are canonicalised before digesting", TOOL,
     '        "snapshot_taken_at": canonical_ledger_instant(\n            args.snapshot_taken_at, "snapshot_taken_at"\n        ),',
     '        "snapshot_taken_at": args.snapshot_taken_at,'),
    # --- remaining primitive validators ------------------------------------
    ("digest must be 64 lowercase hex", CONTRACTS,
     "    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX64 for ch in value):",
     "    if not isinstance(value, str):"),
    ("strict rejects non-mapping input", CONTRACTS,
     "    if not isinstance(data, Mapping) or any(not isinstance(k, str) for k in data):",
     "    if not isinstance(data, Mapping):"),
    ("digest tuple rejects a non-array", CONTRACTS,
     "    if not isinstance(value, (list, tuple)):", "    if False:"),
    ("names must be a non-empty array", CONTRACTS,
     "    if not isinstance(value, (list, tuple)) or not value:", "    if False:"),
]


def run_suites():
    r = subprocess.run([sys.executable, "-m", "pytest", *SUITES, "-q", "--no-header", "-x"],
                       cwd=REPO, capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": "src"})
    return r.returncode == 0, (r.stdout or "")[-160:].strip().replace("\n", " ")


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
    ok, note = run_suites()
    print(f"baseline suites pass: {ok} ({note})")
    if not ok:
        return 2
    results, survivors = [], []
    for label, path, needle, replacement in MUTANTS:
        src = path.read_text()
        if src.count(needle) != 1:
            results.append({"guard": label, "status": "ANCHOR_AMBIGUOUS",
                            "note": f"occurrences={src.count(needle)}"})
            survivors.append(label)
            print(f"  !! {label}: occurrences={src.count(needle)}")
            continue
        path.write_text(src.replace(needle, replacement, 1))
        try:
            passed, note = run_suites()
        finally:
            restore()
        caught = not passed
        results.append({"guard": label, "status": "CAUGHT" if caught else "SURVIVED",
                        "note": note})
        if not caught:
            survivors.append(label)
        print(f"  {'CAUGHT  ' if caught else 'SURVIVED'} {label}")
    dirty = "" if all(p.read_text() == t for p, t in ORIGINAL.items()) else "modified"
    print(f"\nsource restored cleanly: {not dirty}")
    print(f"mutants: {len(MUTANTS)} | caught: {len(MUTANTS)-len(survivors)} | survived: {len(survivors)}")
    for s in survivors:
        print(f"  SURVIVOR: {s}")
    out = REPO / "artifacts/second-brain/db03-migration-evidence-mutation-audit-behaviour.json"
    out.write_text(json.dumps({
        "schemaVersion": 1, "kind": "algorithm-mutation-audit",
        "batch": "behaviour-not-rejection",
        "purpose": ("Batches 1-3 proved the guards notice bad input. This corrupts the "
                    "computations instead - the set difference, the counts, the sort orders, "
                    "the constants the tool writes for the operator, and the coherence call - "
                    "to prove the suite would notice the tool producing wrong evidence from "
                    "good input."),
        "suites": SUITES, "mutantCount": len(MUTANTS),
        "caught": len(MUTANTS) - len(survivors), "survived": len(survivors),
        "sourceRestoredCleanly": not dirty, "results": results,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"written_to: {out}")
    return 1 if (survivors or dirty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
