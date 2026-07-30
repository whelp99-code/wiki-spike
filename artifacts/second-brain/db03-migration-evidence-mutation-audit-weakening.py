#!/usr/bin/env python3.12
"""Fifth mutation batch: the subtle ones a reviewer would worry about.

Not deleted guards this time, but guards that still fire while meaning something
weaker or different: a digest domain reused across artifact types, an ordering
comparison that reverts to string compare, bounds loosened rather than removed,
the scope inventory widened, and the verify dispatcher reporting a neighbour's
digest field. Each of these keeps the code superficially working.
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
    # --- digest domain separation ------------------------------------------
    ("snapshot binds under its own digest domain", CONTRACTS,
     '        if digest != canonical_ledger_digest("migration-snapshot-v1", body):',
     '        if digest != canonical_ledger_digest("migration-export-profile-v1", body):'),
    ("uniqueness diff binds under its own digest domain", CONTRACTS,
     '        if digest != canonical_ledger_digest("migration-uniqueness-diff-v1", body):',
     '        if digest != canonical_ledger_digest("migration-history-treatment-v1", body):'),
    ("bundle binds under its own digest domain", CONTRACTS,
     '        if digest != canonical_ledger_digest("migration-source-evidence-v1", body):',
     '        if digest != canonical_ledger_digest("migration-snapshot-v1", body):'),
    # --- ordering semantics -------------------------------------------------
    ("instant ordering compares real time, not spelling", CONTRACTS,
     '    return datetime.fromisoformat(canonical[:-1] + "+00:00").astimezone(timezone.utc)',
     "    return canonical"),
    # --- bounds loosened rather than removed --------------------------------
    ("count digit bound stays tight", CONTRACTS,
     "_MAX_COUNT_DIGITS = 20", "_MAX_COUNT_DIGITS = 4300"),
    ("identifier token bound stays at 128", CONTRACTS,
     '_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}")',
     '_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,4096}")'),
    # --- scope inventory ----------------------------------------------------
    ("DB-03 scope inventory stays exactly three names", CONTRACTS,
     'MIGRATION_SOURCE_NAMES = ("legacy Mem0/RAG", "me-wiki", "unified-db")',
     'MIGRATION_SOURCE_NAMES = ("legacy Mem0/RAG", "me-wiki", "unified-db", "hermes")'),
    # --- read-only export method set ----------------------------------------
    ("export methods stay read-only", CONTRACTS,
     'READ_ONLY_EXPORT_METHODS = (\n    "read-only-transaction",',
     'READ_ONLY_EXPORT_METHODS = (\n    "read-write-transaction",\n    "read-only-transaction",'),
    # --- overlap behaviour has no escape hatch -------------------------------
    ("overlap behaviour admits no unknown value", CONTRACTS,
     'OVERLAP_BEHAVIORS = ("replay-overlap", "exactly-once-cursor")',
     'OVERLAP_BEHAVIORS = ("replay-overlap", "exactly-once-cursor", "unknown")'),
    # --- positive vs plain count --------------------------------------------
    ("page size limit must be positive, not merely decimal", CONTRACTS,
     '            "page_size_limit": _positive_count(values["page_size_limit"], "page_size_limit"),',
     '            "page_size_limit": _count(values["page_size_limit"], "page_size_limit"),'),
    ("candidate count must be positive, not merely decimal", CONTRACTS,
     '        candidate_count = _positive_count(values["candidate_item_count"], "candidate_item_count")',
     '        candidate_count = _count(values["candidate_item_count"], "candidate_item_count")'),
    # --- verify dispatcher --------------------------------------------------
    ("verify reports the bundle's own digest field", TOOL,
     'MIGRATION_SOURCE_EVIDENCE_V1: (MigrationSourceEvidenceV1, "evidence_digest"),',
     'MIGRATION_SOURCE_EVIDENCE_V1: (MigrationSourceEvidenceV1, "snapshot_binding_digest"),'),
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
    out = REPO / "artifacts/second-brain/db03-migration-evidence-mutation-audit-weakening.json"
    out.write_text(json.dumps({
        "schemaVersion": 1, "kind": "algorithm-mutation-audit",
        "batch": "weakened-not-deleted",
        "purpose": ("Guards that still fire but mean something weaker: a digest domain reused "
                    "across artifact types, ordering reverted to string compare, bounds loosened, "
                    "the scope inventory widened, a read-write export method admitted, an unknown "
                    "overlap behaviour admitted, positive counts relaxed to plain counts, and the "
                    "verify dispatcher reporting a neighbour's digest field."),
        "suites": SUITES, "mutantCount": len(MUTANTS),
        "caught": len(MUTANTS) - len(survivors), "survived": len(survivors),
        "sourceRestoredCleanly": not dirty, "results": results,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"written_to: {out}")
    return 1 if (survivors or dirty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
