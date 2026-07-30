#!/usr/bin/env python3.12
"""Third mutation batch: enum closures, version pins, uniqueness, and tool guards.

Batches 1 and 2 covered the field rules and the binding/coherence mechanisms.
This one sweeps what was left: the closed-enum check, the ref prefix, the five
version pins, tuple uniqueness, the positive-count floor, the boolean constants,
the history availability rules, and the guards living in the two scripts.
"""
from __future__ import annotations

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

NEVER = "if False:"

MUTANTS = [
    # --- shared validators -------------------------------------------------
    ("ref prefix requirement", CONTRACTS,
     '    if not isinstance(value, str) or not value.startswith(prefix + ":"):',
     f"    {NEVER}"),
    ("closed enum membership", CONTRACTS,
     "    if not isinstance(value, str) or value not in allowed:", f"    {NEVER}"),
    ("_true constant guard", CONTRACTS, "    if value is not True:", f"    {NEVER}"),
    ("_false constant guard", CONTRACTS, "    if value is not False:", f"    {NEVER}"),
    ("positive-count floor rejects 0", CONTRACTS, '    if value == "0":', f"    {NEVER}"),
    # --- version pins ------------------------------------------------------
    ("version pin: snapshot", CONTRACTS,
     '        if values["snapshot_version"] != MIGRATION_SNAPSHOT_V1:', f"        {NEVER}"),
    ("version pin: export profile", CONTRACTS,
     '        if values["profile_version"] != MIGRATION_EXPORT_PROFILE_V1:', f"        {NEVER}"),
    ("version pin: uniqueness diff", CONTRACTS,
     '        if values["diff_version"] != MIGRATION_UNIQUENESS_DIFF_V1:', f"        {NEVER}"),
    ("version pin: history treatment", CONTRACTS,
     '        if values["treatment_version"] != MIGRATION_HISTORY_TREATMENT_V1:', f"        {NEVER}"),
    ("version pin: source evidence", CONTRACTS,
     '        if values["evidence_version"] != MIGRATION_SOURCE_EVIDENCE_V1:', f"        {NEVER}"),
    # --- history availability rules ---------------------------------------
    ("declared tombstone representation needs a sample", CONTRACTS,
     '        if representation != "absent" and not tombstones:', f"        {NEVER}"),
    ("unavailable history rules", CONTRACTS,
     '        if availability == "unavailable":', f"        {NEVER}"),
    ("complete history rules", CONTRACTS,
     '        if availability == "complete":', f"        {NEVER}"),
    ("partial history needs both sample sets", CONTRACTS,
     '        if availability == "partial-with-proof" and not (retained and unavailable):',
     f"        {NEVER}"),
    # --- script guards -----------------------------------------------------
    ("write_atomic refuses a symlink destination", COMMON,
     '    if path.is_symlink():\n        raise EvidenceToolError(f"{path} is a symlink; refusing to write through it")',
     f"    {NEVER}\n        pass"),
    ("export directory must hold files", COMMON, "    if not digests:", f"    {NEVER}"),
    ("export directory rejects byte-identical duplicates", COMMON,
     "    if len(set(digests)) != len(digests):", f"    {NEVER}"),
    ("verify requires exactly one version field", COMMON,
     "    if len(versions) != 1:", f"    {NEVER}"),
    ("verify rejects an unrecognised version", COMMON,
     "    if entry is None:", f"    {NEVER}"),
    ("digest list must be a non-empty array", TOOL,
     "    if not isinstance(raw, list) or not raw:", f"    {NEVER}"),
    ("digest list rejects duplicates", TOOL,
     "    if len(set(raw)) != len(raw):", f"    {NEVER}"),
]


def run_suites():
    r = subprocess.run([sys.executable, "-m", "pytest", *SUITES, "-q", "--no-header", "-x"],
                       cwd=REPO, capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": "src"})
    return r.returncode == 0, (r.stdout or "")[-160:].strip().replace("\n", " ")


def restore():
    subprocess.run(["git", "checkout", "--", *[str(f.relative_to(REPO)) for f in FILES]],
                   cwd=REPO, check=True)


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
        passed, note = run_suites()
        restore()
        caught = not passed
        results.append({"guard": label, "status": "CAUGHT" if caught else "SURVIVED",
                        "note": note})
        if not caught:
            survivors.append(label)
        print(f"  {'CAUGHT  ' if caught else 'SURVIVED'} {label}")
    dirty = subprocess.run(["git", "status", "--porcelain",
                            *[str(f.relative_to(REPO)) for f in FILES]],
                           cwd=REPO, capture_output=True, text=True).stdout.strip()
    print(f"\nsource restored cleanly: {not dirty}")
    print(f"mutants: {len(MUTANTS)} | caught: {len(MUTANTS)-len(survivors)} | survived: {len(survivors)}")
    for s in survivors:
        print(f"  SURVIVOR: {s}")
    out = REPO / "artifacts/second-brain/db03-migration-evidence-mutation-audit-enums.json"
    out.write_text(json.dumps({
        "schemaVersion": 1, "kind": "algorithm-mutation-audit",
        "batch": "enums-versions-uniqueness-tools",
        "purpose": ("Sweeps what batches 1 and 2 left: closed-enum membership, the ref prefix, "
                    "the five version pins, tuple uniqueness, the positive-count floor, the "
                    "boolean constants, the history availability rules, and the script guards."),
        "suites": SUITES, "mutantCount": len(MUTANTS),
        "caught": len(MUTANTS) - len(survivors), "survived": len(survivors),
        "sourceRestoredCleanly": not dirty, "results": results,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"written_to: {out}")
    return 1 if (survivors or dirty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
