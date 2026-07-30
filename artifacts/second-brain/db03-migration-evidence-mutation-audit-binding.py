#!/usr/bin/env python3.12
"""Second mutation batch: the binding, coherence and scope guards.

The first batch mutated the field-level rules. This one targets the mechanisms
those rules rest on -- the five digest-binding checks, the seven cross-artifact
coherence checks, the strict field-set check, the ref prefix, the instant
ordering and the registrability guards. If any of these can be deleted while the
suite stays green, the integrity story has a hole.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path("/tmp/wiki-spike-native-measurement")
CONTRACTS = REPO / "src/wiki_spike/memory_core/second_brain_migration_evidence_contracts.py"
REL = str(CONTRACTS.relative_to(REPO))
SUITES = [
    "tests/second_brain/test_migration_evidence_contracts.py",
    "tests/second_brain/test_migration_source_evidence_tool.py",
    "tests/second_brain/test_migration_source_evidence_red_team.py",
    "tests/second_brain/test_db03_doc_migration_agreement.py",
]

DISABLE = "        if False:"
DISABLE4 = "    if False:"
DISABLE8 = "            if False:"

MUTANTS = [
    ("binding digest: snapshot",
     '        if digest != canonical_ledger_digest("migration-snapshot-v1", body):', DISABLE),
    ("binding digest: export profile",
     '        if digest != canonical_ledger_digest("migration-export-profile-v1", body):', DISABLE),
    ("binding digest: uniqueness diff",
     '        if digest != canonical_ledger_digest("migration-uniqueness-diff-v1", body):', DISABLE),
    ("binding digest: history treatment",
     '        if digest != canonical_ledger_digest("migration-history-treatment-v1", body):', DISABLE),
    ("binding digest: source evidence bundle",
     '        if digest != canonical_ledger_digest("migration-source-evidence-v1", body):', DISABLE),
    ("unique_item_count matches enumerated digests",
     "        if len(unique) != int(unique_count):", DISABLE),
    ("coherence: all components share one source name",
     "    if names != {evidence.source_name}:", DISABLE4),
    ("coherence: evidence binds the supplied snapshot",
     "    if snapshot.snapshot_binding_digest != evidence.snapshot_binding_digest:", DISABLE4),
    ("coherence: each component binds the same snapshot",
     "        if component != snapshot.snapshot_binding_digest:", DISABLE),
    ("coherence: evidence binds the supplied export profile",
     "    if profile.profile_digest != evidence.export_profile_digest:", DISABLE4),
    ("coherence: evidence binds the supplied uniqueness diff",
     "    if diff.diff_digest != evidence.uniqueness_diff_digest:", DISABLE4),
    ("coherence: evidence binds the supplied history treatment",
     "    if treatment.treatment_digest != evidence.history_treatment_digest:", DISABLE4),
    ("coherence: evidence carries the snapshot owner attestation",
     "    if snapshot.owner_attestation_digest != evidence.owner_attestation_digest:", DISABLE4),
    ("strict field set (unknown/missing rejected)",
     "    if unknown or missing:", DISABLE4),
    ("snapshot instant ordering",
     "        if _as_utc(taken) < _as_utc(quiesced):", DISABLE),
    ("registrable: NO_GO source refused",
     "    if name in dict(scope.disabled_migration_sources):", DISABLE4),
    ("registrable: source must be enabled by a GO",
     "    if name not in set(scope.enabled_migration_sources):", DISABLE4),
    ("registrable: never also a serving surface",
     "        if name in set(collection):", DISABLE),
]


def run_suites():
    r = subprocess.run([sys.executable, "-m", "pytest", *SUITES, "-q", "--no-header", "-x"],
                       cwd=REPO, capture_output=True, text=True,
                       env={**os.environ, "PYTHONPATH": "src"})
    return r.returncode == 0, (r.stdout or "")[-160:].strip().replace("\n", " ")


def restore():
    subprocess.run(["git", "checkout", "--", REL], cwd=REPO, check=True)


def main() -> int:
    ok, note = run_suites()
    print(f"baseline suites pass: {ok} ({note})")
    if not ok:
        return 2
    results, survivors = [], []
    for label, needle, replacement in MUTANTS:
        src = CONTRACTS.read_text()
        if src.count(needle) != 1:
            results.append({"guard": label, "status": "ANCHOR_AMBIGUOUS",
                            "note": f"occurrences={src.count(needle)}"})
            survivors.append(label)
            print(f"  !! {label}: anchor occurrences={src.count(needle)}")
            continue
        CONTRACTS.write_text(src.replace(needle, replacement, 1))
        passed, note = run_suites()
        restore()
        caught = not passed
        results.append({"guard": label, "status": "CAUGHT" if caught else "SURVIVED",
                        "note": note})
        if not caught:
            survivors.append(label)
        print(f"  {'CAUGHT  ' if caught else 'SURVIVED'} {label}")
    dirty = subprocess.run(["git", "status", "--porcelain", REL],
                           cwd=REPO, capture_output=True, text=True).stdout.strip()
    print(f"\nsource restored cleanly: {not dirty}")
    print(f"mutants: {len(MUTANTS)} | caught: {len(MUTANTS)-len(survivors)} | survived: {len(survivors)}")
    for s in survivors:
        print(f"  SURVIVOR: {s}")
    out = REPO / "artifacts/second-brain/db03-migration-evidence-mutation-audit-binding.json"
    out.write_text(json.dumps({
        "schemaVersion": 1, "kind": "algorithm-mutation-audit",
        "batch": "binding-coherence-scope",
        "purpose": ("The first batch mutated field-level rules. This one targets the mechanisms "
                    "they rest on: digest binding, cross-artifact coherence, the strict field "
                    "set, instant ordering and registrability."),
        "suites": SUITES, "mutantCount": len(MUTANTS),
        "caught": len(MUTANTS) - len(survivors), "survived": len(survivors),
        "sourceRestoredCleanly": not dirty, "results": results,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"written_to: {out}")
    return 1 if (survivors or dirty) else 0


if __name__ == "__main__":
    raise SystemExit(main())
