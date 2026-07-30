#!/usr/bin/env python3.12
"""Mutation audit: does removing or weakening each guard actually break the tests?

A guard whose removal leaves the suite green is decoration. This disables or
weakens one guard at a time in the shipped source, runs the relevant suites, and
records whether the suite noticed.

Five batches, defined as data in `db03-migration-evidence-mutants.json`:

  guards                          delete the field-level rules outright
  binding-coherence-scope         delete the digest binding and cross-artifact checks
  enums-versions-uniqueness-tools delete the enum closures, version pins and tool guards
  behaviour-not-rejection         corrupt the computations, not the guards
  weakened-not-deleted            leave guards in place but make them mean less

  ./db03-migration-evidence-mutation-audit.py                # every batch
  ./db03-migration-evidence-mutation-audit.py --batch guards # one batch

Restoration is deliberate. An earlier version of this harness restored with
`git checkout`, which reverts to HEAD and silently destroyed uncommitted work in
the files under test -- twice -- and left a mutation behind in the working tree
when it crashed mid-cycle, so a later suite run went green against mutated
source. Restore now comes from an in-memory snapshot taken at import, every
cycle is wrapped in try/finally, and atexit covers the rest. Verified by killing
the harness mid-run with SIGTERM.
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
MUTANTS = json.loads((HERE / "db03-migration-evidence-mutants.json").read_text(encoding="utf-8"))
FILES = sorted({
    REPO / entry["file"]
    for batch in MUTANTS.values() for entry in batch["mutants"]
})
ORIGINAL = {path: path.read_text(encoding="utf-8") for path in FILES}


def restore() -> None:
    """Restore from the in-memory snapshot; never `git checkout`."""
    for path, text in ORIGINAL.items():
        if path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8")


atexit.register(restore)


def run_suites(suites: list[str]) -> tuple[bool, str]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", *suites, "-q", "--no-header", "-x"],
        cwd=REPO, capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": "src"},
    )
    return result.returncode == 0, (result.stdout or "")[-160:].strip().replace("\n", " ")


def run_batch(name: str) -> dict:
    batch = MUTANTS[name]
    suites = batch["suites"]
    ok, note = run_suites(suites)
    print(f"[{name}] baseline suites pass: {ok} ({note})")
    if not ok:
        return {"batch": name, "error": "baseline red", "mutantCount": len(batch["mutants"]),
                "caught": 0, "survived": len(batch["mutants"]), "results": []}

    results, survivors = [], []
    for entry in batch["mutants"]:
        path = REPO / entry["file"]
        source = path.read_text(encoding="utf-8")
        if source.count(entry["find"]) != 1:
            results.append({"guard": entry["label"], "status": "ANCHOR_AMBIGUOUS",
                            "note": f"occurrences={source.count(entry['find'])}"})
            survivors.append(entry["label"])
            print(f"  !! {entry['label']}: occurrences={source.count(entry['find'])}")
            continue
        path.write_text(source.replace(entry["find"], entry["replace"], 1), encoding="utf-8")
        try:
            passed, note = run_suites(suites)
        finally:
            restore()
        caught = not passed
        results.append({"guard": entry["label"], "status": "CAUGHT" if caught else "SURVIVED",
                        "note": note})
        if not caught:
            survivors.append(entry["label"])
        print(f"  {'CAUGHT  ' if caught else 'SURVIVED'} {entry['label']}")

    clean = all(p.read_text(encoding="utf-8") == t for p, t in ORIGINAL.items())
    report = {
        "schemaVersion": 1, "kind": "algorithm-mutation-audit", "batch": name,
        "purpose": batch.get("purpose"), "suites": suites,
        "mutantCount": len(batch["mutants"]),
        "caught": len(batch["mutants"]) - len(survivors), "survived": len(survivors),
        "sourceRestoredCleanly": clean, "results": results,
    }
    out = HERE / f"db03-migration-evidence-mutation-audit-{name}.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[{name}] mutants: {report['mutantCount']} | caught: {report['caught']} | "
          f"survived: {report['survived']} | restored cleanly: {clean}")
    for survivor in survivors:
        print(f"  SURVIVOR: {survivor}")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--batch", choices=sorted(MUTANTS), action="append")
    args = parser.parse_args(argv)
    names = args.batch or sorted(MUTANTS)
    reports = [run_batch(name) for name in names]
    total = sum(r["mutantCount"] for r in reports)
    caught = sum(r["caught"] for r in reports)
    print(f"\nTOTAL: {caught}/{total} guards and computations proven load-bearing")
    return 0 if caught == total and all(r.get("sourceRestoredCleanly") for r in reports) else 1


if __name__ == "__main__":
    raise SystemExit(main())
