#!/usr/bin/env python3.12
"""Drive the DB-03 evidence surface adversarially and record what actually happens.

Every row in the emitted report is the observed result of a real invocation. No
verdict is written by hand: `verdict` is computed by comparing the observed
outcome against the expectation declared with the case.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from pathlib import Path

REPO = Path("/tmp/wiki-spike-native-measurement")
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from wiki_spike.memory_core.errors import InvalidContractValue  # noqa: E402
from wiki_spike.memory_core.second_brain_ledger_contracts import (  # noqa: E402
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (  # noqa: E402
    MigrationExportProfileV1,
    MigrationHistoryTreatmentV1,
    MigrationSnapshotV1,
    MigrationSourceEvidenceV1,
    MigrationUniquenessDiffV1,
)

spec = importlib.util.spec_from_file_location(
    "db03tool", REPO / "scripts" / "second_brain_migration_source_evidence.py"
)
TOOL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TOOL)

SCRATCH = Path("/tmp/db03-qa/scratch")
CASES: list[dict] = []


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def cli(*args) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            code = TOOL.main([str(a) for a in args])
    except SystemExit as exc:  # argparse choices rejection
        code = int(exc.code) if exc.code is not None else 0
    return code, out.getvalue(), err.getvalue()


def record(cid, scenario, expected, observed, ok, refs=()):
    CASES.append({
        "id": cid,
        "contractRef": "DB-03-migration-sources",
        "scenario": scenario,
        "expectedBehavior": expected,
        "observed": observed,
        "verdict": "passed" if ok else "failed",
        "artifactRefs": list(refs),
    })


def refuses(cid, scenario, fn, expected="refused as InvalidContractValue"):
    try:
        fn()
        record(cid, scenario, expected, "ACCEPTED", False)
    except InvalidContractValue as exc:
        record(cid, scenario, expected, f"InvalidContractValue: {str(exc)[:110]}", True)
    except Exception as exc:  # noqa: BLE001 - an escape is itself the finding
        record(cid, scenario, expected, f"ESCAPED as {type(exc).__name__}: {exc}", False)


def snap_args(out: Path, **over) -> list:
    args = {
        "--source-name": "unified-db",
        "--snapshot-ref": "snapshot:unified-db-2026-07-30",
        "--writers-quiesced-at": "2026-07-30T00:00:00Z",
        "--snapshot-taken-at": "2026-07-30T00:05:00Z",
        "--source-root-digest-before": d("root"),
        "--source-root-digest-after": d("root"),
        "--snapshot-package-digest": d("package"),
        "--owner-key-ref": "key:migration-owner-2026",
        "--owner-attestation-digest": d("owner-attestation"),
        "--out": str(out),
    }
    args.update(over)
    return ["snapshot", *[x for kv in args.items() for x in kv]]


def profile_args(snapshot: Path, out: Path, **over) -> list:
    args = {
        "--snapshot": str(snapshot),
        "--export-method": "read-only-transaction",
        "--write-capability-probe-digest": d("write-probe"),
        "--schema-version": "unified-db-2026-07",
        "--schema-digest": d("schema"),
        "--identity-mapping-digest": d("identity"),
        "--revision-semantics": "content-hash-revision",
        "--revision-mapping-digest": d("revision"),
        "--watermark-cursor-field": "source_cursor",
        "--overlap-behavior": "replay-overlap",
        "--restart-evidence-digest": d("restart"),
        "--page-size-limit": "500",
        "--retention-days": "90",
        "--source-fixture-digest": d("fixture"),
        "--out": str(out),
    }
    args.update(over)
    flat = [x for kv in args.items() for x in kv]
    for f in ("source_id", "native_id", "content_hash"):
        flat += ["--native-identity-field", f]
    return ["export-profile", *flat]


def main() -> int:
    os.makedirs(SCRATCH, exist_ok=True)
    for stale in SCRATCH.rglob("*"):
        if stale.is_file() or stale.is_symlink():
            stale.unlink()

    # --- baseline chain -------------------------------------------------
    snapshot = SCRATCH / "snapshot.json"
    assert cli(*snap_args(snapshot))[0] == 0
    profile = SCRATCH / "profile.json"
    assert cli(*profile_args(snapshot, profile))[0] == 0

    cand_dir, canon_dir = SCRATCH / "cand", SCRATCH / "canon"
    cand_dir.mkdir(exist_ok=True); canon_dir.mkdir(exist_ok=True)
    for i, body in enumerate(["c-one", "c-two", "c-both"]):
        (cand_dir / f"{i}.txt").write_text(body, encoding="utf-8")
    for i, body in enumerate(["c-both", "k-only"]):
        (canon_dir / f"{i}.txt").write_text(body, encoding="utf-8")
    cand_j, canon_j = SCRATCH / "cand.json", SCRATCH / "canon.json"
    assert cli("digests", "--dir", cand_dir, "--out", cand_j)[0] == 0
    assert cli("digests", "--dir", canon_dir, "--out", canon_j)[0] == 0
    diff = SCRATCH / "diff.json"
    assert cli("uniqueness-diff", "--snapshot", snapshot, "--candidates", cand_j,
               "--canonical", canon_j, "--out", diff)[0] == 0
    treat = SCRATCH / "treat.json"
    assert cli("history-treatment", "--snapshot", snapshot,
               "--tombstone-representation", "absent",
               "--history-availability", "partial-with-proof",
               "--retained-sample", d("retained"), "--unavailable-sample", d("unavail"),
               "--out", treat)[0] == 0
    evidence = SCRATCH / "evidence.json"
    code, out, _ = cli("evidence", "--snapshot", snapshot, "--export-profile", profile,
                       "--uniqueness-diff", diff, "--history-treatment", treat,
                       "--workspace-ref", "workspace:second-brain-final",
                       "--security-review-digest", d("security"), "--out", evidence)
    record("a-00", "Full happy-path chain produces a bundle",
           "exit 0 and an evidence_digest the contract accepts", f"exit {code}", code == 0)
    bundle = json.loads(evidence.read_text())
    MigrationSourceEvidenceV1.from_mapping(bundle)

    # --- counts ---------------------------------------------------------
    diff_body = {k: v for k, v in json.loads(diff.read_text()).items() if k != "diff_digest"}
    def diff_with(**over):
        b = {**diff_body, **over}
        b["diff_digest"] = canonical_ledger_digest("migration-uniqueness-diff-v1", b)
        return lambda: MigrationUniquenessDiffV1.from_mapping(b)
    refuses("a-01", "Arabic-Indic digits as unique_item_count (second encoding of one value)",
            diff_with(unique_item_count="\u0665\u0660\u0660"))
    refuses("a-02", "Superscript two as unique_item_count (isdigit true, int() raises)",
            diff_with(unique_item_count="\u00b2"))
    refuses("a-03", "4301-digit count exceeding sys.get_int_max_str_digits()",
            diff_with(unique_item_count="1" * 4301))
    refuses("a-04", "21-digit count just past the declared bound",
            diff_with(unique_item_count="9" * 21))
    refuses("a-05", "Leading-zero count creating a second encoding",
            diff_with(unique_item_count="007"))
    refuses("a-06", "Inflated unique_item_count without matching digests",
            diff_with(unique_item_count="99", candidate_item_count="100"))
    refuses("a-07", "Understated candidate_item_count hiding duplicates",
            diff_with(candidate_item_count=diff_body["unique_item_count"]))
    refuses("a-08", "Comparison method replaced by operator judgement",
            diff_with(comparison_method="operator-judgement"))

    # --- symlinks -------------------------------------------------------
    outside = SCRATCH / "outside-secret.txt"
    outside.write_text("OUTSIDE-BYTES", encoding="utf-8")
    otherdir = SCRATCH / "otherdir"; otherdir.mkdir(exist_ok=True)
    (otherdir / "x.txt").write_text("other", encoding="utf-8")
    outside_digest = d("OUTSIDE-BYTES")
    for cid, label, target in (
        ("a-09", "symlink to a file outside the export tree", outside),
        ("a-10", "symlink to a directory outside the export tree", otherdir),
        ("a-11", "dangling symlink", Path("/nonexistent-target")),
    ):
        one = SCRATCH / f"link-{cid}"
        one.mkdir(exist_ok=True)
        (one / "real.txt").write_text("real", encoding="utf-8")
        (one / "l").symlink_to(target)
        code, out, err = cli("digests", "--dir", one)
        ok = code == 2 and "symlink" in err and outside_digest not in out
        record(cid, f"digests --dir over a {label}",
               "exit 2, symlink refusal, no out-of-tree digest emitted",
               f"exit {code}; stderr={err.strip()[:90]}", ok)
    loop = SCRATCH / "loop"; loop.mkdir(exist_ok=True)
    (loop / "real.txt").write_text("real", encoding="utf-8")
    (loop / "l").symlink_to(loop)
    code, out, err = cli("digests", "--dir", loop)
    record("a-12", "symlink loop under the export tree",
           "exit 2 without hanging or recursing", f"exit {code}", code == 2)

    # --- body-free ------------------------------------------------------
    prof_body = {k: v for k, v in json.loads(profile.read_text()).items() if k != "profile_digest"}
    def prof_with(**over):
        b = {**prof_body, **over}
        b["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", b)
        return lambda: MigrationExportProfileV1.from_mapping(b)
    for cid, label, value in (
        ("a-13", "email address in schema_version", "owner@example.com"),
        ("a-14", "absolute path in schema_version", "/var/lib/unified-db/rows"),
        ("a-15", "NUL byte in watermark_cursor_field", "cur\x00sor"),
        ("a-16", "newline in schema_version", "a\nb"),
        ("a-17", "spaced record excerpt in schema_version", "patient record 12345"),
        ("a-18", "non-ASCII record text in schema_version", "\uc8fc\ubbfc\ubc88\ud638"),
        ("a-19", "JSON body in schema_version", '{"body":"secret"}'),
        ("a-20", "129-character schema_version", "a" * 129),
    ):
        refuses(cid, f"body-free escape via {label}", prof_with(**{
            "watermark_cursor_field" if "cursor" in label else "schema_version": value}))

    # --- export evidence distinctness -----------------------------------
    for cid, field, collides in (
        ("a-21", "revision_mapping_digest", "identity"),
        ("a-22", "write_capability_probe_digest", "restart"),
        ("a-23", "source_fixture_digest", "schema"),
    ):
        refuses(cid, f"one document reused as both {field} and its twin",
                prof_with(**{field: d(collides)}))
    missing = {k: v for k, v in prof_body.items() if k != "write_capability_probe_digest"}
    missing["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", missing)
    refuses("a-24", "export profile with no write-capability probe digest",
            lambda: MigrationExportProfileV1.from_mapping(missing))

    # --- snapshot integrity ---------------------------------------------
    snap_body = {k: v for k, v in json.loads(snapshot.read_text()).items()
                 if k != "snapshot_binding_digest"}
    def snap_with(**over):
        b = {**snap_body, **over}
        b["snapshot_binding_digest"] = canonical_ledger_digest("migration-snapshot-v1", b)
        return lambda: MigrationSnapshotV1.from_mapping(b)
    refuses("a-25", "snapshot rebound with active_run_observed true",
            snap_with(active_run_observed=True))
    refuses("a-26", "source root changed across the export window",
            snap_with(source_root_digest_after=d("after-a-write")))
    code, _, _ = cli(*snap_args(SCRATCH / "never.json",
                                **{"--snapshot-taken-at": "2026-07-29T00:00:00Z"}))
    record("a-27", "snapshot taken before writers were quiesced",
           "exit 2 and no artifact written",
           f"exit {code}; artifact_exists={(SCRATCH / 'never.json').exists()}",
           code == 2 and not (SCRATCH / "never.json").exists())
    code, _, _ = cli("snapshot", "--source-name", "hermes", "--snapshot-ref", "snapshot:h",
                     "--writers-quiesced-at", "2026-07-30T00:00:00Z",
                     "--snapshot-taken-at", "2026-07-30T00:05:00Z",
                     "--source-root-digest-before", d("r"), "--source-root-digest-after", d("r"),
                     "--snapshot-package-digest", d("p"), "--owner-key-ref", "key:o",
                     "--owner-attestation-digest", d("o"))
    record("a-28", "source outside DB-03's three-name scope inventory (hermes)",
           "rejected before any artifact is produced", f"exit {code}", code != 0)

    # --- history --------------------------------------------------------
    tre_body = {k: v for k, v in json.loads(treat.read_text()).items()
                if k != "treatment_digest"}
    def tre_with(**over):
        b = {**tre_body, **over}
        b["treatment_digest"] = canonical_ledger_digest("migration-history-treatment-v1", b)
        return lambda: MigrationHistoryTreatmentV1.from_mapping(b)
    refuses("a-29", "tombstone samples for a source whose representation is absent",
            tre_with(tombstone_sample_digests=[d("guess")]))
    refuses("a-30", "unavailable history also presenting retained samples",
            tre_with(history_availability="unavailable"))
    refuses("a-31", "one record counted as both retained and unavailable",
            tre_with(unavailable_history_sample_digests=list(
                tre_body["retained_history_sample_digests"])))
    refuses("a-32", "absence_is_not_deletion switched off",
            tre_with(absence_is_not_deletion=False))

    # --- bundle splices --------------------------------------------------
    ev_body = {k: v for k, v in bundle.items() if k != "evidence_digest"}
    def ev_with(**over):
        b = {**ev_body, **over}
        b["evidence_digest"] = canonical_ledger_digest("migration-source-evidence-v1", b)
        return lambda: MigrationSourceEvidenceV1.from_mapping(b)
    refuses("a-33", "owner attestation reused as the Security review",
            ev_with(security_review_digest=ev_body["owner_attestation_digest"]))
    refuses("a-34", "export profile digest reused as the Security review",
            ev_with(security_review_digest=ev_body["export_profile_digest"]))
    refuses("a-35", "one component digest filling two bundle slots",
            ev_with(uniqueness_diff_digest=ev_body["export_profile_digest"]))
    other_snap = SCRATCH / "me-wiki.json"
    assert cli(*snap_args(other_snap, **{"--source-name": "me-wiki",
                                         "--snapshot-ref": "snapshot:me-wiki"}))[0] == 0
    other_prof = SCRATCH / "me-wiki-profile.json"
    assert cli(*profile_args(other_snap, other_prof))[0] == 0
    code, _, _ = cli("evidence", "--snapshot", snapshot, "--export-profile", other_prof,
                     "--uniqueness-diff", diff, "--history-treatment", treat,
                     "--workspace-ref", "workspace:second-brain-final",
                     "--security-review-digest", d("security"),
                     "--out", SCRATCH / "spliced.json")
    record("a-36", "another source's export profile spliced into the bundle",
           "exit 2", f"exit {code}", code == 2)
    later = SCRATCH / "later.json"
    assert cli(*snap_args(later, **{"--snapshot-ref": "snapshot:unified-db-2026-08-01"}))[0] == 0
    later_treat = SCRATCH / "later-treat.json"
    assert cli("history-treatment", "--snapshot", later,
               "--tombstone-representation", "absent",
               "--history-availability", "partial-with-proof",
               "--retained-sample", d("retained"), "--unavailable-sample", d("unavail"),
               "--out", later_treat)[0] == 0
    code, _, _ = cli("evidence", "--snapshot", snapshot, "--export-profile", profile,
                     "--uniqueness-diff", diff, "--history-treatment", later_treat,
                     "--workspace-ref", "workspace:second-brain-final",
                     "--security-review-digest", d("security"),
                     "--out", SCRATCH / "spliced2.json")
    record("a-37", "component from a later snapshot of the same source",
           "exit 2", f"exit {code}", code == 2)

    # --- verify dispatch --------------------------------------------------
    code, out, _ = cli("verify", "--file", evidence)
    rep = json.loads(out)
    borrowed = {bundle[k] for k in ("snapshot_binding_digest", "export_profile_digest",
                                    "uniqueness_diff_digest", "history_treatment_digest")}
    record("a-38", "verify on a bundle carrying four other artifacts' digests",
           "reports evidence_digest, never a borrowed one",
           f"digest_field={rep['digest_field']}",
           rep["digest_field"] == "evidence_digest" and rep["digest"] not in borrowed)
    spliced = {**json.loads(snapshot.read_text()), "diff_version": "x"}
    p = SCRATCH / "twoversions.json"; p.write_text(json.dumps(spliced), encoding="utf-8")
    code, _, _ = cli("verify", "--file", p)
    record("a-39", "artifact carrying two version fields", "exit 2", f"exit {code}", code == 2)

    # --- write path -------------------------------------------------------
    target = SCRATCH / "real-target.json"; target.write_text("{}", encoding="utf-8")
    link = SCRATCH / "out-link.json"
    if link.is_symlink() or link.exists():
        link.unlink()
    link.symlink_to(target)
    code, _, _ = cli(*snap_args(link))
    record("a-40", "--out pointing at a symlink",
           "exit 2 and the symlink target untouched",
           f"exit {code}; target={target.read_text()!r}",
           code == 2 and target.read_text() == "{}")
    deep = SCRATCH / "no" / "such" / "dir" / "s.json"
    code, _, _ = cli(*snap_args(deep))
    record("a-41", "--out under a nonexistent parent directory",
           "exit 2 and no partial artifact or directory created",
           f"exit {code}; created={deep.exists()}", code == 2 and not deep.exists())
    code, _, _ = cli(*snap_args(SCRATCH))
    record("a-42", "--out pointing at a directory",
           "exit 2 without a traceback", f"exit {code}", code == 2)

    # --- malformed input ---------------------------------------------------
    bad = SCRATCH / "bad.json"
    bad.write_text('{"snapshot_version": "a", "snapshot_version": "b"}', encoding="utf-8")
    code, _, _ = cli("verify", "--file", bad)
    record("a-43", "duplicate JSON keys in an artifact", "exit 2", f"exit {code}", code == 2)
    bad.write_text("[1,2,3]", encoding="utf-8")
    code, _, _ = cli("verify", "--file", bad)
    record("a-44", "JSON array where an artifact object is expected", "exit 2",
           f"exit {code}", code == 2)
    bad.write_text("", encoding="utf-8")
    code, _, _ = cli("verify", "--file", bad)
    record("a-45", "empty file as an artifact", "exit 2", f"exit {code}", code == 2)
    code, _, err = cli("verify", "--file", SCRATCH / "definitely-absent.json")
    record("a-46", "missing file", "exit 2 with a FAIL line and no traceback",
           f"exit {code}; stderr_starts={err.strip()[:12]!r}",
           code == 2 and err.startswith("FAIL:"))
    dupes = SCRATCH / "dupes.json"
    dupes.write_text(json.dumps([d("x"), d("x")]), encoding="utf-8")
    code, _, _ = cli("uniqueness-diff", "--snapshot", snapshot, "--candidates", dupes,
                     "--canonical", canon_j)
    record("a-47", "candidate digest list containing duplicates", "exit 2",
           f"exit {code}", code == 2)
    empty_dir = SCRATCH / "emptydir"; empty_dir.mkdir(exist_ok=True)
    code, _, _ = cli("digests", "--dir", empty_dir)
    record("a-48", "empty export directory", "exit 2", f"exit {code}", code == 2)

    # --- stated limitation -------------------------------------------------
    b = {**prof_body, "schema_version": "patient-12345-diagnosis-hypertension"}
    b["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", b)
    try:
        MigrationExportProfileV1.from_mapping(b)
        observed, ok = "ACCEPTED, as the module docstring states", True
    except InvalidContractValue:
        observed, ok = "refused (docstring now over-states the guard)", False
    record("a-49",
           "Deliberately identifier-encoded record excerpt in schema_version",
           "accepted; the charset is a documented accident guard, not a boundary",
           observed, ok)

    failed = [c for c in CASES if c["verdict"] != "passed"]
    report = {
        "schemaVersion": 1,
        "kind": "algorithm-adversarial-report",
        "generation": 3,
        "sourceHash": SOURCE_HASH,
        "surface": "algorithm+api+cli",
        "producedBy": "ultragoal leader (delegation unavailable this session)",
        "adversarial_case_count": len(CASES),
        "passed": len(CASES) - len(failed),
        "failed": len(failed),
        "cases": CASES,
    }
    dest = REPO / "artifacts" / "second-brain" / "db03-migration-evidence-adversarial-report.json"
    dest.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"cases": len(CASES), "failed": len(failed),
                      "failed_ids": [c["id"] for c in failed], "written_to": str(dest)}, indent=2))
    return 1 if failed else 0


SOURCE_HASH = os.environ.get("DB03_SOURCE_HASH", "unset")

if __name__ == "__main__":
    raise SystemExit(main())
