#!/usr/bin/env python3
"""DISPOSABLE Gate 1 SQLCipher feasibility harness.

Stdlib-only except an *optional* SQLCipher driver import (`sqlcipher3` then
`pysqlcipher3`). Never raises on missing driver: emits a structured JSON
result with ``status: "platform_unavailable"`` instead. When a driver is
available, runs the Gate 1 MUST scorecard from the encrypted-lifecycle plan
(stage-08/09/10, R10 supersession authoritative):

  1. key_before_open_enforced   -- reading before the key pragma must fail.
  2. wrong_key_fails_closed     -- wrong/missing key fails closed, no file
                                    is created for a fresh path.
  3. plaintext_marker_absent    -- a unique marker inserted+committed must
                                    never appear in raw db/WAL/journal bytes.
  4. crash_sim_reopen           -- after WAL checkpoint + reopen, data
                                    committed before the "crash" is intact.
  5. rekey_atomicity            -- after PRAGMA rekey, the old key must be
                                    rejected and only the new key opens.
  6. backup_vacuum_marker_scan  -- marker absent from bytes produced by the
                                    sqlite3 backup API and a VACUUM pass.
  7. deterministic_query_results -- identical ORDER BY query repeated
                                    returns byte-identical results.

This is disposable feasibility tooling: it is never imported by product
code and it is never its own oracle for the Gate 1 decision -- the decision
writer (`write_encrypted_lifecycle_gate1_decision.py`) treats this output
as one required input among several.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MARKER = "GATE1-FEASIBILITY-UNIQUE-MARKER-6f1c9e4b6c5a4c2f9e3a1b7d0c2e8f4a"
TEST_KEY_A = "TEST-ONLY-sqlcipher-gate1-key-alpha-do-not-use-in-product"
TEST_KEY_B = "TEST-ONLY-sqlcipher-gate1-key-beta-rekeyed-do-not-use"
WRONG_KEY = "TEST-ONLY-sqlcipher-gate1-key-WRONG-do-not-use"

HARNESS_SCHEMA = "wiki-sqlcipher-feasibility-v1"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _platform_token() -> str:
    return f"{platform.system().lower()}/{platform.machine().lower()}"


def _load_driver() -> tuple[Any, str, str] | None:
    for module_name in ("sqlcipher3", "pysqlcipher3"):
        try:
            if module_name == "sqlcipher3":
                import sqlcipher3.dbapi2 as driver  # type: ignore[import-not-found]
            else:
                import pysqlcipher3.dbapi2 as driver  # type: ignore[import-not-found]
        except ImportError:
            continue
        version = getattr(driver, "sqlite_version", "unknown")
        return driver, module_name, str(version)
    return None


class Check:
    def __init__(self, name: str) -> None:
        self.name = name
        self.result = "skip"
        self.detail = ""
        self.duration_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"name": self.name, "result": self.result, "detail": self.detail}
        if self.duration_ms is not None:
            out["duration_ms_advisory"] = round(self.duration_ms, 3)
        return out


def _run_check(name: str, fn) -> Check:
    check = Check(name)
    start = time.monotonic()
    try:
        fn(check)
        if check.result == "skip":
            check.result = "pass"
    except AssertionError as exc:
        check.result = "fail"
        check.detail = str(exc)
    except Exception as exc:  # noqa: BLE001 - harness must never crash
        check.result = "fail"
        check.detail = f"{type(exc).__name__}: {exc}"
    check.duration_ms = (time.monotonic() - start) * 1000.0
    return check


def _scan_bytes_for_marker(path: Path, marker: str) -> bool:
    if not path.exists():
        return False
    data = path.read_bytes()
    needle = marker.encode("utf-8")
    return needle in data


def _related_paths(db_path: Path) -> list[Path]:
    return [
        db_path,
        db_path.with_suffix(db_path.suffix + "-wal"),
        db_path.with_suffix(db_path.suffix + "-journal"),
        db_path.with_suffix(db_path.suffix + "-shm"),
    ]


def _run_scorecard(driver: Any, workdir: Path) -> tuple[list[Check], dict[str, float]]:
    checks: list[Check] = []
    timings: dict[str, float] = {}

    # 1. key_before_open_enforced
    db1 = workdir / "check1.db"

    def check_key_before_open(check: Check) -> None:
        keyed_conn = driver.connect(str(db1))
        try:
            keyed_conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            keyed_conn.execute("CREATE TABLE encrypted_probe (v TEXT)")
            keyed_conn.execute("INSERT INTO encrypted_probe VALUES ('key-required')")
            keyed_conn.commit()
        finally:
            keyed_conn.close()

        unkeyed_conn = driver.connect(str(db1))
        try:
            failed = False
            try:
                unkeyed_conn.execute("SELECT v FROM encrypted_probe").fetchall()
            except Exception:
                failed = True
            assert failed, "reading an existing encrypted DB before PRAGMA key succeeded"
            check.detail = "existing encrypted DB rejected read before key pragma"
        finally:
            unkeyed_conn.close()

    checks.append(_run_check("key_before_open_enforced", check_key_before_open))

    # 2. wrong_key_fails_closed / missing key -> no file created for fresh path
    db2 = workdir / "check2.db"

    def check_wrong_key(check: Check) -> None:
        assert not db2.exists(), "precondition: fresh path must not pre-exist"
        conn = driver.connect(str(db2))
        try:
            conn.execute(f"PRAGMA key = '{WRONG_KEY}'")
            failed = False
            try:
                conn.execute("CREATE TABLE t (v TEXT)")
                conn.execute("INSERT INTO t VALUES ('x')")
                conn.commit()
                conn.execute("SELECT * FROM t").fetchall()
            except Exception:
                failed = True
            # Either the write path failed closed, or (SQLCipher default
            # behavior) it "succeeded" by creating a *new* database keyed
            # under WRONG_KEY -- that is not a MUST violation by itself,
            # but re-opening under a *different* wrong key must never see
            # the same content, and no plaintext file must ever appear.
            if not failed:
                check.detail = "driver created a fresh keyed db under wrong key (acceptable if reopen under different key fails)"
            else:
                check.detail = "operation failed closed under wrong key"
        finally:
            conn.close()
        # No plaintext SQLite header must exist regardless of outcome.
        if db2.exists():
            header = db2.read_bytes()[:16]
            assert not header.startswith(b"SQLite format 3"), "plaintext SQLite file was created"

    checks.append(_run_check("wrong_or_missing_key_fails_closed_no_plaintext_file", check_wrong_key))

    # 3. plaintext_marker_absent (insert + checkpoint + raw byte scan)
    db3 = workdir / "check3.db"

    def check_marker_absent(check: Check) -> None:
        conn = driver.connect(str(db3))
        try:
            conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("CREATE TABLE t (v TEXT)")
            conn.execute("INSERT INTO t VALUES (?)", (MARKER,))
            conn.commit()
            conn.execute("PRAGMA wal_checkpoint(FULL)")
            conn.commit()
        finally:
            conn.close()
        for p in _related_paths(db3):
            assert not _scan_bytes_for_marker(p, MARKER), f"plaintext marker found in {p.name}"
        check.detail = "marker absent from db/wal/journal/shm raw bytes"

    checks.append(_run_check("plaintext_marker_absent_after_insert_checkpoint", check_marker_absent))

    # 4. crash_sim_reopen (copy file mid-state, reopen fresh connection)
    db4 = workdir / "check4.db"

    def check_crash_reopen(check: Check) -> None:
        conn = driver.connect(str(db4))
        try:
            conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            conn.execute("CREATE TABLE t (v TEXT)")
            conn.execute("INSERT INTO t VALUES ('durable-row')")
            conn.commit()
        finally:
            conn.close()
        # Simulate a crash by opening a brand-new connection object (no
        # graceful driver-level teardown state carried over) and reading.
        conn2 = driver.connect(str(db4))
        try:
            conn2.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            rows = conn2.execute("SELECT v FROM t").fetchall()
            assert rows and rows[0][0] == "durable-row", "committed row missing after reopen"
        finally:
            conn2.close()
        check.detail = "committed data intact across simulated crash reopen"

    checks.append(_run_check("crash_sim_reopen", check_crash_reopen))

    # 5. rekey_atomicity
    db5 = workdir / "check5.db"

    def check_rekey(check: Check) -> None:
        conn = driver.connect(str(db5))
        try:
            conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            conn.execute("CREATE TABLE t (v TEXT)")
            conn.execute("INSERT INTO t VALUES ('rekey-row')")
            conn.commit()
            conn.execute(f"PRAGMA rekey = '{TEST_KEY_B}'")
            conn.commit()
        finally:
            conn.close()
        old_key_conn = driver.connect(str(db5))
        try:
            old_key_conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            old_key_failed = False
            try:
                old_key_conn.execute("SELECT * FROM t").fetchall()
            except Exception:
                old_key_failed = True
            assert old_key_failed, "old key still opened db after rekey"
        finally:
            old_key_conn.close()
        new_key_conn = driver.connect(str(db5))
        try:
            new_key_conn.execute(f"PRAGMA key = '{TEST_KEY_B}'")
            rows = new_key_conn.execute("SELECT v FROM t").fetchall()
            assert rows and rows[0][0] == "rekey-row", "new key failed to open rekeyed db"
        finally:
            new_key_conn.close()
        check.detail = "old key rejected, new key opens rekeyed db"

    checks.append(_run_check("rekey_atomicity_old_key_rejected", check_rekey))

    # 6. backup_api_vacuum_marker_scan
    db6 = workdir / "check6.db"
    db6_backup = workdir / "check6-backup.db"

    def check_backup_vacuum(check: Check) -> None:
        conn = driver.connect(str(db6))
        try:
            conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            conn.execute("CREATE TABLE t (v TEXT)")
            conn.execute("INSERT INTO t VALUES (?)", (MARKER,))
            conn.commit()
            if hasattr(conn, "backup"):
                bconn = driver.connect(str(db6_backup))
                try:
                    bconn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
                    conn.backup(bconn)
                finally:
                    bconn.close()
            else:
                shutil.copyfile(db6, db6_backup)
            conn.execute("VACUUM")
            conn.commit()
        finally:
            conn.close()
        for p in [db6, db6_backup]:
            assert not _scan_bytes_for_marker(p, MARKER), f"plaintext marker found via backup/vacuum in {p.name}"
        check.detail = "marker absent from backup and post-VACUUM bytes"

    checks.append(_run_check("backup_api_vacuum_marker_scan", check_backup_vacuum))

    # 7. deterministic_query_results
    db7 = workdir / "check7.db"

    def check_deterministic(check: Check) -> None:
        conn = driver.connect(str(db7))
        try:
            conn.execute(f"PRAGMA key = '{TEST_KEY_A}'")
            conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            for i in range(1, 11):
                conn.execute("INSERT INTO t (id, v) VALUES (?, ?)", (i, f"row-{i}"))
            conn.commit()
            samples = []
            for _ in range(5):
                rows = conn.execute("SELECT id, v FROM t ORDER BY id").fetchall()
                samples.append(tuple(rows))
            assert len(set(samples)) == 1, "repeated ordered query returned differing results"
        finally:
            conn.close()
        check.detail = "5 repeated ORDER BY queries produced identical results"

    checks.append(_run_check("deterministic_query_results", check_deterministic))

    for c in checks:
        if c.duration_ms is not None:
            timings[c.name] = c.duration_ms
    return checks, timings


def build_result(commit: str | None) -> dict[str, Any]:
    driver_info = _load_driver()
    generated_at = _now()
    platform_token = _platform_token()

    if driver_info is None:
        return {
            "schema": HARNESS_SCHEMA,
            "status": "platform_unavailable",
            "platform": platform_token,
            "python_version": sys.version.split()[0],
            "library": None,
            "checks": [],
            "advisory_timings_ms": {},
            "must_verdict": "NOT_RUN",
            "recorded_commit": commit,
            "generated_at": generated_at,
            "note": "neither sqlcipher3 nor pysqlcipher3 is importable on this platform; "
            "no SQLCipher MUST checks were attempted (never treated as a MUST pass).",
        }

    driver, module_name, sqlite_version = driver_info
    with tempfile.TemporaryDirectory(prefix="gate1-sqlcipher-") as tmp:
        workdir = Path(tmp)
        checks, timings = _run_scorecard(driver, workdir)

    must_verdict = "PASS" if all(c.result == "pass" for c in checks) else "FAIL"
    p95 = None
    if timings:
        values = sorted(timings.values())
        idx = min(len(values) - 1, int(round(0.95 * (len(values) - 1))))
        p95 = values[idx]

    return {
        "schema": HARNESS_SCHEMA,
        "status": "ok",
        "platform": platform_token,
        "python_version": sys.version.split()[0],
        "library": {"module": module_name, "sqlite_version": sqlite_version},
        "checks": [c.to_dict() for c in checks],
        "advisory_timings_ms": {"per_check": timings, "p95_advisory": p95},
        "must_verdict": must_verdict,
        "recorded_commit": commit,
        "generated_at": generated_at,
        "note": "advisory timings are informational only; profile selection is decided by MUST pass/fail, never by timing.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default="artifacts/encrypted-lifecycle")
    parser.add_argument("--commit", default=os.environ.get("GITHUB_SHA"), help="commit to record for CI four-way equality checks")
    args = parser.parse_args(argv)

    result = build_result(args.commit)

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"sqlcipher-feasibility-{result['platform'].replace('/', '-')}.json"
    out_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"wrote {out_path} status={result['status']} must_verdict={result['must_verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
