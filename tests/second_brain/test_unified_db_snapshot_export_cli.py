from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from tests.second_brain.unified_db_export_support import (
    FIXTURE,
    SCRIPT,
    authority,
    load_mapping,
    plan_for,
    profile,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)


def _write_inputs(tmp_path: Path) -> tuple[Path, Path]:
    exported = profile()
    planned = plan_for(exported)
    profile_path = tmp_path / "profile.json"
    plan_path = tmp_path / "plan.json"
    _ = profile_path.write_bytes(canonical_bytes(exported.to_mapping()) + b"\n")
    _ = plan_path.write_bytes(canonical_bytes(planned.to_mapping()) + b"\n")
    return profile_path, plan_path


def test_cli_help_lists_fixture_verify_export_without_live_flags() -> None:
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout
    assert "fixture" in text
    assert "verify" in text
    assert "export" in text
    for banned in (
        "--import",
        "--cas",
        "--cas-root",
        "--key",
        "--key-fd",
        "--serve",
        "--promote",
        "--cutover",
        "--database",
        "--target",
    ):
        assert banned not in text


def test_cli_fixture_and_verify_in_isolated_temp(tmp_path: Path) -> None:
    before = (FIXTURE.stat().st_mtime_ns, FIXTURE.stat().st_size, FIXTURE.read_bytes())
    profile_path, plan_path = _write_inputs(tmp_path)
    dest = tmp_path / "pkg"
    fixture_run = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "fixture",
            "--profile",
            str(profile_path),
            "--plan",
            str(plan_path),
            "--fixture",
            str(FIXTURE),
            "--output",
            str(dest),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert fixture_run.returncode == 0, fixture_run.stderr
    assert dest.is_dir()
    receipt = UnifiedDbExportReceiptV1.from_mapping(load_mapping(dest / "receipt.json"))
    assert receipt.state == "FIXTURE_EXPORTED_NOT_AUTHORIZED"
    verify_run = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", "--package", str(dest)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert verify_run.returncode == 0, verify_run.stderr
    after = (FIXTURE.stat().st_mtime_ns, FIXTURE.stat().st_size, FIXTURE.read_bytes())
    assert before == after
    assert authority().authority_kind == "FIXTURE_ONLY"


def test_cli_export_refuses_before_dsn_fd_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    dest = tmp_path / "live"
    refused = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "export",
            "--dsn-fd",
            str(read_fd),
            "--output",
            str(dest),
        ],
        capture_output=True,
        check=False,
        pass_fds=(read_fd,),
    )
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"unapproved mapper" in refused.stderr
    assert leftover == payload
    assert not dest.exists()


def test_cli_verify_rejects_tampered_package(tmp_path: Path) -> None:
    profile_path, plan_path = _write_inputs(tmp_path)
    dest = tmp_path / "pkg"
    created = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "fixture",
            "--profile",
            str(profile_path),
            "--plan",
            str(plan_path),
            "--fixture",
            str(FIXTURE),
            "--output",
            str(dest),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert created.returncode == 0, created.stderr
    target = dest / "payload" / "00000000.json"
    os.chmod(dest / "payload", 0o700)
    os.chmod(target, 0o600)
    _ = target.write_bytes(target.read_bytes() + b"tamper")
    os.chmod(target, 0o400)
    os.chmod(dest / "payload", 0o500)
    refused = subprocess.run(
        [sys.executable, str(SCRIPT), "verify", "--package", str(dest)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert refused.returncode != 0
    assert stat.S_ISREG(os.lstat(dest / "receipt.json").st_mode)
