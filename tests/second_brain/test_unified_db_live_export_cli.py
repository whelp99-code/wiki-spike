"""Public inspect/verify/preflight CLI for body-free live-export contracts."""
from __future__ import annotations

import datetime
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.second_brain.unified_db_live_export_support import (
    SCRIPT,
    bound_authorization,
    consistent_live_export_bundle,
    identity_body,
    live_plan_body,
    mapping_body,
    quiescence_body,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _run(args: list[str], *, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )


def _write_bundle(tmp_path: Path, *, fresh: bool = True) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    bundle = consistent_live_export_bundle()
    if fresh:
        current = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
        captured_at = current.isoformat().replace("+00:00", "Z")
        expires_at = (current + datetime.timedelta(minutes=15)).isoformat().replace(
            "+00:00", "Z"
        )
        bundle["identity"] = identity_body(captured_at=captured_at)
        bundle["mapping"] = mapping_body(
            str(bundle["identity"]["identity_digest"])
        )
        bundle["quiescence"] = quiescence_body(
            str(bundle["identity"]["identity_digest"]),
            captured_at=captured_at,
        )
        bundle["plan"] = live_plan_body(bundle)
        bundle["authorization"] = bound_authorization(
            bundle["plan"],
            issued_at=captured_at,
            not_before=captured_at,
            expires_at=expires_at,
        )
    paths: dict[str, Path] = {}
    for name, payload in bundle.items():
        path = tmp_path / f"{name}.json"
        _ = path.write_bytes(canonical_bytes(payload) + b"\n")
        paths[name] = path
    return paths


def _verify_args(paths: dict[str, Path]) -> list[str]:
    return [
        "--plan",
        str(paths["plan"]),
        "--identity",
        str(paths["identity"]),
        "--mapping",
        str(paths["mapping"]),
        "--adapter",
        str(paths["adapter"]),
        "--destination",
        str(paths["destination"]),
        "--quiescence",
        str(paths["quiescence"]),
        "--authorization",
        str(paths["authorization"]),
    ]


def test_help_lists_live_inspect_verify_preflight_without_dsn_on_inspect() -> None:
    completed = _run(["--help"])
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout.decode("utf-8")
    assert "live-inspect" in text
    assert "live-verify" in text
    assert "live-preflight" in text
    inspect_help = _run(["live-inspect", "--help"])
    assert inspect_help.returncode == 0, inspect_help.stderr
    assert b"--dsn-fd" not in inspect_help.stdout
    assert b"--key" not in inspect_help.stdout


def test_live_inspect_and_verify_accept_synthetic_body_free_fixtures(
    tmp_path: Path,
) -> None:
    paths = _write_bundle(tmp_path)
    inspected = _run(
        ["live-inspect", "--kind", "identity", "--input", str(paths["identity"])]
    )
    assert inspected.returncode == 0, inspected.stderr
    shown = decode_json_object(inspected.stdout.decode("utf-8"))
    assert shown["identity_version"] == "second-brain-unified-db-postgres-identity-v1"
    assert "body" not in shown
    verified = _run(["live-verify", *_verify_args(paths)])
    assert verified.returncode == 0, verified.stderr
    report = decode_json_object(verified.stdout.decode("utf-8"))
    assert report["verified"] is True

    stale_paths = _write_bundle(tmp_path / "stale", fresh=False)
    stale = _run(["live-verify", *_verify_args(stale_paths)])
    assert stale.returncode != 0
    assert b"identity is stale" in stale.stderr


def test_live_inspect_rejects_malformed_identity(tmp_path: Path) -> None:
    path = tmp_path / "bad-identity.json"
    _ = path.write_bytes(canonical_bytes(identity_body(system_identifier="016")) + b"\n")
    refused = _run(["live-inspect", "--kind", "identity", "--input", str(path)])
    assert refused.returncode != 0
    assert b"refused" in refused.stderr


def test_live_preflight_uses_empty_production_registry(tmp_path: Path) -> None:
    paths = _write_bundle(tmp_path)
    refused = _run(["live-preflight", *_verify_args(paths)])
    assert refused.returncode != 0
    assert b"unapproved mapper" in refused.stderr


def test_cli_export_still_leaves_dsn_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    support = tmp_path / "Library" / "Application Support"
    support.mkdir(parents=True)
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    dest = tmp_path / "live"
    refused = _run(
        ["export", "--dsn-fd", str(read_fd), "--output", str(dest)],
        pass_fds=(read_fd,),
    )
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"unapproved mapper" in refused.stderr
    assert leftover == payload
    assert not dest.exists()
