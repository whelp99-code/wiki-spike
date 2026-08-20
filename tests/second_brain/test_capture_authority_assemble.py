"""User-run public-only POSTGRES_METADATA_CAPTURE_ONLY assemble runner."""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    authorization_body,
    sign_body,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_RUNNER = Path("scripts/run_pending_capture_authority_assemble.sh")
_CLI = Path("scripts/second_brain_unified_db_snapshot_export.py")


@dataclass(frozen=True, slots=True)
class AssembleInputs:
    body: Path
    approver: Path
    owner: Path
    dest: Path


def _run_runner(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RUNNER), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def _write_envelope(path: Path, envelope: Ed25519SignatureEnvelopeV1) -> None:
    _ = path.write_text(
        json.dumps(envelope.to_mapping(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _signed_inputs(tmp_path: Path) -> AssembleInputs:
    body = authorization_body()
    body_path = tmp_path / "POSTGRES_METADATA_CAPTURE_ONLY.body.json"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    approver_env, owner_env = sign_body(
        body, Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    )
    approver_path = tmp_path / "approver-envelope.json"
    owner_path = tmp_path / "owner-envelope.json"
    _write_envelope(approver_path, approver_env)
    _write_envelope(owner_path, owner_env)
    return AssembleInputs(
        body_path, approver_path, owner_path, tmp_path / "assembled.json"
    )


def test_runner_prints_usage_when_help_requested() -> None:
    result = _run_runner("--help")
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert "unsigned-body" in result.stdout or "body.json" in result.stdout
    order_lines = [
        line
        for line in result.stdout.splitlines()
        if "approver" in line.casefold()
        and "owner" in line.casefold()
        and "Usage:" not in line
    ]
    assert order_lines
    assert any(
        line.casefold().find("approver") < line.casefold().find("owner")
        for line in order_lines
    )
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
    assert "dsn" not in combined.casefold()


def test_runner_prints_usage_when_args_missing() -> None:
    result = _run_runner()
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_runner_refuses_when_extra_args_are_supplied(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    extra = tmp_path / "extra.json"
    _ = extra.write_text("{}", encoding="utf-8")
    result = _run_runner(
        str(paths.body),
        str(paths.approver),
        str(paths.owner),
        str(paths.dest),
        str(extra),
    )
    assert result.returncode == 2
    assert "Usage:" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_when_unsigned_body_is_missing(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    missing = tmp_path / "missing-body.json"
    result = _run_runner(
        str(missing), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    assert result.returncode == 2
    assert "unsigned body is missing" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_when_approver_envelope_is_missing(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    missing = tmp_path / "missing-approver.json"
    result = _run_runner(
        str(paths.body), str(missing), str(paths.owner), str(paths.dest)
    )
    assert result.returncode == 2
    assert "approver envelope is missing" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_when_owner_envelope_is_missing(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    missing = tmp_path / "missing-owner.json"
    result = _run_runner(
        str(paths.body), str(paths.approver), str(missing), str(paths.dest)
    )
    assert result.returncode == 2
    assert "owner envelope is missing" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_when_envelope_order_is_reversed(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    result = _run_runner(
        str(paths.body), str(paths.owner), str(paths.approver), str(paths.dest)
    )
    assert result.returncode == 2
    assert "approver then owner" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_when_body_is_symlink(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    linked = tmp_path / "body-link.json"
    linked.symlink_to(paths.body)
    result = _run_runner(
        str(linked), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert not paths.dest.exists()
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined


def test_runner_refuses_when_envelope_is_symlink(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    linked = tmp_path / "approver-link.json"
    linked.symlink_to(paths.approver)
    result = _run_runner(
        str(paths.body), str(linked), str(paths.owner), str(paths.dest)
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert not paths.dest.exists()
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined


def test_runner_refuses_when_dest_is_symlink(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    victim = tmp_path / "victim.json"
    _ = victim.write_text("keep-me", encoding="utf-8")
    paths.dest.symlink_to(victim)
    result = _run_runner(
        str(paths.body), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
    assert victim.read_text(encoding="utf-8") == "keep-me"
    assert paths.dest.is_symlink()


def test_runner_refuses_when_dest_already_exists(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    _ = paths.dest.write_text("keep-me", encoding="utf-8")
    result = _run_runner(
        str(paths.body), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    assert result.returncode == 2
    assert "already exists" in result.stderr
    assert paths.dest.read_text(encoding="utf-8") == "keep-me"


def test_runner_writes_create_only_assembled_envelope_when_order_is_approver_then_owner(
    tmp_path: Path,
) -> None:
    paths = _signed_inputs(tmp_path)
    result = _run_runner(
        str(paths.body), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert paths.dest.is_file()
    assert not paths.dest.is_symlink()
    assembled = decode_json_object(paths.dest.read_text(encoding="utf-8"))
    signatures = assembled["signatures"]
    assert isinstance(signatures, list)
    assert [item["role"] for item in signatures if isinstance(item, dict)] == [
        "approver",
        "owner",
    ]
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
    assert "private" not in paths.dest.read_text(encoding="utf-8").casefold()
    second = _run_runner(
        str(paths.body), str(paths.approver), str(paths.owner), str(paths.dest)
    )
    assert second.returncode == 2
    assert "already exists" in second.stderr


def test_runner_wraps_public_assemble_and_verify_without_private_keys_or_dsn() -> None:
    script = _RUNNER.read_text(encoding="utf-8")
    create_cli = Path(
        "src/wiki_spike/applications/unified_db_postgres_capture_authorization_cli.py"
    ).read_text(encoding="utf-8")
    signing = Path("scripts/run_pending_capture_authority_role_signing.sh")
    assert "capture-authority-assemble" in script
    assert "capture-authority-verify" in script
    assert str(_CLI) in script or _CLI.name in script
    assert "--private-key" not in script
    assert "--dsn-fd" not in script
    assert "BEGIN" not in script
    assert "PRIVATE KEY" not in script
    assert "capture-authority-create" in create_cli
    assert signing.is_file()
