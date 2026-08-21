"""User-run public-only pending decision assemble runner."""
from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_RUNNER = Path("scripts/run_pending_decision_assemble.sh")
_SIGNER = Path("scripts/sign_second_brain_decision_role.py")
_STEMS = (
    "DB-02-claude-memory-bank",
    "DB-02-codex",
    "DB-02-git",
    "DB-02-markdown",
    "DB-03-legacy-mem0-rag",
    "DB-03-unified-db",
    "DB-07",
)
_BODY_DIR = Path("artifacts/product-release/second-brain-v1/decision-signing")


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> str:
    _ = path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    raw_public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw_public).decode("ascii")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RUNNER), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def test_assemble_prints_usage_when_help_requested() -> None:
    result = _run("--help")
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert "approver" in result.stdout.casefold()
    assert "owner" in result.stdout.casefold()
    assert "--private-key" not in combined
    assert "BEGIN" not in combined


def test_assemble_refuses_extra_args() -> None:
    result = _run("a", "b", "c", "d")
    assert result.returncode == 2
    assert "--private-key" not in result.stdout + result.stderr


def test_assemble_refuses_when_envelopes_are_missing(tmp_path: Path) -> None:
    approver = tmp_path / "approver"
    owner = tmp_path / "owner"
    out = tmp_path / "assembled"
    approver.mkdir()
    owner.mkdir()
    result = _run(str(approver), str(owner), str(out))
    assert result.returncode == 2
    assert "missing" in result.stderr
    assert not out.exists()


def test_assemble_refuses_symlink_output_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "link"
    linked.symlink_to(real, target_is_directory=True)
    approver = tmp_path / "approver"
    owner = tmp_path / "owner"
    approver.mkdir()
    owner.mkdir()
    result = _run(str(approver), str(owner), str(linked))
    assert result.returncode == 2
    assert "symlink" in result.stderr


def test_assemble_writes_six_create_only_records_when_public_envelopes_exist(
    tmp_path: Path,
) -> None:
    owner_key = Ed25519PrivateKey.generate()
    approver_key = Ed25519PrivateKey.generate()
    owner_pem = tmp_path / "owner.pem"
    approver_pem = tmp_path / "approver.pem"
    owner_b64 = _write_private_key(owner_pem, owner_key)
    approver_b64 = _write_private_key(approver_pem, approver_key)
    owner_dir = tmp_path / "owner"
    approver_dir = tmp_path / "approver"
    owner_dir.mkdir()
    approver_dir.mkdir()
    for stem in _STEMS:
        body = _BODY_DIR / f"{stem}.body.json"
        for role, pem, key_id, b64, dest_dir in (
            ("owner", owner_pem, "wiki-owner-2026", owner_b64, owner_dir),
            ("approver", approver_pem, "wiki-approver-2026", approver_b64, approver_dir),
        ):
            output = dest_dir / f"{stem}.{role}-envelope.json"
            signed = subprocess.run(
                [
                    sys.executable,
                    str(_SIGNER),
                    "--role",
                    role,
                    "--key-id",
                    key_id,
                    "--expected-public-key-b64",
                    b64,
                    "--body",
                    str(body),
                    "--private-key",
                    str(pem),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                check=False,
                text=True,
            )
            assert signed.returncode == 0, signed.stderr
    out = tmp_path / "assembled"
    result = _run(str(approver_dir), str(owner_dir), str(out))
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
    for stem in _STEMS:
        record = out / f"{stem}.json"
        assert record.is_file()
        parsed = decode_json_object(record.read_text(encoding="utf-8"))
        signatures = parsed["signatures"]
        assert isinstance(signatures, list)
        roles = [
            role
            for item in signatures
            if isinstance(item, dict) and isinstance((role := item.get("role")), str)
        ]
        assert roles == ["approver", "owner"]
        assert record.read_bytes() == canonical_bytes(parsed)
    second = _run(str(approver_dir), str(owner_dir), str(out))
    assert second.returncode == 2
    assert "already exists" in second.stderr
