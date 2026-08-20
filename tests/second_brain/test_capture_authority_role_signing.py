"""User-run public-only POSTGRES_METADATA_CAPTURE_ONLY role signing."""
from __future__ import annotations

import base64
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    authorization_body,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN,
    METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    metadata_capture_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_RUNNER = Path("scripts/run_pending_capture_authority_role_signing.sh")
_SIGNER = Path("scripts/sign_second_brain_capture_authority_role.py")
_BINDINGS = Path(
    "artifacts/product-release/second-brain-v1/governance/trusted-bindings.json"
)
_ENVELOPE_FIELDS = frozenset(
    {"signature_version", "role", "key_id", "public_key_b64", "signature_b64"}
)
_OUTPUT_NAME = "POSTGRES_METADATA_CAPTURE_ONLY.{role}-envelope.json"


def _run_runner(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RUNNER), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def _text(value: JsonValue) -> str:
    assert isinstance(value, str)
    return value


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


def _run_signer(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SIGNER), *argv],
        capture_output=True,
        check=False,
        text=True,
    )


def test_runner_prints_usage_when_help_requested() -> None:
    result = _run_runner("--help")
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert "owner|approver" in result.stdout
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


def test_runner_prints_usage_when_args_missing() -> None:
    result = _run_runner()
    assert result.returncode == 2
    assert "Usage:" in result.stderr


def test_runner_refuses_when_role_unknown(tmp_path: Path) -> None:
    key_path = tmp_path / "role.pem"
    _ = key_path.write_text("unused", encoding="utf-8")
    result = _run_runner("security", str(key_path), str(tmp_path / "out"))
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "unknown role" in result.stderr
    assert str(key_path) not in combined


def test_runner_refuses_when_unsigned_body_is_missing(tmp_path: Path) -> None:
    key_path = tmp_path / "owner.pem"
    _ = key_path.write_text("unused", encoding="utf-8")
    result = _run_runner("owner", str(key_path), str(tmp_path / "out"))
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "unsigned body is missing" in result.stderr
    assert str(key_path) not in combined
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined


def test_runner_refuses_when_output_is_symlink(tmp_path: Path) -> None:
    output_directory = tmp_path / "out"
    output_directory.mkdir()
    victim = tmp_path / "victim.json"
    _ = victim.write_text("keep-me", encoding="utf-8")
    planted = output_directory / _OUTPUT_NAME.format(role="owner")
    planted.symlink_to(victim)
    key_path = tmp_path / "owner.pem"
    _ = key_path.write_text("unused", encoding="utf-8")
    result = _run_runner("owner", str(key_path), str(output_directory))
    combined = result.stdout + result.stderr
    assert result.returncode == 2
    assert "symlink" in result.stderr
    assert str(key_path) not in combined
    assert victim.read_text(encoding="utf-8") == "keep-me"
    assert planted.is_symlink()


def test_signer_writes_public_envelope_schema_when_key_matches(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private_key = tmp_path / "owner.pem"
    expected_public_key_b64 = _write_private_key(private_key, key)
    body_path = tmp_path / "body.json"
    body = authorization_body()
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    output = tmp_path / "owner-envelope.json"
    result = _run_signer(
        [
            "--role",
            "owner",
            "--key-id",
            "wiki-owner-2026",
            "--expected-public-key-b64",
            expected_public_key_b64,
            "--body",
            str(body_path),
            "--private-key",
            str(private_key),
            "--output",
            str(output),
        ]
    )
    assert result.returncode == 0, result.stderr
    envelope = decode_json_object(output.read_text(encoding="utf-8"))
    assert set(envelope) == _ENVELOPE_FIELDS
    parsed = Ed25519SignatureEnvelopeV1.from_mapping(
        envelope, version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION
    )
    assert parsed.role == "owner"
    assert parsed.key_id == "wiki-owner-2026"
    assert parsed.public_key_b64 == expected_public_key_b64
    assert parsed.verify(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN, body)
    assert metadata_capture_authorization_signing_bytes(body).startswith(
        METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN
    )


def test_signer_omits_private_key_material_when_envelope_written(tmp_path: Path) -> None:
    key = Ed25519PrivateKey.generate()
    private_key = tmp_path / "approver.pem"
    expected_public_key_b64 = _write_private_key(private_key, key)
    pem = private_key.read_text(encoding="utf-8")
    body_path = tmp_path / "body.json"
    _ = body_path.write_bytes(canonical_bytes(authorization_body()) + b"\n")
    output = tmp_path / "approver-envelope.json"
    result = _run_signer(
        [
            "--role",
            "approver",
            "--key-id",
            "wiki-approver-2026",
            "--expected-public-key-b64",
            expected_public_key_b64,
            "--body",
            str(body_path),
            "--private-key",
            str(private_key),
            "--output",
            str(output),
        ]
    )
    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr + output.read_text(encoding="utf-8")
    assert str(private_key) not in combined
    assert pem not in combined
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined
    assert "private" not in output.read_text(encoding="utf-8").casefold()


def test_runner_pins_trusted_capture_key_bindings() -> None:
    script = _RUNNER.read_text(encoding="utf-8")
    raw = decode_json_object(_BINDINGS.read_text(encoding="utf-8"))
    bindings = raw["aggregate_binding"]
    assert isinstance(bindings, dict)
    owner_key_id = _text(bindings["owner_key_id"])
    approver_key_id = _text(bindings["approver_key_id"])
    owner_public = _text(bindings["owner_public_key_b64"])
    approver_public = _text(bindings["approver_public_key_b64"])
    assert owner_key_id == "wiki-owner-2026"
    assert approver_key_id == "wiki-approver-2026"
    assert owner_key_id in script
    assert approver_key_id in script
    assert owner_public in script
    assert approver_public in script
