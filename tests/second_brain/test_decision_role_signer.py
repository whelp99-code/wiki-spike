from __future__ import annotations

import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts.second_brain_decision import signing_bytes

_SCRIPT = Path("scripts/sign_second_brain_decision_role.py")
_BODY = Path(
    "artifacts/product-release/second-brain-v1/decision-signing/DB-07.body.json"
)


def _write_private_key(path: Path, key: Ed25519PrivateKey) -> str:
    path.write_bytes(
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


def _run(
    private_key: Path,
    expected_public_key_b64: str,
    output: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--role",
            "owner",
            "--key-id",
            "synthetic-owner",
            "--expected-public-key-b64",
            expected_public_key_b64,
            "--body",
            str(_BODY),
            "--private-key",
            str(private_key),
            "--output",
            str(output),
        ],
        capture_output=True,
        check=False,
        text=True,
    )


def test_role_signer_emits_verified_envelope_without_key_material(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    private_key = tmp_path / "owner.pem"
    expected_public_key_b64 = _write_private_key(private_key, key)
    output = tmp_path / "owner-envelope.json"

    result = _run(private_key, expected_public_key_b64, output)

    assert result.returncode == 0, result.stderr
    assert str(private_key) not in result.stdout + result.stderr
    envelope = json.loads(output.read_text(encoding="utf-8"))
    body = json.loads(_BODY.read_text(encoding="utf-8"))
    signature = base64.b64decode(envelope["signature_b64"], validate=True)
    key.public_key().verify(signature, signing_bytes(body))
    assert envelope["role"] == "owner"
    assert envelope["key_id"] == "synthetic-owner"
    assert envelope["public_key_b64"] == expected_public_key_b64
    assert "private" not in output.read_text(encoding="utf-8").casefold()


@pytest.mark.parametrize("mode", [0o644, 0o640])
def test_role_signer_rejects_broad_key_permissions(
    tmp_path: Path,
    mode: int,
) -> None:
    key = Ed25519PrivateKey.generate()
    private_key = tmp_path / "owner.pem"
    expected_public_key_b64 = _write_private_key(private_key, key)
    private_key.chmod(mode)
    output = tmp_path / "owner-envelope.json"

    result = _run(private_key, expected_public_key_b64, output)

    assert result.returncode != 0
    assert "permissions" in result.stderr
    assert not output.exists()


def test_role_signer_rejects_wrong_public_binding_and_existing_output(
    tmp_path: Path,
) -> None:
    key = Ed25519PrivateKey.generate()
    private_key = tmp_path / "owner.pem"
    _ = _write_private_key(private_key, key)
    other_key = Ed25519PrivateKey.generate()
    wrong_public = base64.b64encode(
        other_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")
    output = tmp_path / "owner-envelope.json"

    wrong = _run(private_key, wrong_public, output)

    assert wrong.returncode != 0
    assert "trusted public binding" in wrong.stderr
    assert not output.exists()
    output.write_text("occupied", encoding="utf-8")
    existing = _run(private_key, wrong_public, output)
    assert existing.returncode != 0
    assert "already exists" in existing.stderr
