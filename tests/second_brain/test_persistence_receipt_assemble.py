"""User-run public-only Mac persistence receipt assemble runner."""
from __future__ import annotations

import json
import subprocess
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    verify_mac_persistence_authorization,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_persistence import (
    PERSISTENCE_PROFILE_RECEIPT_V1,
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
    persistence_profile_authorization_payload,
)

_RUNNER = Path("scripts/run_pending_persistence_receipt_assemble.sh")
_CLI = Path("scripts/second_brain_persistence_receipt.py")
_PROFILE = Path("artifacts/product-release/second-brain-v1/persistence-profile.json")
_SQLCIPHER = Path(
    "artifacts/encrypted-lifecycle/sqlcipher-feasibility-darwin-arm64.json"
)
_RELEASE_RECEIPT = Path(
    "artifacts/product-release/second-brain-v1/persistence-receipt.json"
)
_AUTHORIZED_AT = "2026-08-21T00:00:00Z"
_SIGNATURE_VERSION = "second-brain-persistence-profile-signature-v1"
_OWNER_ID = "test-owner-2026"
_APPROVER_ID = "test-approver-2026"


@dataclass(frozen=True, slots=True)
class AssembleInputs:
    profile: Path
    authorized_at: str
    approver: Path
    owner: Path
    dest: Path
    owner_key: Ed25519PrivateKey
    approver_key: Ed25519PrivateKey


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RUNNER), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def _invoke(
    paths: AssembleInputs,
    *,
    approver: Path | None = None,
    owner: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return _run(
        str(paths.profile),
        paths.authorized_at,
        str(approver or paths.approver),
        str(owner or paths.owner),
        str(paths.dest),
    )


def _write_envelope(
    path: Path,
    *,
    role: str,
    key_id: str,
    signer: Ed25519PrivateKey,
    public_key: Ed25519PrivateKey,
    payload: dict[str, JsonValue],
) -> None:
    signature = crypto.sign(signer, PERSISTENCE_PROFILE_SIGNATURE_DOMAIN, payload)
    body = {
        "signature_version": _SIGNATURE_VERSION,
        "role": role,
        "key_id": key_id,
        "public_key_b64": b64encode(public_key.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
        "signature_b64": b64encode(bytes.fromhex(signature)).decode("ascii"),
    }
    _ = path.write_text(
        json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _signed_inputs(tmp_path: Path, *, untrusted: bool = False) -> AssembleInputs:
    profile = MacPersistenceProfileV1.from_mapping(
        json.loads(_PROFILE.read_text(encoding="utf-8"))
    )
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    payload = persistence_profile_authorization_payload(
        receipt_version=PERSISTENCE_PROFILE_RECEIPT_V1,
        profile_digest=profile.profile_digest,
        owner_key_id=_OWNER_ID,
        approver_key_id=_APPROVER_ID,
        authorized_at=_AUTHORIZED_AT,
    )
    approver_path = tmp_path / "approver-envelope.json"
    owner_path = tmp_path / "owner-envelope.json"
    displayed = Ed25519PrivateKey.generate() if untrusted else approver
    _write_envelope(
        approver_path,
        role="approver",
        key_id=_APPROVER_ID,
        signer=approver,
        public_key=displayed,
        payload=payload,
    )
    _write_envelope(
        owner_path,
        role="owner",
        key_id=_OWNER_ID,
        signer=owner,
        public_key=owner,
        payload=payload,
    )
    return AssembleInputs(
        _PROFILE,
        _AUTHORIZED_AT,
        approver_path,
        owner_path,
        tmp_path / "assembled-receipt.json",
        owner,
        approver,
    )


def test_runner_refuses_when_approver_envelope_is_missing(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    result = _invoke(paths, approver=tmp_path / "missing-approver.json")
    assert result.returncode != 0
    assert "approver envelope is missing" in result.stderr
    assert not paths.dest.exists()
    assert not _RELEASE_RECEIPT.exists()


def test_runner_refuses_when_dest_is_symlink(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    victim = tmp_path / "victim.json"
    _ = victim.write_text("keep-me", encoding="utf-8")
    paths.dest.symlink_to(victim)
    result = _invoke(paths)
    assert result.returncode != 0
    assert "symlink" in result.stderr
    assert victim.read_text(encoding="utf-8") == "keep-me"
    assert paths.dest.is_symlink()
    assert not _RELEASE_RECEIPT.exists()


def test_runner_refuses_when_dest_already_exists(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    _ = paths.dest.write_text("keep-me", encoding="utf-8")
    result = _invoke(paths)
    assert result.returncode != 0
    assert "already exists" in result.stderr
    assert paths.dest.read_text(encoding="utf-8") == "keep-me"


def test_runner_refuses_when_envelope_order_is_reversed(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path)
    result = _invoke(paths, approver=paths.owner, owner=paths.approver)
    assert result.returncode != 0
    assert "approver then owner" in result.stderr
    assert not paths.dest.exists()


def test_runner_refuses_untrusted_key(tmp_path: Path) -> None:
    paths = _signed_inputs(tmp_path, untrusted=True)
    result = _invoke(paths)
    assert result.returncode != 0
    assert "FAIL" in result.stderr
    assert not paths.dest.exists()
    assert not _RELEASE_RECEIPT.exists()


def test_runner_writes_create_only_receipt_and_second_assemble_refuses(
    tmp_path: Path,
) -> None:
    paths = _signed_inputs(tmp_path)
    result = _invoke(paths)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert paths.dest.is_file() and not paths.dest.is_symlink()
    assert not _RELEASE_RECEIPT.exists()
    body = json.loads(paths.dest.read_text(encoding="utf-8"))
    assert set(body) == PersistenceProfileReceiptV1.FIELDS
    receipt = PersistenceProfileReceiptV1.from_mapping(body)
    assert paths.dest.read_bytes() == canonical_bytes(receipt.to_mapping()) + b"\n"
    profile = MacPersistenceProfileV1.from_mapping(
        json.loads(paths.profile.read_text(encoding="utf-8"))
    )
    authorization = verify_mac_persistence_authorization(
        profile=profile,
        receipt=receipt,
        owner_key_id=_OWNER_ID,
        owner_public_key=paths.owner_key.public_key(),
        approver_key_id=_APPROVER_ID,
        approver_public_key=paths.approver_key.public_key(),
        sqlcipher_artifact_bytes=_SQLCIPHER.read_bytes(),
    )
    assert authorization.receipt_digest == receipt.receipt_digest
    with pytest.raises(PersistenceProfileAuthorizationError):
        _ = verify_mac_persistence_authorization(
            profile=profile,
            receipt=receipt,
            owner_key_id=_OWNER_ID,
            owner_public_key=Ed25519PrivateKey.generate().public_key(),
            approver_key_id=_APPROVER_ID,
            approver_public_key=paths.approver_key.public_key(),
            sqlcipher_artifact_bytes=_SQLCIPHER.read_bytes(),
        )
    assert "BEGIN" not in combined and "PRIVATE KEY" not in combined
    assert "private" not in paths.dest.read_text(encoding="utf-8").casefold()
    second = _invoke(paths)
    assert second.returncode != 0
    assert "already exists" in second.stderr
    script = _RUNNER.read_text(encoding="utf-8")
    cli = _CLI.read_text(encoding="utf-8")
    assert "assemble" in script and "verify" in script
    assert "--private-key" not in script and "--private-key" not in cli
    assert "BEGIN" not in script and "PRIVATE KEY" not in script
    assert not _RELEASE_RECEIPT.exists()
