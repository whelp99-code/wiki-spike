"""CLI tests for public LIVE_EXPORT_ONLY signing-bytes, inspect, and envelopes."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.second_brain.unified_db_export_authorization_support import (
    SCRIPT,
    authorization_body,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
    export_only_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _run(args: list[str], *, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )


def test_help_lists_authority_commands_without_private_key_flags() -> None:
    completed = _run(["--help"])
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout.decode("utf-8")
    assert "authority-signing-bytes" in text
    assert "authority-inspect" in text
    assert "authority-envelope" in text
    assert "authority-assemble" in text
    assert "authority-verify" in text
    for banned in ("--key ", "--key-fd", "--private-key", "--import", "--serve"):
        assert banned not in text


def test_signing_bytes_and_inspect_round_trip_public_body(tmp_path: Path) -> None:
    body = authorization_body()
    body_path = tmp_path / "body.json"
    out = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    emitted = _run(
        ["authority-signing-bytes", "--body", str(body_path), "--out", str(out)]
    )
    assert emitted.returncode == 0, emitted.stderr
    payload = out.read_bytes()
    assert payload == export_only_authorization_signing_bytes(body)
    assert payload.startswith(EXPORT_ONLY_AUTHORIZATION_DOMAIN)
    inspected = _run(["authority-inspect", "--signing-bytes", str(out)])
    assert inspected.returncode == 0, inspected.stderr
    shown = decode_json_object(inspected.stdout.decode("utf-8"))
    expected = decode_json_object(canonical_bytes(body).decode("utf-8"))
    assert shown == expected


def test_inspect_refuses_wrong_domain_or_tampered_bytes(tmp_path: Path) -> None:
    body_path = tmp_path / "body.json"
    out = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(authorization_body()) + b"\n")
    emitted = _run(
        ["authority-signing-bytes", "--body", str(body_path), "--out", str(out)]
    )
    assert emitted.returncode == 0, emitted.stderr
    tampered = tmp_path / "bad.bin"
    _ = tampered.write_bytes(out.read_bytes() + b"X")
    refused = _run(["authority-inspect", "--signing-bytes", str(tampered)])
    assert refused.returncode != 0
    wrong_domain = tmp_path / "domain.bin"
    _ = wrong_domain.write_bytes(b"wiki-spike.second-brain.decision.v1\x00" + b"{}")
    domain = _run(["authority-inspect", "--signing-bytes", str(wrong_domain)])
    assert domain.returncode != 0


def test_public_envelopes_verify_and_reject_tamper(tmp_path: Path) -> None:
    body = authorization_body()
    body_path = tmp_path / "body.json"
    signing = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    emitted = _run(
        ["authority-signing-bytes", "--body", str(body_path), "--out", str(signing)]
    )
    assert emitted.returncode == 0, emitted.stderr
    payload = signing.read_bytes()
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    owner_pub = tmp_path / "owner.pub"
    approver_pub = tmp_path / "approver.pub"
    owner_sig = tmp_path / "owner.sig"
    approver_sig = tmp_path / "approver.sig"
    _ = owner_pub.write_bytes(
        owner.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    _ = approver_pub.write_bytes(
        approver.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    _ = owner_sig.write_bytes(owner.sign(payload))
    _ = approver_sig.write_bytes(approver.sign(payload))
    owner_env = tmp_path / "owner.json"
    approver_env = tmp_path / "approver.json"
    owner_wrap = _run(
        [
            "authority-envelope",
            "--role",
            "owner",
            "--key-id",
            "owner",
            "--public-key",
            str(owner_pub),
            "--signature",
            str(owner_sig),
        ]
    )
    approver_wrap = _run(
        [
            "authority-envelope",
            "--role",
            "approver",
            "--key-id",
            "security-approver",
            "--public-key",
            str(approver_pub),
            "--signature",
            str(approver_sig),
        ]
    )
    assert owner_wrap.returncode == 0, owner_wrap.stderr
    assert approver_wrap.returncode == 0, approver_wrap.stderr
    _ = owner_env.write_bytes(owner_wrap.stdout)
    _ = approver_env.write_bytes(approver_wrap.stdout)
    assembled = tmp_path / "assembled.json"
    built = _run(
        [
            "authority-assemble",
            "--body",
            str(body_path),
            "--signature",
            str(owner_env),
            "--signature",
            str(approver_env),
            "--out",
            str(assembled),
        ]
    )
    assert built.returncode == 0, built.stderr
    verified = _run(
        [
            "authority-verify",
            "--body",
            str(body_path),
            "--signature",
            str(owner_env),
            "--signature",
            str(approver_env),
        ]
    )
    assert verified.returncode == 0, verified.stderr
    edited = authorization_body()
    edited["authorization_id"] = "export-auth-009"
    bad_body = tmp_path / "edited.json"
    _ = bad_body.write_bytes(canonical_bytes(edited) + b"\n")
    tampered = _run(
        [
            "authority-verify",
            "--body",
            str(bad_body),
            "--signature",
            str(owner_env),
            "--signature",
            str(approver_env),
        ]
    )
    assert tampered.returncode != 0


def test_live_export_still_refuses_before_dsn_fd_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
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
    assert b"executable mapping and signed authority" in refused.stderr
    assert leftover == payload
    assert not dest.exists()
