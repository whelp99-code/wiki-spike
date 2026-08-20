"""CLI tests for public metadata-capture signing-bytes, inspect, and envelopes."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    SCRIPT,
    authorization_body,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
    export_only_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN,
    metadata_capture_authorization_signing_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _run(args: list[str], *, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )


def test_help_lists_capture_authority_commands_without_private_key_flags() -> None:
    completed = _run(["--help"])
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout.decode("utf-8")
    assert "capture-authority-signing-bytes" in text
    assert "capture-authority-inspect" in text
    assert "capture-authority-envelope" in text
    assert "capture-authority-assemble" in text
    assert "capture-authority-verify" in text
    for banned in ("--key ", "--key-fd", "--private-key", "--import", "--serve"):
        assert banned not in text


def test_signing_bytes_and_inspect_round_trip_public_body(tmp_path: Path) -> None:
    body = authorization_body()
    body_path = tmp_path / "body.json"
    out = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    emitted = _run(
        ["capture-authority-signing-bytes", "--body", str(body_path), "--out", str(out)]
    )
    assert emitted.returncode == 0, emitted.stderr
    payload = out.read_bytes()
    assert payload == metadata_capture_authorization_signing_bytes(body)
    assert payload.startswith(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN)
    inspected = _run(["capture-authority-inspect", "--signing-bytes", str(out)])
    assert inspected.returncode == 0, inspected.stderr
    shown = decode_json_object(inspected.stdout.decode("utf-8"))
    expected = decode_json_object(canonical_bytes(body).decode("utf-8"))
    assert shown == expected


def test_inspect_refuses_export_domain_or_tampered_bytes(tmp_path: Path) -> None:
    body = authorization_body()
    body_path = tmp_path / "body.json"
    out = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    emitted = _run(
        ["capture-authority-signing-bytes", "--body", str(body_path), "--out", str(out)]
    )
    assert emitted.returncode == 0, emitted.stderr
    tampered = tmp_path / "bad.bin"
    _ = tampered.write_bytes(out.read_bytes() + b"X")
    refused = _run(["capture-authority-inspect", "--signing-bytes", str(tampered)])
    assert refused.returncode != 0
    wrong_domain = tmp_path / "export.bin"
    _ = wrong_domain.write_bytes(export_only_authorization_signing_bytes(body))
    assert wrong_domain.read_bytes().startswith(EXPORT_ONLY_AUTHORIZATION_DOMAIN)
    domain = _run(["capture-authority-inspect", "--signing-bytes", str(wrong_domain)])
    assert domain.returncode != 0


def test_public_envelopes_verify_and_reject_tamper(tmp_path: Path) -> None:
    body = authorization_body()
    body_path = tmp_path / "body.json"
    signing = tmp_path / "signing.bin"
    _ = body_path.write_bytes(canonical_bytes(body) + b"\n")
    emitted = _run(
        ["capture-authority-signing-bytes", "--body", str(body_path), "--out", str(signing)]
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
    owner_wrap = _run(
        [
            "capture-authority-envelope",
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
            "capture-authority-envelope",
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
    owner_env = tmp_path / "owner.json"
    approver_env = tmp_path / "approver.json"
    _ = owner_env.write_bytes(owner_wrap.stdout)
    _ = approver_env.write_bytes(approver_wrap.stdout)
    assembled = tmp_path / "assembled.json"
    built = _run(
        [
            "capture-authority-assemble",
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
            "capture-authority-verify",
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
    edited["authorization_id"] = "capture-auth-009"
    bad_body = tmp_path / "edited.json"
    _ = bad_body.write_bytes(canonical_bytes(edited) + b"\n")
    tampered = _run(
        [
            "capture-authority-verify",
            "--body",
            str(bad_body),
            "--signature",
            str(owner_env),
            "--signature",
            str(approver_env),
        ]
    )
    assert tampered.returncode != 0


def test_production_capture_still_refuses_before_dsn_fd_read(tmp_path: Path) -> None:
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    dest = tmp_path / "capture-out"
    refused = _run(
        ["capture", "--dsn-fd", str(read_fd), "--output", str(dest)],
        pass_fds=(read_fd,),
    )
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"owner approval required" in refused.stderr
    assert leftover == payload
    assert not dest.exists()
