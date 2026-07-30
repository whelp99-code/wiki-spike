"""Tests for scripts/second_brain_decision.py.

The tool exists so an owner can produce a valid DB-01..DB-08 record without
reimplementing this repository's canonicalisation. These tests pin the two
properties that matter: the happy path really produces a contract-valid record,
and the tool cannot be used to manufacture an approval.
"""
from __future__ import annotations

import importlib.util
import json
from base64 import b64encode
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    DecisionRecordV1,
)

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "second_brain_decision.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("second_brain_decision", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


def raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def body(tmp_path: Path, **overrides) -> Path:
    payload = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": "DB-03",
        "outcome": "GO",
        "scope_kind": "migration_source",
        "scope_name": "unified-db",
        "record_revision": "1",
        "decided_at": "2026-07-30T00:00:00Z",
        "supersedes": None,
        "post_interview_reconciliation": {"original_question": "q", "reconciliation": "r"},
        "reason": "test",
        "evidence_refs": ["artifacts/example.json"],
        "evidence_digest": "a" * 64,
        "expires_at": "2099-01-01T00:00:00Z",
    }
    payload.update(overrides)
    path = tmp_path / "body.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def envelope(tmp_path: Path, role: str, key: Ed25519PrivateKey, signed: bytes, name: str) -> Path:
    data = {
        "signature_version": DECISION_SIGNATURE_VERSION,
        "role": role,
        "key_id": f"{role}-key",
        "public_key_b64": b64encode(raw_public_bytes(key)).decode("ascii"),
        "signature_b64": b64encode(key.sign(signed)).decode("ascii"),
    }
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def signed_record(tmp_path: Path) -> tuple[Path, Path]:
    body_path = body(tmp_path)
    payload = TOOL.signing_bytes(json.loads(body_path.read_text(encoding="utf-8")))
    owner, approver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    owner_env = envelope(tmp_path, "owner", owner, payload, "owner.json")
    approver_env = envelope(tmp_path, "approver", approver, payload, "approver.json")
    out = tmp_path / "record.json"
    assert (
        TOOL.main(
            [
                "assemble",
                "--body", str(body_path),
                "--signature", str(owner_env),
                "--signature", str(approver_env),
                "--out", str(out),
            ]
        )
        == 0
    )
    return body_path, out


def test_signing_bytes_are_the_domain_prefixed_canonical_body(tmp_path):
    body_path = body(tmp_path)
    payload = TOOL.signing_bytes(json.loads(body_path.read_text(encoding="utf-8")))
    assert payload.startswith(DECISION_SIGNING_DOMAIN)
    # Signing bytes must not depend on key order in the source file.
    reordered = dict(reversed(list(json.loads(body_path.read_text(encoding="utf-8")).items())))
    assert TOOL.signing_bytes(reordered) == payload


def test_assembled_record_is_contract_valid_and_canonically_ordered(tmp_path):
    _, record_path = signed_record(tmp_path)
    record = DecisionRecordV1.from_mapping(json.loads(record_path.read_text(encoding="utf-8")))
    assert record.decision_id == "DB-03"
    assert tuple(item.role for item in record.signatures) == ("approver", "owner")
    assert all(
        item.verify(DECISION_SIGNING_DOMAIN, record.signing_payload())
        for item in record.signatures
    )
    assert TOOL.main(["verify", "--record", str(record_path)]) == 0


def test_verify_reports_failure_when_the_signed_body_is_edited(tmp_path):
    _, record_path = signed_record(tmp_path)
    record = json.loads(record_path.read_text(encoding="utf-8"))
    record["outcome"] = "NO_GO"
    record_path.write_text(json.dumps(record), encoding="utf-8")
    assert TOOL.main(["verify", "--record", str(record_path)]) == 1


def test_assemble_refuses_a_body_edited_after_signing(tmp_path):
    body_path = body(tmp_path)
    payload = TOOL.signing_bytes(json.loads(body_path.read_text(encoding="utf-8")))
    owner, approver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    owner_env = envelope(tmp_path, "owner", owner, payload, "owner.json")
    approver_env = envelope(tmp_path, "approver", approver, payload, "approver.json")
    edited = body(tmp_path, evidence_digest="b" * 64)
    assert (
        TOOL.main(
            [
                "assemble",
                "--body", str(edited),
                "--signature", str(owner_env),
                "--signature", str(approver_env),
                "--out", str(tmp_path / "out.json"),
            ]
        )
        == 2
    )


@pytest.mark.parametrize("roles", [("owner",), ("owner", "owner"), ("approver", "approver")])
def test_assemble_requires_exactly_one_owner_and_one_approver(tmp_path, roles):
    body_path = body(tmp_path)
    payload = TOOL.signing_bytes(json.loads(body_path.read_text(encoding="utf-8")))
    args = ["assemble", "--body", str(body_path)]
    for index, role in enumerate(roles):
        key = Ed25519PrivateKey.generate()
        args += ["--signature", str(envelope(tmp_path, role, key, payload, f"{index}.json"))]
    args += ["--out", str(tmp_path / "out.json")]
    assert TOOL.main(args) == 2


def test_signing_bytes_refuses_an_already_signed_record(tmp_path):
    _, record_path = signed_record(tmp_path)
    assert TOOL.main(["signing-bytes", "--body", str(record_path)]) == 2


def test_envelope_rejects_a_signature_or_key_of_the_wrong_length(tmp_path):
    key = Ed25519PrivateKey.generate()
    good_key = tmp_path / "key.raw"
    good_key.write_bytes(raw_public_bytes(key))
    short = tmp_path / "short.sig"
    short.write_bytes(b"\x00" * 63)
    assert (
        TOOL.main(
            [
                "envelope", "--role", "owner", "--key-id", "k",
                "--public-key", str(good_key), "--signature", str(short),
            ]
        )
        == 2
    )
    good_sig = tmp_path / "good.sig"
    good_sig.write_bytes(key.sign(b"x"))
    spki = tmp_path / "spki.der"
    spki.write_bytes(
        key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    # A 44-byte SubjectPublicKeyInfo is the classic mistake; it must be rejected.
    assert (
        TOOL.main(
            [
                "envelope", "--role", "owner", "--key-id", "k",
                "--public-key", str(spki), "--signature", str(good_sig),
            ]
        )
        == 2
    )


def test_skeleton_enforces_the_scope_kind_of_each_decision(tmp_path):
    # DB-05 is global and takes no scope name; DB-03 is scoped and requires one.
    assert TOOL.main(["skeleton", "--decision-id", "DB-05"]) == 0
    assert TOOL.main(["skeleton", "--decision-id", "DB-05", "--scope-name", "x"]) == 2
    assert TOOL.main(["skeleton", "--decision-id", "DB-03", "--scope-name", "unified-db"]) == 0
    assert TOOL.main(["skeleton", "--decision-id", "DB-03"]) == 2
    assert TOOL.main(["skeleton", "--decision-id", "DB-99"]) == 2


def test_body_with_unknown_or_missing_fields_is_rejected(tmp_path):
    path = tmp_path / "body.json"
    payload = json.loads(body(tmp_path).read_text(encoding="utf-8"))
    payload["extra"] = 1
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert TOOL.main(["signing-bytes", "--body", str(path)]) == 2
    del payload["extra"], payload["reason"]
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert TOOL.main(["signing-bytes", "--body", str(path)]) == 2


def test_duplicate_json_keys_are_rejected(tmp_path):
    path = tmp_path / "body.json"
    path.write_text('{"decision_id": "DB-03", "decision_id": "DB-05"}', encoding="utf-8")
    assert TOOL.main(["signing-bytes", "--body", str(path)]) == 2


def test_tool_source_holds_no_private_key_material():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("Ed25519PrivateKey", "private_bytes", "generate()", "-----BEGIN"):
        assert forbidden not in source, f"{forbidden} must never appear in the tool"
    digest = sha256(SCRIPT.read_bytes()).hexdigest()
    assert len(digest) == 64
