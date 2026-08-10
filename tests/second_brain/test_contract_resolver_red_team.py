from __future__ import annotations

from base64 import b64encode
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import second_brain_contract_resolver as TOOL
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    detached_signing_bytes,
)

from test_contract_resolver_cli import (
    APPROVER,
    _decision,
    _evidence_envelope,
    arguments,
    build_inputs,
    trusted_authority,
)


def _resolve(paths: dict[str, Path], *, now: str | None = None) -> int:
    return TOOL.main(
        arguments(paths) if now is None else arguments(paths, now=now),
        trusted_authority=trusted_authority(),
    )


def _rewrite(path: Path, value: dict[str, object]) -> None:
    path.write_bytes(canonical_bytes(value))


def _evidence_body(paths: dict[str, Path]) -> dict[str, object]:
    return json.loads(paths["evidence"].read_bytes())["evidence_body"]


def _public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def test_public_cli_without_authority_rejects_before_timestamp_or_input_access(tmp_path, monkeypatch):
    paths = build_inputs(tmp_path)

    def accessed(*_args, **_kwargs):
        raise AssertionError("public no-authority invocation must not access inputs")

    monkeypatch.setattr(TOOL, "_timestamp", accessed)
    monkeypatch.setattr(TOOL, "_canonical_absolute_path", accessed)
    monkeypatch.setattr(TOOL, "_load_records", accessed)
    assert TOOL.main(arguments(paths)) == 2
    assert not paths["out"].exists()


def test_internal_failures_have_a_constant_non_leaking_cli_diagnostic(monkeypatch, capsys):
    def internal_failure(*_args, **_kwargs):
        raise RuntimeError("/private/receipt-path attacker-identity")

    monkeypatch.setattr(TOOL._Parser, "parse_args", internal_failure)
    assert TOOL.main(["resolve"]) == 2
    assert capsys.readouterr().err == "FAIL: RESOLVER_INTERNAL_REJECTED\n"


def test_attacker_self_signed_records_and_cli_binding_are_not_a_public_trust_root(tmp_path):
    paths = build_inputs(tmp_path)
    attacker_approver, attacker_owner = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    for record_path in paths["records"].glob("*.json"):
        record = json.loads(record_path.read_bytes())
        signed = {key: value for key, value in record.items() if key != "signatures"}
        payload = detached_signing_bytes(DECISION_SIGNING_DOMAIN, signed)
        record["signatures"] = [
            {
                "signature_version": DECISION_SIGNATURE_VERSION, "role": "approver",
                "key_id": "attacker-approver", "public_key_b64": _public(attacker_approver),
                "signature_b64": b64encode(attacker_approver.sign(payload)).decode("ascii"),
            },
            {
                "signature_version": DECISION_SIGNATURE_VERSION, "role": "owner",
                "key_id": "attacker-owner", "public_key_b64": _public(attacker_owner),
                "signature_b64": b64encode(attacker_owner.sign(payload)).decode("ascii"),
            },
        ]
        _rewrite(record_path, record)
    bindings = json.loads(paths["bindings"].read_bytes())
    for binding in [*bindings["decision_bindings"], bindings["aggregate_binding"]]:
        binding.update({
            "approver_key_id": "attacker-approver", "approver_public_key_b64": _public(attacker_approver),
            "owner_key_id": "attacker-owner", "owner_public_key_b64": _public(attacker_owner),
        })
    _rewrite(paths["bindings"], bindings)
    assert TOOL.main(arguments(paths)) == 2
    assert not paths["out"].exists()


def test_public_cli_cannot_backdate_an_expired_fixture_with_now(tmp_path):
    paths = build_inputs(tmp_path, expired=True)
    assert TOOL.main(arguments(paths, now="2026-08-09T11:00:00Z")) == 2
    assert not paths["out"].exists()


def test_injected_clock_rejects_an_expired_fixture_replayed_with_old_argv_now(tmp_path):
    paths = build_inputs(tmp_path, expired=True)
    assert TOOL.main(
        arguments(paths, now="2026-08-09T11:00:00Z"),
        trusted_authority=trusted_authority(now="2026-08-10T12:00:00Z"),
    ) == 2
    assert not paths["out"].exists()


@pytest.mark.parametrize(
    ("mutation", "target"),
    [
        ("untrusted_binding", "bindings"),
        ("same_identity", "bindings"),
        ("noncanonical_decision_timestamp", "records"),
        ("unknown_scope_field", "scope"),
        ("aggregate_mismatch", "aggregate"),
    ],
)
def test_adversarial_canonical_inputs_fail_closed_without_receipt(tmp_path, mutation, target):
    paths = build_inputs(tmp_path)
    if mutation == "untrusted_binding":
        body = json.loads(paths[target].read_bytes())
        body["decision_bindings"][0]["owner_key_id"] = "untrusted-owner"
        _rewrite(paths[target], body)
    elif mutation == "same_identity":
        body = json.loads(paths[target].read_bytes())
        body["aggregate_binding"]["owner_key_id"] = body["aggregate_binding"]["approver_key_id"]
        _rewrite(paths[target], body)
    elif mutation == "noncanonical_decision_timestamp":
        body = json.loads((paths[target] / "00.json").read_bytes())
        body["decided_at"] = "2026-08-09T11:00:00+00:00"
        _rewrite(paths[target] / "00.json", body)
    elif mutation == "unknown_scope_field":
        body = json.loads(paths[target].read_bytes())
        body["forged"] = "value"
        _rewrite(paths[target], body)
    else:
        body = json.loads(paths[target].read_bytes())
        body["contract_digest"] = "0" * 64
        _rewrite(paths[target], body)
    assert _resolve(paths) == 2
    assert not paths["out"].exists()


def test_timestamp_rewrite_without_resigning_is_rejected_before_freshness(tmp_path, capsys):
    paths = build_inputs(tmp_path)
    envelope = json.loads(paths["evidence"].read_bytes())
    envelope["evidence_body"]["observed_at"] = "2026-08-09T11:59:59Z"
    _rewrite(paths["evidence"], envelope)
    assert _resolve(paths) == 2
    assert "digest does not match" in capsys.readouterr().err
    assert not paths["out"].exists()


@pytest.mark.parametrize(
    "variant",
    ("untrusted_key", "same_signer", "wrong_domain", "reordered", "extra_signature"),
)
def test_evidence_signature_authority_and_shape_fail_closed(tmp_path, variant):
    paths = build_inputs(tmp_path)
    body = _evidence_body(paths)
    if variant == "untrusted_key":
        envelope = _evidence_envelope(body, owner=Ed25519PrivateKey.generate(), owner_key_id="outside")
    elif variant == "same_signer":
        envelope = _evidence_envelope(body, owner=APPROVER, owner_key_id="approver")
    elif variant == "wrong_domain":
        envelope = _evidence_envelope(body, domain=b"wrong-evidence-domain\x00")
    else:
        envelope = _evidence_envelope(body)
        if variant == "reordered":
            envelope["signatures"] = list(reversed(envelope["signatures"]))
        else:
            envelope["signatures"].append(envelope["signatures"][0])
    _rewrite(paths["evidence"], envelope)
    assert _resolve(paths) == 2
    assert not paths["out"].exists()


@pytest.mark.parametrize(
    ("observed_at", "expires_at", "expected_error"),
    [
        ("2026-08-09T11:00:00Z", "2026-08-09T12:00:00Z", "stale"),
        ("2026-08-09T12:00:01Z", "2026-08-09T13:00:00Z", "future"),
    ],
)
def test_stale_and_future_signed_evidence_are_rejected_after_signature_verification(
    tmp_path, capsys, observed_at, expires_at, expected_error,
):
    paths = build_inputs(tmp_path)
    body = _evidence_body(paths)
    body["observed_at"], body["expires_at"] = observed_at, expires_at
    _rewrite(paths["evidence"], _evidence_envelope(body))
    assert _resolve(paths) == 2
    assert expected_error in capsys.readouterr().err
    assert not paths["out"].exists()


def test_validly_resigned_expired_decision_reaches_expiry_rejection(tmp_path, capsys):
    paths = build_inputs(tmp_path, expired=True)
    assert _resolve(paths) == 2
    assert "decision is expired" in capsys.readouterr().err
    assert not paths["out"].exists()


def test_duplicate_scope_and_malformed_json_fail_closed(tmp_path):
    paths = build_inputs(tmp_path)
    (paths["records"] / "99.json").write_bytes((paths["records"] / "00.json").read_bytes())
    assert _resolve(paths) == 2
    assert not paths["out"].exists()

    paths = build_inputs(tmp_path / "malformed")
    (paths["records"] / "00.json").write_bytes(b'{"decision_id":"DB-01","decision_id":"DB-01"}')
    assert _resolve(paths) == 2
    assert not paths["out"].exists()


def test_missing_and_extra_scopes_fail_closed(tmp_path):
    paths = build_inputs(tmp_path)
    (paths["records"] / "12.json").unlink()
    assert _resolve(paths) == 2
    assert not paths["out"].exists()

    paths = build_inputs(tmp_path / "extra")
    _rewrite(paths["records"] / "99.json", _decision("DB-06", "model-b"))
    assert _resolve(paths) == 2
    assert not paths["out"].exists()


@pytest.mark.parametrize("target", ("records", "out"))
def test_relative_and_ancestor_symlink_paths_are_rejected(tmp_path, target):
    paths = build_inputs(tmp_path)
    args = arguments(paths)
    option = "--records-dir" if target == "records" else "--out"
    index = args.index(option) + 1
    args[index] = "records" if target == "records" else "receipt.json"
    assert TOOL.main(args, trusted_authority=trusted_authority()) == 2
    assert not paths["out"].exists()

    paths = build_inputs(tmp_path / f"alias-{target}")
    alias = paths["out"].parent / "alias"
    alias.symlink_to(paths["out"].parent, target_is_directory=True)
    args = arguments(paths)
    index = args.index(option) + 1
    args[index] = str(alias / ("records" if target == "records" else "receipt.json"))
    assert TOOL.main(args, trusted_authority=trusted_authority()) == 2
    assert not paths["out"].exists()


def test_atomic_publication_leaves_no_final_or_temp_receipt_on_write_failure(tmp_path, monkeypatch):
    paths = build_inputs(tmp_path)
    monkeypatch.setattr(TOOL.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("forced fsync failure")))
    assert _resolve(paths) == 2
    assert not paths["out"].exists()
    assert not list(paths["out"].parent.glob(f".{paths['out'].name}.*.tmp"))


def test_second_directory_fsync_failure_unlinks_our_published_inode(tmp_path, monkeypatch):
    paths = build_inputs(tmp_path)
    actual_fsync = TOOL.os.fsync
    calls = 0

    def fail_only_post_link_fsync(descriptor):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("forced post-link fsync failure")
        return actual_fsync(descriptor)

    monkeypatch.setattr(TOOL.os, "fsync", fail_only_post_link_fsync)
    assert _resolve(paths) == 2
    assert calls == 3
    assert not paths["out"].exists()
    assert not list(paths["out"].parent.glob(f".{paths['out'].name}.*.tmp"))


def test_existing_output_is_an_immutable_collision_and_is_left_untouched(tmp_path):
    paths = build_inputs(tmp_path)
    paths["out"].write_bytes(b"tampered")
    assert _resolve(paths) == 2
    assert paths["out"].read_bytes() == b"tampered"
