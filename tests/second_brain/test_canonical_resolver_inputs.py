"""Canonical resolver inputs preserve the personal-key signing boundary."""
from __future__ import annotations

import base64
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export_json import (
    decode_json_object,
)

_ROOT = Path(__file__).resolve().parents[2]
_BUILDER = _ROOT / "scripts/build_canonical_resolver_inputs.py"
_SIGNER = _ROOT / "scripts/sign_second_brain_resolver_role.py"
_CLI = _ROOT / "scripts/second_brain_contract_resolver.py"
_COVERAGE = "decision evidence does not exactly match the expected-scope manifest"
_REAL_RELEASE = _ROOT / "artifacts/product-release/second-brain-v1"


def _run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *arguments],
        capture_output=True,
        check=False,
        text=True,
    )


def _public_b64(key: Ed25519PrivateKey) -> str:
    return base64.b64encode(
        key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    ).decode("ascii")


def _write_key(path: Path, key: Ed25519PrivateKey) -> None:
    _ = path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    _ = path.chmod(0o600)


def _fixture_root(tmp_path: Path) -> tuple[Path, Path, Path]:
    release = Path("artifacts/product-release/second-brain-v1")
    fixture = tmp_path / "fixture"
    for relative in ("decisions", "governance"):
        _ = shutil.copytree(
            _ROOT / release / relative,
            fixture / release / relative,
        )
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    owner_key = tmp_path / "owner.pem"
    approver_key = tmp_path / "approver.pem"
    _write_key(owner_key, owner)
    _write_key(approver_key, approver)
    bindings_path = fixture / release / "governance/trusted-bindings.json"
    bindings = decode_json_object(bindings_path.read_text(encoding="utf-8"))
    bindings["aggregate_binding"] = {
        "approver_key_id": "test-approver",
        "approver_public_key_b64": _public_b64(approver),
        "owner_key_id": "test-owner",
        "owner_public_key_b64": _public_b64(owner),
    }
    _ = bindings_path.write_bytes(canonical_bytes(bindings))
    return fixture, owner_key, approver_key


def _sign(
    *,
    root: Path,
    role: str,
    key: Path,
    key_id: str,
    public_key_b64: str,
    output: Path,
) -> None:
    result = _run(
        str(_SIGNER),
        "--role",
        role,
        "--key-id",
        key_id,
        "--expected-public-key-b64",
        public_key_b64,
        "--private-key",
        str(key),
        "--resolver-signing-dir",
        str(
            root
            / "artifacts/product-release/second-brain-v1/resolver-signing"
        ),
        "--output-directory",
        str(output),
    )
    assert result.returncode == 0, result.stderr


def _run_resolve(root: Path, out: Path) -> subprocess.CompletedProcess[str]:
    release = root / "artifacts/product-release/second-brain-v1"
    resolver = release / "resolver"
    return _run(
        str(_CLI),
        "resolve",
        "--records-dir",
        str(release / "decisions"),
        "--resolved-scope",
        str(resolver / "resolved-scope.json"),
        "--expected-scopes",
        str(release / "governance/expected-scopes.json"),
        "--aggregate",
        str(resolver / "aggregate-envelope.json"),
        "--trusted-bindings",
        str(release / "governance/trusted-bindings.json"),
        "--evidence-manifest",
        str(resolver / "evidence-manifest-envelope.json"),
        "--now",
        "2026-08-21T15:00:00Z",
        "--out",
        str(out),
    )


def test_builder_exposes_no_private_key_arguments() -> None:
    result = _run(str(_BUILDER), "--help")
    assert result.returncode == 0
    assert "--owner-key" not in result.stdout
    assert "--approver-key" not in result.stdout
    assert "--private-key" not in result.stdout


def test_public_envelopes_build_canonical_fail_closed_resolver_inputs(
    tmp_path: Path,
) -> None:
    root, owner_key, approver_key = _fixture_root(tmp_path)
    release = root / "artifacts/product-release/second-brain-v1"
    trusted = decode_json_object(
        (release / "governance/trusted-bindings.json").read_text(
            encoding="utf-8"
        )
    )
    bindings = trusted["aggregate_binding"]
    assert isinstance(bindings, dict)
    owner_id = bindings["owner_key_id"]
    owner_public = bindings["owner_public_key_b64"]
    approver_id = bindings["approver_key_id"]
    approver_public = bindings["approver_public_key_b64"]
    assert isinstance(owner_id, str)
    assert isinstance(owner_public, str)
    assert isinstance(approver_id, str)
    assert isinstance(approver_public, str)
    prepared = _run(str(_BUILDER), "prepare", "--root", str(root))
    assert prepared.returncode == 0, prepared.stderr
    signing = release / "resolver-signing"
    owner_out = tmp_path / "owner-envelopes"
    approver_out = tmp_path / "approver-envelopes"
    owner_out.mkdir()
    approver_out.mkdir()
    _sign(
        root=root,
        role="owner",
        key=owner_key,
        key_id=owner_id,
        public_key_b64=owner_public,
        output=owner_out,
    )
    _sign(
        root=root,
        role="approver",
        key=approver_key,
        key_id=approver_id,
        public_key_b64=approver_public,
        output=approver_out,
    )
    assembled = _run(
        str(_BUILDER),
        "assemble",
        "--root",
        str(root),
        "--owner-envelope-dir",
        str(owner_out),
        "--approver-envelope-dir",
        str(approver_out),
    )
    assert assembled.returncode == 0, assembled.stderr
    for name in (
        "resolved-scope.json",
        "aggregate-envelope.json",
        "evidence-manifest-envelope.json",
    ):
        raw = (release / "resolver" / name).read_bytes()
        assert raw == canonical_bytes(decode_json_object(raw.decode("utf-8")))
    result = _run_resolve(root, tmp_path / "receipt.json")
    assert result.returncode != 0
    assert _COVERAGE in result.stdout + result.stderr
    assert not (tmp_path / "receipt.json").exists()
    assert sorted(path.name for path in signing.glob("*.json")) == [
        "aggregate.payload.json",
        "evidence-manifest.payload.json",
    ]


def test_real_authority_wall_names_only_owner_evidence_gaps() -> None:
    wall = decode_json_object(
        (_REAL_RELEASE / "resolver/authority-wall.json").read_text(
            encoding="utf-8"
        )
    )
    assert wall["outcome"] == "FAIL_CLOSED_OWNER_EVIDENCE_REQUIRED"
    assert wall["live_operation_authorized"] is False
    assert wall["complete_signed_decision_records"] == "10"
    assert wall["expected_decision_records"] == "13"
    missing = wall["missing_decisions"]
    assert isinstance(missing, list)
    identities: list[tuple[str, str, str | None, str]] = []
    for item in missing:
        assert isinstance(item, dict)
        decision_id = item["decision_id"]
        scope_kind = item["scope_kind"]
        scope_name = item["scope_name"]
        state = item["state"]
        assert isinstance(decision_id, str)
        assert isinstance(scope_kind, str)
        assert scope_name is None or isinstance(scope_name, str)
        assert isinstance(state, str)
        identities.append((decision_id, scope_kind, scope_name, state))
    assert identities == [
        ("DB-01", "global", None, "SIGNED_UNRESOLVED"),
        ("DB-03", "migration_source", "me-wiki", "SIGNED_UNRESOLVED"),
        ("DB-05", "global", None, "OWNER_EVIDENCE_REQUIRED"),
    ]
