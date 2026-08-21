"""Unsigned MacPersistenceProfileV1 artifact binds SQLCipher feasibility digest."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from wiki_spike.composition.mac_production import PINNED_SQLCIPHER_ARTIFACT_BYTES
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_persistence import MacPersistenceProfileV1

_ROOT = Path(__file__).resolve().parents[2]
_RELEASE = _ROOT / "artifacts/product-release/second-brain-v1"
_PROFILE = _RELEASE / "persistence-profile.json"
_RECEIPT = _RELEASE / "persistence-receipt.json"
_SQLCIPHER = (
    _ROOT / "artifacts/encrypted-lifecycle/sqlcipher-feasibility-darwin-arm64.json"
)
_PACKAGED_SQLCIPHER = (
    _ROOT / "src/wiki_spike/resources/sqlcipher-feasibility-darwin-arm64.json"
)
_SQLCIPHER_DIGEST = (
    "4be0904f80c46d406dc45479febcab43ef3c0fd4db184250bc927041fc97ade2"
)
_FIELDS = frozenset(MacPersistenceProfileV1.FIELDS)
_FORBIDDEN = (
    "BEGIN ",
    "PRIVATE KEY",
    "private_key",
    "signature_b64",
    "live_operation_authorized",
)


def _load(path: Path) -> dict[str, JsonValue]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    mapping: dict[str, JsonValue] = {}
    for key, item in value.items():
        assert isinstance(key, str)
        assert isinstance(item, str)
        mapping[key] = item
    return mapping


def test_unsigned_profile_binds_sqlcipher_digest_without_receipt_or_signatures() -> None:
    assert _PROFILE.is_file()
    assert _PROFILE.parent == _RELEASE
    assert "Library/Application Support" not in _PROFILE.as_posix()
    assert not _RECEIPT.exists()
    raw = _PROFILE.read_bytes()
    body = _load(_PROFILE)
    assert raw == canonical_bytes(body) + b"\n"
    assert set(body) == _FIELDS
    assert body["sqlcipher_status"] == "platform_unavailable"
    assert body["sqlcipher_must_verdict"] == "NOT_RUN"
    assert body["database_page_cipher"] == "none"
    assert body["content_cipher"] == "AES-256-GCM"
    assert body["sqlcipher_artifact_digest"] == sha256(_SQLCIPHER.read_bytes()).hexdigest()
    sqlite_runtime = body["sqlite_runtime"]
    assert isinstance(sqlite_runtime, str)
    assert sqlite_runtime.startswith("python-stdlib-sqlite3/")
    assert sqlite_runtime.removeprefix("python-stdlib-sqlite3/") != ""
    serialized = json.dumps(body, sort_keys=True)
    for token in _FORBIDDEN:
        assert token not in serialized
        assert token.encode("ascii") not in raw
        assert token not in body


def test_unsigned_profile_from_mapping_matches_canonical_digest_helper() -> None:
    body = _load(_PROFILE)
    parsed = MacPersistenceProfileV1.from_mapping(body)
    unsigned = {field: body[field] for field in _FIELDS - {"profile_digest"}}
    expected_digest = canonical_ledger_digest("mac-persistence-profile-v1", unsigned)
    assert parsed.profile_digest == expected_digest
    assert parsed.to_mapping() == body
    assert parsed.sqlcipher_status == "platform_unavailable"
    assert parsed.sqlcipher_must_verdict == "NOT_RUN"


def test_production_default_sqlcipher_bytes_match_unsigned_profile_digest() -> None:
    artifact = _SQLCIPHER.read_bytes()
    packaged = _PACKAGED_SQLCIPHER.read_bytes()
    body = _load(_PROFILE)
    assert sha256(artifact).hexdigest() == _SQLCIPHER_DIGEST
    assert sha256(PINNED_SQLCIPHER_ARTIFACT_BYTES).hexdigest() == _SQLCIPHER_DIGEST
    assert sha256(packaged).hexdigest() == _SQLCIPHER_DIGEST
    assert PINNED_SQLCIPHER_ARTIFACT_BYTES == artifact
    assert packaged == artifact
    assert body["sqlcipher_artifact_digest"] == _SQLCIPHER_DIGEST
    assert body["sqlcipher_status"] == "platform_unavailable"
    assert body["sqlcipher_must_verdict"] == "NOT_RUN"
    assert not _RECEIPT.exists()
