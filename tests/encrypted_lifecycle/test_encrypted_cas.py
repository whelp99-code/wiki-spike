"""Tests for wiki_spike.infrastructure.encrypted_cas.EncryptedContentStore.

Covers: write-once + verify-after-write; idempotent identical put;
colliding-different-bytes rejection; get integrity failure on corrupted
blob; scan detects corruption; tombstone blocks get but retains bytes;
assert_opaque rejects a plaintext-bearing object.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from wiki_spike.infrastructure import encrypted_cas
from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedContentStore,
    IntegrityError,
    NotFound,
    OpaqueViolation,
    Tombstoned,
    assert_opaque,
)

CIPHERTEXT_A = os.urandom(48)
CIPHERTEXT_B = os.urandom(48)


def _envelope_bytes(payload: bytes = CIPHERTEXT_A) -> bytes:
    """A stand-in for a nonce||ciphertext||tag envelope: opaque, non-JSON bytes."""
    return b"\x00" * 12 + payload + b"\xff" * 16


def test_put_is_write_once_and_verified_after_write(tmp_path):
    store = EncryptedContentStore(tmp_path)
    data = _envelope_bytes()
    blob_id = store.put(data)

    assert blob_id == hashlib.sha256(data).hexdigest()
    path = store.objects / blob_id
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o444  # read-only after commit (write-once)
    assert store.get(blob_id) == data  # verify-after-write: bytes round-trip exactly


def test_put_idempotent_on_identical_bytes(tmp_path):
    store = EncryptedContentStore(tmp_path)
    data = _envelope_bytes()
    id1 = store.put(data)
    id2 = store.put(data)
    assert id1 == id2
    assert store.get(id1) == data


def test_put_rejects_colliding_id_with_different_existing_bytes(tmp_path):
    store = EncryptedContentStore(tmp_path)
    good = _envelope_bytes()
    blob_id = hashlib.sha256(good).hexdigest()

    # Simulate a corrupted/tampered pre-existing object stored under the
    # id that `good` would compute to: the store must not silently treat
    # this as idempotent, and must not overwrite it either.
    path = store.objects / blob_id
    path.write_bytes(b"tampered-bytes-not-matching-hash")
    os.chmod(path, 0o444)

    with pytest.raises(IntegrityError):
        store.put(good)


def test_get_detects_corruption(tmp_path):
    store = EncryptedContentStore(tmp_path)
    data = _envelope_bytes()
    blob_id = store.put(data)

    path = store.objects / blob_id
    os.chmod(path, 0o644)
    path.write_bytes(b"corrupted-after-commit")

    with pytest.raises(IntegrityError):
        store.get(blob_id)


def test_get_missing_blob_raises_not_found(tmp_path):
    store = EncryptedContentStore(tmp_path)
    with pytest.raises(NotFound):
        store.get("0" * 64)


def test_scan_flags_tampered_blob(tmp_path):
    store = EncryptedContentStore(tmp_path)
    data = _envelope_bytes()
    blob_id = store.put(data)

    path = store.objects / blob_id
    os.chmod(path, 0o644)
    path.write_bytes(b"changed-after-commit")

    assert blob_id in store.scan()


def test_scan_clean_store_reports_no_corruption(tmp_path):
    store = EncryptedContentStore(tmp_path)
    store.put(_envelope_bytes(CIPHERTEXT_A))
    store.put(_envelope_bytes(CIPHERTEXT_B))
    assert store.scan() == []


def test_tombstone_blocks_get_but_retains_bytes(tmp_path):
    store = EncryptedContentStore(tmp_path)
    data = _envelope_bytes()
    blob_id = store.put(data)

    store.tombstone(blob_id, "crypto-shred: key destroyed")

    assert store.is_tombstoned(blob_id)
    assert store.exists(blob_id)  # bytes retained, not hard-deleted
    with pytest.raises(Tombstoned):
        store.get(blob_id)

    # The bytes are still physically present and byte-identical on disk.
    assert (store.objects / blob_id).read_bytes() == data


def test_assert_opaque_rejects_plaintext_bearing_object():
    leaking = json.dumps({"plaintext": "the secret text"}).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        assert_opaque(leaking)

    leaking_body = json.dumps({"body": "raw content"}).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        assert_opaque(leaking_body)

    leaking_locator = json.dumps({"locator_text": "/wiki/Some_Page"}).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        assert_opaque(leaking_locator)

    # Opaque ciphertext bytes and plaintext-free JSON pass through untouched.
    assert_opaque(_envelope_bytes())
    assert_opaque(json.dumps({"schema": "wiki-envelope-v1"}).encode("utf-8"))


def test_put_rejects_plaintext_bearing_json_object(tmp_path):
    store = EncryptedContentStore(tmp_path)
    leaking = json.dumps({"plaintext": "never store me"}).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(leaking)
    assert store.scan() == []  # nothing was persisted


def test_put_rejects_malformed_json_object_that_is_not_a_valid_envelope(tmp_path):
    store = EncryptedContentStore(tmp_path)
    not_an_envelope = json.dumps({"schema": "wiki-envelope-v1", "oops": True}).encode(
        "utf-8"
    )
    with pytest.raises(OpaqueViolation):
        store.put(not_an_envelope)


def test_put_accepts_schema_valid_envelope_v1_object(tmp_path):
    store = EncryptedContentStore(tmp_path)
    envelope = {
        "schema": "wiki-envelope-v1",
        "version": "1",
        "algorithm": "AES-256-GCM",
        "workspace_id": "ws-alpha",
        "logical_object_id": "a" * 64,
        "revision_id": "b" * 64,
        "semantic_schema_id": "wiki.page.v1",
        "nonce": "0" * 24,
        "aad_digest": "c" * 64,
        "ciphertext": "deadbeef",
        "tag": "e" * 32,
        "metadata": {
            "consent_epoch": "1",
            "key_version": "1",
            "content_length_bytes": "4",
            "created_at": "2026-01-01T00:00:00Z",
        },
    }
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    blob_id = store.put(data)
    assert blob_id == hashlib.sha256(data).hexdigest()
    assert store.get(blob_id) == data


def _valid_envelope_dict() -> dict:
    return {
        "schema": "wiki-envelope-v1",
        "version": "1",
        "algorithm": "AES-256-GCM",
        "workspace_id": "ws-alpha",
        "logical_object_id": "a" * 64,
        "revision_id": "b" * 64,
        "semantic_schema_id": "wiki.page.v1",
        "nonce": "0" * 24,
        "aad_digest": "c" * 64,
        "ciphertext": "deadbeef",
        "tag": "e" * 32,
        "metadata": {
            "consent_epoch": "1",
            "key_version": "1",
            "content_length_bytes": "4",
            "created_at": "2026-01-01T00:00:00Z",
        },
    }


def test_manual_validator_rejects_wrong_schema_const_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    envelope["schema"] = "not-the-right-schema"
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(data)
    assert store.scan() == []


def test_manual_validator_rejects_missing_required_field_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    del envelope["tag"]
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(data)
    assert store.scan() == []


def test_manual_validator_rejects_bad_length_nonce_hex_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    envelope["nonce"] = "0" * 22  # aesGcmNonceHex24 requires exactly 24 hex chars
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(data)
    assert store.scan() == []


def test_manual_validator_rejects_bad_length_tag_hex_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    envelope["tag"] = "e" * 30  # hex32 requires exactly 32 hex chars
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(data)
    assert store.scan() == []


def test_manual_validator_rejects_unexpected_extra_key_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    envelope["oops"] = True
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    with pytest.raises(OpaqueViolation):
        store.put(data)
    assert store.scan() == []


def test_manual_validator_accepts_valid_envelope_without_jsonschema(tmp_path, monkeypatch):
    monkeypatch.setattr(encrypted_cas, "_HAVE_JSONSCHEMA", False)
    monkeypatch.setattr(encrypted_cas, "jsonschema", None)
    store = EncryptedContentStore(tmp_path)
    envelope = _valid_envelope_dict()
    data = json.dumps(envelope, sort_keys=True).encode("utf-8")
    blob_id = store.put(data)
    assert blob_id == hashlib.sha256(data).hexdigest()
    assert store.get(blob_id) == data
