"""Tests for the durable file-backed LocalRetainedAuthority adapter."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.applications.second_brain_shadow_measurement import ShadowMeasurementError
from wiki_spike.composition.retained_authority import (
    LocalRetainedAuthority,
    LocalRetainedAuthorityError,
    provision_authority,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

_AUTHORITY_DOMAIN = "second-brain-native-shadow-authority-v1"


def test_provision_creates_directory_structure(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    assert (auth_dir / "metadata.json").exists()
    assert (auth_dir / "authority.key").exists()
    assert (auth_dir / "authority.pub").exists()
    assert (auth_dir / "journal.bin").exists()
    assert (auth_dir / "journal.bin").read_bytes() == b""
    metadata = json.loads((auth_dir / "metadata.json").read_text())
    assert metadata["identity"] == "wiki-spike-local-retained-authority"
    assert metadata["policy_id"] == "retention-immutable-v1"
    assert metadata["endpoint"].startswith("retention-authority://local/")
    assert len(metadata["public_key_fingerprint"]) == 64


def test_provision_rejects_existing_directory(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    with pytest.raises(LocalRetainedAuthorityError, match="already provisioned"):
        provision_authority(auth_dir)


def test_provision_custom_identity_and_policy(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth", identity="custom-id", policy_id="custom-policy")
    metadata = json.loads((auth_dir / "metadata.json").read_text())
    assert metadata["identity"] == "custom-id"
    assert metadata["policy_id"] == "custom-policy"


def test_load_unprovisioned_directory_raises(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(LocalRetainedAuthorityError, match="not provisioned"):
        LocalRetainedAuthority(tmp_path / "empty")


def test_load_missing_key_raises(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    (auth_dir / "authority.key").unlink()
    with pytest.raises(LocalRetainedAuthorityError, match="signing key is unreadable"):
        LocalRetainedAuthority(auth_dir)


def test_key_fingerprint_mismatch_raises(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    metadata = json.loads((auth_dir / "metadata.json").read_text())
    metadata["public_key_fingerprint"] = "0" * 64
    (auth_dir / "metadata.json").write_text(json.dumps(metadata))
    with pytest.raises(LocalRetainedAuthorityError, match="does not match metadata"):
        LocalRetainedAuthority(auth_dir)


def test_snapshot_empty_journal(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    snap = auth.snapshot(request_nonce="nonce-1")
    assert snap.revision == 0
    assert snap.events == ()
    assert snap.request_nonce == "nonce-1"
    assert snap.identity == "wiki-spike-local-retained-authority"
    assert snap.policy_id == "retention-immutable-v1"
    assert snap.root == sha256(canonical_ledger_bytes(_AUTHORITY_DOMAIN, {"events": []})).hexdigest()


def test_snapshot_signature_verifies(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    snap = auth.snapshot(request_nonce="nonce-verify")
    pub_key = auth.public_key
    pub_key.verify(
        bytes.fromhex(snap.signature),
        canonical_ledger_bytes(_AUTHORITY_DOMAIN, snap.payload()),
    )


def test_compare_and_advance_monotonic(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    event1 = {"kind": "checkpoint", "data": "first"}
    event2 = {"kind": "append", "data": "second"}

    snap1 = auth.compare_and_advance(expected_revision=0, event=event1, request_nonce="n1")
    assert snap1.revision == 1
    assert dict(snap1.events[0]) == event1

    snap2 = auth.compare_and_advance(expected_revision=1, event=event2, request_nonce="n2")
    assert snap2.revision == 2
    assert dict(snap2.events[0]) == event1
    assert dict(snap2.events[1]) == event2


def test_compare_and_advance_cas_conflict(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    auth.compare_and_advance(expected_revision=0, event={"kind": "a"}, request_nonce="n1")
    with pytest.raises(ShadowMeasurementError, match="CAS conflict"):
        auth.compare_and_advance(expected_revision=0, event={"kind": "b"}, request_nonce="n2")


def test_durability_across_reload(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    auth.compare_and_advance(expected_revision=0, event={"kind": "x"}, request_nonce="n1")
    auth.compare_and_advance(expected_revision=1, event={"kind": "y"}, request_nonce="n2")

    # Reload from disk
    auth2 = LocalRetainedAuthority(auth_dir)
    snap = auth2.snapshot(request_nonce="n3")
    assert snap.revision == 2
    assert len(snap.events) == 2
    assert dict(snap.events[0]) == {"kind": "x"}
    assert dict(snap.events[1]) == {"kind": "y"}
    # Signature still verifies after reload
    auth2.public_key.verify(
        bytes.fromhex(snap.signature),
        canonical_ledger_bytes(_AUTHORITY_DOMAIN, snap.payload()),
    )


def test_public_key_matches_metadata(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    raw = auth.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    fingerprint = sha256(raw).hexdigest()
    metadata = json.loads((auth_dir / "metadata.json").read_text())
    assert fingerprint == metadata["public_key_fingerprint"]
    # Public key file matches
    pub_hex = (auth_dir / "authority.pub").read_text().strip()
    assert pub_hex == raw.hex()


def test_receipt_freshness_window(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    snap = auth.snapshot(request_nonce="fresh")
    from datetime import datetime, timezone
    issued = datetime.fromisoformat(snap.issued_at.replace("Z", "+00:00"))
    expires = datetime.fromisoformat(snap.expires_at.replace("Z", "+00:00"))
    assert (expires - issued).total_seconds() == 300  # 5 minutes
    now = datetime.now(timezone.utc)
    assert issued <= now < expires


def test_journal_is_append_only(tmp_path):
    auth_dir = provision_authority(tmp_path / "auth")
    auth = LocalRetainedAuthority(auth_dir)
    auth.compare_and_advance(expected_revision=0, event={"kind": "a"}, request_nonce="n1")
    size_after_one = (auth_dir / "journal.bin").stat().st_size
    auth.compare_and_advance(expected_revision=1, event={"kind": "b"}, request_nonce="n2")
    size_after_two = (auth_dir / "journal.bin").stat().st_size
    assert size_after_two > size_after_one
