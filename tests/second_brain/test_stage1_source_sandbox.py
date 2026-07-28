from __future__ import annotations

from hashlib import sha256
import json
import socket

import pytest

from wiki_spike.infrastructure.source_sandbox import FixtureLimitPolicy, FixtureSourceSandbox, SourceSandboxDisposition
from wiki_spike.memory_core.policy import Sensitivity
from wiki_spike.memory_core.second_brain_consent import ConsentState, RetentionPolicy, RetentionState, SourceConsentState
from wiki_spike.memory_core.second_brain_source_fixture import SourceFixtureVerifier, SourceFixtureVerificationError
from wiki_spike.memory_core.contracts import canonical_bytes

NOW = "2030-01-01T00:00:00Z"
FUTURE = "2030-02-01T00:00:00Z"
REF = "fixture:" + "a" * 64


def current():
    return (
        SourceConsentState("workspace", "source", "project", "2", ConsentState.ENABLED, Sensitivity.PRIVATE, FUTURE, "a" * 64, NOW),
        RetentionPolicy("workspace", "source", "project", "3", RetentionState.ACTIVE, Sensitivity.PRIVATE, FUTURE, "a" * 64, NOW),
    )


def manifest(entries, **changes):
    body = {"security_version": "second-brain-security-foundation-v1", "manifest_ref": "fixture_manifest:" + "a" * 64, "fixture_revision": "1", "source_fixture_refs": [e["source_fixture_ref"] for e in entries], "fixture_profile": "fixture-local-v1", "source_ref_id": "source", "project_ref_id": "project", "consent_epoch": "2", "entries": entries}
    body.update(changes)
    body["manifest_digest"] = sha256(canonical_bytes(body)).hexdigest()
    return body


def entry(path, content, *, pages="1"):
    return {"source_fixture_ref": REF, "path": path, "sha256": sha256(content).hexdigest(), "byte_count": str(len(content)), "page_count": pages}


def sandbox(tmp_path, **limits):
    return FixtureSourceSandbox(tmp_path, FixtureLimitPolicy(3, 3, 64, 10, **limits))


def read(box, verified):
    consent, retention = current()
    return box.read(verified, consent=consent, retention=retention, sensitivity=Sensitivity.PUBLIC, now=NOW)


def test_normal_fixture_is_local_only_and_never_advances_checkpoint(tmp_path, monkeypatch):
    content = b'{"page":1}\n'
    (tmp_path / "normal.json").write_bytes(content)
    verified = SourceFixtureVerifier().verify(manifest([entry("normal.json", content)]))
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: pytest.fail("external call"))
    result = read(sandbox(tmp_path), verified)
    assert result.disposition is SourceSandboxDisposition.ACCEPTED
    assert result.items[0].content == content
    assert not result.checkpoint_advanced


@pytest.mark.parametrize("path", ["../secret", "https://example.test/a", "$HOME/token", "file:///tmp/x"])
def test_traversal_url_and_environment_routes_are_rejected(path):
    with pytest.raises(SourceFixtureVerificationError):
        SourceFixtureVerifier().verify(manifest([entry(path, b"x")]))


def test_malformed_and_oversized_manifests_cannot_read(tmp_path):
    content = b"x" * 10
    (tmp_path / "normal.json").write_bytes(content)
    bad = manifest([entry("normal.json", content)])
    bad["manifest_digest"] = "0" * 64
    with pytest.raises(SourceFixtureVerificationError):
        SourceFixtureVerifier().verify(bad)
    verified = SourceFixtureVerifier().verify(manifest([entry("normal.json", content)]))
    result = read(FixtureSourceSandbox(tmp_path, FixtureLimitPolicy(1, 1, 9, 10)), verified)
    assert result.disposition is SourceSandboxDisposition.QUARANTINED
    assert result.items == () and not result.checkpoint_advanced


def test_symlink_and_leak_marker_are_quarantined_without_body(tmp_path):
    outside = tmp_path.parent / "LEAK_MARKER"
    outside.write_bytes(b"LEAK_MARKER")
    (tmp_path / "link").symlink_to(outside)
    verified = SourceFixtureVerifier().verify(manifest([entry("link", b"LEAK_MARKER")]))
    result = read(sandbox(tmp_path), verified)
    assert result.disposition is SourceSandboxDisposition.QUARANTINED
    assert result.items == () and "LEAK_MARKER" not in (result.quarantine_reason or "")


def test_pagination_boundary_and_current_consent_are_enforced(tmp_path):
    content = b"x"
    (tmp_path / "normal.json").write_bytes(content)
    verified = SourceFixtureVerifier().verify(manifest([entry("normal.json", content, pages="3")]))
    assert read(sandbox(tmp_path), verified).accepted
    denied_consent, retention = current()
    denied = FixtureSourceSandbox(tmp_path, FixtureLimitPolicy(1, 3, 64, 10)).read(verified, consent=denied_consent, retention=retention, sensitivity=Sensitivity.PUBLIC, now=NOW)
    assert denied.accepted
    too_many = SourceFixtureVerifier().verify(manifest([entry("normal.json", content, pages="4")]))
    assert read(sandbox(tmp_path), too_many).disposition is SourceSandboxDisposition.QUARANTINED


def test_expired_or_superseded_consent_is_denied_before_file_read(tmp_path):
    content = b"x"
    (tmp_path / "normal.json").write_bytes(content)
    verified = SourceFixtureVerifier().verify(manifest([entry("normal.json", content)]))
    consent, retention = current()
    stale = SourceConsentState(**{**consent.__dict__, "consent_epoch": "1"})
    result = FixtureSourceSandbox(tmp_path, FixtureLimitPolicy(1, 1, 64, 10)).read(verified, consent=stale, retention=retention, sensitivity=Sensitivity.PUBLIC, now=NOW)
    assert result.disposition is SourceSandboxDisposition.QUARANTINED
def test_deadline_is_checked_before_and_during_fixture_read(tmp_path):
    content = b"x" * 2
    (tmp_path / "normal.json").write_bytes(content)
    verified = SourceFixtureVerifier().verify(manifest([entry("normal.json", content)]))
    ticks = iter((0.0, 0.0, 2.0))
    box = FixtureSourceSandbox(tmp_path, FixtureLimitPolicy(1, 1, 64, 1, chunk_bytes=1), clock=lambda: next(ticks))
    result = read(box, verified)
    assert result.disposition is SourceSandboxDisposition.QUARANTINED
    assert not result.checkpoint_advanced and result.items == ()
