"""Gate 7 MCP tool integration tests.

Tests the ``McpServer``, ``McpNonceGuard``, and the two read-only MCP
tools (``memory_recall``, ``memory_source``) against a real DB + CAS.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.mcp import (
    MAX_RESPONSE_SIZE,
    MCP_DOMAIN,
    McpAuthError,
    McpError,
    McpNonceGuard,
    McpRequest,
    McpResponse,
    McpServer,
    McpToolError,
)
from wiki_spike.infrastructure.floor_protocol import build_freshness_serve_gate
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
)

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def pipeline(tmp_path: Path) -> EncryptedLifecyclePipeline:
    db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
    db.initialize()
    cas = EncryptedContentStore(root=tmp_path / "cas")
    keys = crypto.derive_identity_keys(TEST_ONLY_IKM)
    return EncryptedLifecyclePipeline(
        workspace_id="ws-test-1",
        derived_keys=keys,
        db=db,
        cas=cas,
        dek=TEST_DEK,
    )


@pytest.fixture()
def mcp_server(pipeline: EncryptedLifecyclePipeline) -> McpServer:
    return McpServer(
        workspace_id=pipeline.workspace_id,
        derived_keys=pipeline.derived_keys,
        db=pipeline.db,
        cas=pipeline.cas,
        dek=TEST_DEK,
    )


# ---------------------------------------------------------------------------
# McpNonceGuard
# ---------------------------------------------------------------------------


class TestMcpNonceGuard:
    def test_consume_ok(self) -> None:
        guard = McpNonceGuard()
        guard.consume("a" * 64)
        assert "a" * 64 in guard._consumed

    def test_consume_replay_raises(self) -> None:
        guard = McpNonceGuard()
        guard.consume("b" * 64)
        with pytest.raises(McpAuthError) as excinfo:
            guard.consume("b" * 64)
        assert excinfo.value.code == "nonce_replay"


# ---------------------------------------------------------------------------
# McpServer auth
# ---------------------------------------------------------------------------


class TestMcpServerAuth:
    def test_unauthenticated_request_ok(self, mcp_server: McpServer) -> None:
        """Unauthenticated request with valid nonce succeeds (no auth error)."""
        req = {"tool": "memory_recall", "params": {}, "nonce": "n0" * 32, "workspace_id": "ws-test-1"}
        resp = json.loads(mcp_server.handle_request(json.dumps(req)))
        # Should return a tool error (missing params), not an auth error.
        assert resp["error"] is not None
        assert resp["error"] not in ("signature_invalid", "signature_missing", "nonce_replay")

    def test_replayed_nonce_raises(self, mcp_server: McpServer) -> None:
        """Replayed nonce raises McpAuthError."""
        req = json.dumps({
            "tool": "memory_recall", "params": {}, "nonce": "r1" * 32, "workspace_id": "ws-test-1",
        })
        mcp_server.handle_request(req)
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] == "nonce_replay"

    def test_invalid_signature_raises(self, mcp_server: McpServer) -> None:
        """Bad signature raises McpAuthError."""
        signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-mcp-key").digest())
        public_key = signing_key.public_key()
        body = {"tool": "memory_recall", "params": {}, "nonce": "s1" * 32, "workspace_id": "ws-test-1"}
        body_json = json.dumps(body)
        bad_sig = "ff" * 64
        resp = json.loads(mcp_server.handle_request(body_json, signature_hex=bad_sig, public_key=public_key))
        assert resp["error"] == "signature_invalid"


# ---------------------------------------------------------------------------
# Helper: remember -> approve -> build+persist changeset -> activate
# ---------------------------------------------------------------------------


def _remember_and_activate(
    pipeline: EncryptedLifecyclePipeline,
    raw_body: bytes,
    project_id: str = "proj-test",
) -> tuple:
    """Remember, approve, build/persist changeset, generate, and activate."""
    result = pipeline.remember(raw_body=raw_body, project_id=project_id)
    pipeline.review_candidate(
        artifact_id=result.artifact_semantic_digest,
        reviewer_handle="reviewer-1",
        review_state="APPROVED",
    )
    cs = pipeline.build_changeset(command_ids=[result.command_id])
    pipeline.persist_changeset(cs)
    signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-gen-key").digest())
    pipeline.create_generation(
        changeset_id=cs["changeset_id"],
        signing_key=signing_key,
        signer_key_id="test-signer",
    )
    pipeline.activate_artifact(
        artifact_id=result.artifact_semantic_digest,
        blob_id=result.blob_id,
    )
    return result, cs


# ---------------------------------------------------------------------------
# memory_recall
# ---------------------------------------------------------------------------


class TestMemoryRecall:
    def test_happy_path(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        raw_body = b"hello mcp recall"
        result, _ = _remember_and_activate(pipeline, raw_body)

        req = json.dumps({
            "tool": "memory_recall",
            "params": {
                "artifact_id": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "r1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] is None, f"unexpected error: {resp['error']}"
        assert resp["result"]["artifact_id"] == result.artifact_semantic_digest
        assert resp["result"]["content"] == raw_body.decode("utf-8")
        assert resp["result"]["truncated"] is False
        assert "metadata" in resp["result"]
        assert resp["result"]["metadata"]["content_length_bytes"] == str(len(raw_body))

    def test_vetoed(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        """Forgetting (deleting) an artifact vetoes recall."""
        raw_body = b"will be forgotten"
        result, _ = _remember_and_activate(pipeline, raw_body)

        # Insert a deletion_state row directly (pipeline.forget requires dual custody).
        from wiki_spike.infrastructure.deletion import DeletionPhase
        phase = DeletionPhase.API_VETO_ACTIVE
        now = "2026-07-25T00:00:00Z"
        pipeline.db.con.execute(
            "INSERT INTO deletion_state (deletion_id, artifact_id, phase_state, updated_at) "
            "VALUES (?,?,?,?)",
            ("del-" + result.artifact_semantic_digest[:48], result.artifact_semantic_digest,
             phase.value, now),
        )

        req = json.dumps({
            "tool": "memory_recall",
            "params": {
                "artifact_id": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "v1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] == "artifact_vetoed"

    def test_serve_withheld(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        """A non-CLEAR serve gate withholds recall."""
        raw_body = b"serve withheld test"
        result, _ = _remember_and_activate(pipeline, raw_body)

        # Force serve gate to FRESH_CHALLENGE_REQUIRED.
        gate = build_freshness_serve_gate(
            workspace_id="ws-test-1",
            state="FRESH_CHALLENGE_REQUIRED",
            stable_floor_generation="gen-1",
            stable_checkpoint_id="00" * 32,
            source_candidate_digest="00" * 32,
            reason="ATTESTATION_EXPIRED_BEFORE_STABILIZE",
            updated_at="2026-07-25T00:00:00Z",
        )
        pipeline.db.con.execute(
            "INSERT OR REPLACE INTO freshness_serve_gate "
            "(workspace_id, gate_state, stable_floor_generation, stable_checkpoint_id, "
            "source_candidate_digest, reason_state, updated_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                "ws-test-1",
                gate["state"],
                gate["stable_floor_generation"],
                gate["stable_checkpoint_id"],
                gate["source_candidate_digest"],
                gate["reason"],
                gate["updated_at"],
            ),
        )

        req = json.dumps({
            "tool": "memory_recall",
            "params": {
                "artifact_id": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "s1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] == "serve_withheld"

    def test_response_bound(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        """Content larger than 64 KiB is truncated."""
        large_body = b"X" * (MAX_RESPONSE_SIZE + 100)
        result, _ = _remember_and_activate(pipeline, large_body, project_id="proj-bound")

        req = json.dumps({
            "tool": "memory_recall",
            "params": {
                "artifact_id": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "b1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] is None, f"unexpected error: {resp['error']}"
        assert resp["result"]["truncated"] is True
        assert len(resp["result"]["content"]) <= MAX_RESPONSE_SIZE


# ---------------------------------------------------------------------------
# memory_source
# ---------------------------------------------------------------------------


class TestMemorySource:
    def test_happy_path(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        """Recall a source artifact, providing blob_id to locate the CAS blob."""
        raw_body = b"source artifact content"
        result, _ = _remember_and_activate(pipeline, raw_body, project_id="proj-source")

        req = json.dumps({
            "tool": "memory_source",
            "params": {
                "source_content_digest": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "sr1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] is None, f"unexpected error: {resp['error']}"
        assert resp["result"]["source_content_digest"] == result.artifact_semantic_digest
        assert resp["result"]["content"] == raw_body.decode("utf-8")
        assert resp["result"]["truncated"] is False

    def test_not_found(self, pipeline: EncryptedLifecyclePipeline, mcp_server: McpServer) -> None:
        """Non-existent source returns source_not_found."""
        req = json.dumps({
            "tool": "memory_source",
            "params": {
                "source_content_digest": "ff" * 32,
            },
            "nonce": "nf1" * 32,
            "workspace_id": "ws-test-1",
        })
        resp = json.loads(mcp_server.handle_request(req))
        assert resp["error"] == "source_not_found"


# ---------------------------------------------------------------------------
# Authenticated request
# ---------------------------------------------------------------------------


class TestAuthenticatedRequest:
    def test_signed_request_processes(self, pipeline: EncryptedLifecyclePipeline) -> None:
        """Correctly signed request is accepted and processed."""
        raw_body = b"signed recall test"
        result, _ = _remember_and_activate(pipeline, raw_body, project_id="proj-sig")

        signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-auth-key").digest())
        public_key = signing_key.public_key()

        body = {
            "tool": "memory_recall",
            "params": {
                "artifact_id": result.artifact_semantic_digest,
                "blob_id": result.blob_id,
            },
            "nonce": "sig1" * 32,
            "workspace_id": "ws-test-1",
        }
        sig = crypto.sign(signing_key, MCP_DOMAIN, body)

        server = McpServer(
            workspace_id=pipeline.workspace_id,
            derived_keys=pipeline.derived_keys,
            db=pipeline.db,
            cas=pipeline.cas,
            dek=TEST_DEK,
        )
        resp = json.loads(server.handle_request(json.dumps(body), signature_hex=sig, public_key=public_key))
        assert resp["error"] is None, f"unexpected error: {resp['error']}"
        assert resp["result"]["content"] == raw_body.decode("utf-8")

    def test_tampered_signature_raises(self, pipeline: EncryptedLifecyclePipeline) -> None:
        """Tampered (modified body) signature fails verification."""
        signing_key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-tamper-key").digest())
        public_key = signing_key.public_key()

        body = {
            "tool": "memory_recall",
            "params": {"artifact_id": "aa" * 32, "blob_id": "bb" * 32},
            "nonce": "tam1" * 32,
            "workspace_id": "ws-test-1",
        }
        # Build alt_body as a completely separate dict (avoid shallow copy bug).
        alt_body = {
            "tool": "memory_recall",
            "params": {"artifact_id": "cc" * 32, "blob_id": "bb" * 32},
            "nonce": "tam1" * 32,
            "workspace_id": "ws-test-1",
        }
        sig = crypto.sign(signing_key, MCP_DOMAIN, alt_body)

        server = McpServer(
            workspace_id=pipeline.workspace_id,
            derived_keys=pipeline.derived_keys,
            db=pipeline.db,
            cas=pipeline.cas,
            dek=TEST_DEK,
        )
        resp = json.loads(server.handle_request(json.dumps(body), signature_hex=sig, public_key=public_key))
        assert resp["error"] == "signature_invalid"
