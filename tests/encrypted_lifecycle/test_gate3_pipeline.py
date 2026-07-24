"""Gate 3 pipeline integration tests.

Tests the REMEMBER → changeset → persist pipeline end-to-end using
the EncryptedLifecyclePipeline application service.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
)

TEST_ONLY_IKM = hashlib.sha256(
    b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-TEST-ONLY-ROOT-IKM-V1"
).digest()
TEST_DEK = hashlib.sha256(b"TEST-ONLY-DEK").digest()


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


def test_remember_produces_all_identities(pipeline):
    result = pipeline.remember(
        raw_body=b"first remember body",
        project_id="proj-1",
    )
    assert len(result.command_id) == 64
    assert len(result.manifest_digest) == 64
    assert len(result.artifact_semantic_digest) == 64
    assert len(result.logical_object_id) == 64
    assert len(result.revision_id) == 64
    assert len(result.blob_id) == 64


def test_remember_persists_command_and_artifact(pipeline):
    result = pipeline.remember(raw_body=b"test body", project_id="proj-1")
    with pipeline.db.unit_of_work() as uow:
        cmd = uow.get_command(result.command_id)
        assert cmd is not None
        assert cmd["command_kind"] == "REMEMBER"
        assert cmd["command_state"] == "ACCEPTED"

        art = uow.get_canonical_artifact(result.artifact_semantic_digest)
        assert art is not None
        assert art["artifact_kind"] == "MEMORY_REVISION"
        assert art["revision_id"] == result.revision_id

        ks = uow.get_key_state(result.artifact_semantic_digest)
        assert ks is not None
        assert ks["custody_state"] == "PREPARED"


def test_remember_seals_envelope_in_cas(pipeline):
    result = pipeline.remember(raw_body=b"encrypted body", project_id="proj-1")
    assert pipeline.cas.exists(result.blob_id)
    stored_bytes = pipeline.cas.get(result.blob_id)
    import json
    stored = json.loads(stored_bytes)
    assert stored["schema"] == "wiki-envelope-v1"
    assert stored["ciphertext"] == result.envelope["ciphertext"]


def test_remember_envelope_decrypts_to_original(pipeline):
    original = b"hello encrypted world"
    result = pipeline.remember(raw_body=original, project_id="proj-1")
    aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(result.artifact_semantic_digest)
    decrypted = crypto.aes_gcm_open(
        TEST_DEK,
        result.envelope["nonce"],
        result.envelope["ciphertext"],
        result.envelope["tag"],
        aad,
    )
    assert decrypted == original


def test_remember_appends_event(pipeline):
    result = pipeline.remember(raw_body=b"event test", project_id="proj-1")
    head = pipeline.db.event_chain_head()
    assert head is not None
    assert len(head) == 64


def test_remember_deterministic_command_id(pipeline):
    r1 = pipeline.remember(raw_body=b"same body", project_id="proj-1")
    # Different pipeline instance, same keys + same input → same command_id
    # (but artifact will differ due to random nonce in envelope)
    assert len(r1.command_id) == 64


def test_build_changeset_from_remember(pipeline):
    r = pipeline.remember(raw_body=b"changeset test", project_id="proj-1")
    cs = pipeline.build_changeset(command_ids=[r.command_id])
    assert cs["contract_version"] == "wiki-encrypted-accepted-change-set-v1"
    assert len(cs["changeset_id"]) == 64
    assert len(cs["deltas"]) == 1
    assert cs["deltas"][0]["operation"] == "ADD"
    assert cs["deltas"][0]["object_kind"] == "MEMORY_REVISION"
    assert len(cs["expected_active_revisions"]) == 1


def test_persist_changeset(pipeline):
    r = pipeline.remember(raw_body=b"persist test", project_id="proj-1")
    cs = pipeline.build_changeset(command_ids=[r.command_id])
    pipeline.persist_changeset(cs)

    with pipeline.db.unit_of_work() as uow:
        row = uow.get_accepted_changeset(cs["changeset_id"])
        assert row is not None
        assert row["changeset_state"] == "ACCEPTED"
        assert row["changes_root_digest"] == cs["changes_root"]

        deltas = uow.list_state_deltas(cs["changeset_id"])
        assert len(deltas) == 1
        assert deltas[0]["operation_kind"] == "ADD"


def test_build_changeset_unknown_command_raises(pipeline):
    with pytest.raises(PipelineError) as excinfo:
        pipeline.build_changeset(command_ids=["ff" * 32])
    assert excinfo.value.code == "command_not_found"


def test_remember_rejects_bom(pipeline):
    from wiki_spike.infrastructure.ingestion import InputNormalizationError
    with pytest.raises(InputNormalizationError):
        pipeline.remember(raw_body=b"\xef\xbb\xbfhello", project_id="proj-1")
