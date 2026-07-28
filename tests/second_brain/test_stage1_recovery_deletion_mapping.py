from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import pytest

from wiki_spike.infrastructure.deletion import (
    DeletionError,
    DeletionPhase,
    map_source_deletion_request,
    persist_verified_recovery_deletion_overlay,
)
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, LifecycleDbError
from wiki_spike.memory_core.recovery import SignedDeletionOverlay, VerifiedDeletionOverlay

DIGEST = "a" * 64


def verified_overlay(
    *,
    seed: bytes,
    sequence: str = "0",
    previous_overlay_id: str | None = None,
    refs: frozenset[str] = frozenset(),
) -> VerifiedDeletionOverlay:
    signed = SignedDeletionOverlay.create(
        workspace_id="workspace",
        manifest_id="b" * 64,
        sequence=sequence,
        previous_overlay_id=previous_overlay_id,
        deleted_artifact_refs=tuple(sorted(refs)),
        mapping_digest=None,
        signer_key_id="recovery-k1",
        signed_at="2026-01-01T00:00:00Z",
        private_key=Ed25519PrivateKey.from_private_bytes(seed * 32),
    )
    return VerifiedDeletionOverlay(signed, refs)


def test_recovered_deleted_artifact_remains_vetoed_while_survivor_is_unmapped(tmp_path):
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    with database.unit_of_work() as uow:
        uow.insert_canonical_artifact("artifact-deleted", "workspace", "record", "revision", "ACTIVE", "2026-01-01T00:00:00Z")
        uow.insert_canonical_artifact("artifact-survivor", "workspace", "record", "revision2", "ACTIVE", "2026-01-01T00:00:00Z")
        uow.insert_source_deletion_recovery_map(
            "map", "workspace", f"source:{DIGEST}", "artifact-deleted",
            f"deletion:{DIGEST}", f"proof:{DIGEST}", "1", DIGEST, DIGEST,
            "2026-01-01T00:00:00Z",
        )
        statuses = map_source_deletion_request(
            uow, workspace_id="workspace", source_ref_id=f"source:{DIGEST}",
            deletion_ref_id=f"deletion:{DIGEST}", updated_at="2026-01-01T00:00:00Z",
        )
        assert [(status.artifact_id, status.phase, status.api_veto_active) for status in statuses] == [
            ("artifact-deleted", DeletionPhase.REQUESTED, True)
        ]
        assert uow.get_deletion_state_by_artifact("artifact-survivor") is None
        assert statuses[0].backup_residual is True
        assert statuses[0].irreversible_egress is False

def test_verified_overlay_persists_body_free_vetoes_and_rejects_discontinuous_history(tmp_path):
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    initial = verified_overlay(seed=b"a", refs=frozenset({"artifact-deleted"}))
    with database.unit_of_work() as uow:
        receipt = persist_verified_recovery_deletion_overlay(uow, overlay=initial)
        assert receipt.deleted_artifact_refs == initial.deleted_artifact_refs
        assert uow.recovery_deletion_vetoed("artifact-deleted") is True
        assert uow.recovery_deletion_vetoed("artifact-survivor") is False
        assert [row["artifact_id"] for row in uow.list_recovery_deletion_vetoes(initial.overlay.overlay_id)] == [
            "artifact-deleted"
        ]

    discontinuous = verified_overlay(
        seed=b"c", sequence="2", previous_overlay_id=initial.overlay.overlay_id
    )
    with pytest.raises(LifecycleDbError, match="rollback or discontinuity"):
        with database.unit_of_work() as uow:
            persist_verified_recovery_deletion_overlay(uow, overlay=discontinuous)


def test_recovery_overlay_requires_valid_resolved_refs(tmp_path):
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    signed = verified_overlay(seed=b"a").overlay
    invalid = VerifiedDeletionOverlay(signed, frozenset({""}))
    with pytest.raises(DeletionError, match="verified deletion overlay is invalid"):
        with database.unit_of_work() as uow:
            persist_verified_recovery_deletion_overlay(uow, overlay=invalid)
def test_replay_rejects_a_changed_veto_set(tmp_path):
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    initial = verified_overlay(seed=b"a", refs=frozenset({"artifact-deleted"}))
    with database.unit_of_work() as uow:
        persist_verified_recovery_deletion_overlay(uow, overlay=initial)
    changed_refs = VerifiedDeletionOverlay(initial.overlay, frozenset({"artifact-survivor"}))
    with pytest.raises(LifecycleDbError, match="persisted veto set"):
        with database.unit_of_work() as uow:
            persist_verified_recovery_deletion_overlay(uow, overlay=changed_refs)
