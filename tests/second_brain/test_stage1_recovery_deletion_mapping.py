from wiki_spike.infrastructure.deletion import DeletionPhase, map_source_deletion_request
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase


DIGEST = "a" * 64


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
