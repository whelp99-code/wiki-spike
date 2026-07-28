from __future__ import annotations

from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase, assert_no_plaintext_columns
from wiki_spike.memory_core.policy import Sensitivity
from wiki_spike.memory_core.second_brain_consent import (
    ConsentRetentionDisposition,
    ConsentRetentionPolicy,
    ConsentState,
    RetentionPolicy,
    RetentionState,
    SourceConsentState,
)


NOW = "2030-01-01T00:00:00Z"
FUTURE = "2030-02-01T00:00:00Z"
DIGEST = "a" * 64


def consent(**changes: object) -> SourceConsentState:
    values: dict[str, object] = {
        "workspace_id": "workspace-1", "source_ref_id": "source-1", "project_ref_id": "project-1",
        "consent_epoch": "2", "consent_state": ConsentState.ENABLED,
        "max_sensitivity": Sensitivity.PRIVATE, "expires_at": FUTURE,
        "consent_digest": DIGEST, "updated_at": NOW,
    }
    values.update(changes)
    return SourceConsentState(**values)  # type: ignore[arg-type]


def retention(**changes: object) -> RetentionPolicy:
    values: dict[str, object] = {
        "workspace_id": "workspace-1", "source_ref_id": "source-1", "project_ref_id": "project-1",
        "retention_epoch": "3", "retention_state": RetentionState.ACTIVE,
        "max_sensitivity": Sensitivity.PRIVATE, "expires_at": FUTURE,
        "retention_digest": DIGEST, "updated_at": NOW,
    }
    values.update(changes)
    return RetentionPolicy(**values)  # type: ignore[arg-type]


def test_capture_and_serve_require_current_exact_policy():
    policy = ConsentRetentionPolicy()
    assert policy.authorize_capture(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent=consent(), retention=retention(), sensitivity=Sensitivity.PRIVATE, now=NOW,
    ).allowed
    assert policy.authorize_serve(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent_epoch="2", retention_epoch="3", consent=consent(), retention=retention(),
        sensitivity=Sensitivity.PRIVATE, now=NOW,
    ).allowed
    assert not policy.authorize_serve(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent_epoch="1", retention_epoch="3", consent=consent(), retention=retention(),
        sensitivity=Sensitivity.PRIVATE, now=NOW,
    ).allowed


def test_disable_and_expired_retention_fail_closed():
    policy = ConsentRetentionPolicy()
    disabled = policy.authorize_serve(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent_epoch="2", retention_epoch="3", consent=consent(consent_state=ConsentState.DISABLED),
        retention=retention(), sensitivity=Sensitivity.PUBLIC, now=NOW,
    )
    assert not disabled.allowed
    expired = policy.authorize_serve(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent_epoch="2", retention_epoch="3", consent=consent(),
        retention=retention(expires_at=NOW), sensitivity=Sensitivity.PUBLIC, now=NOW,
    )
    assert expired.disposition is ConsentRetentionDisposition.DELETION_REQUIRED
    cross_workspace = policy.authorize_capture(
        workspace_id="workspace-2", source_ref_id="source-1", project_ref_id="project-1",
        consent=consent(), retention=retention(), sensitivity=Sensitivity.PUBLIC, now=NOW,
    )
    assert not cross_workspace.allowed
    downgrade = policy.authorize_capture(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent=consent(), retention=retention(), sensitivity=Sensitivity.PUBLIC, now=NOW,
        prior_sensitivity=Sensitivity.PRIVATE,
    )
    assert not downgrade.allowed
def test_authorization_reparses_timestamps_epochs_enums_and_dto_shape():
    policy = ConsentRetentionPolicy()
    for malformed in ("2030-02-01", "2030-02-01T00:00:00", "2030-02-01T00:00:00+25:00", "2030-02-01 00:00:00Z", "2030-02-01T00:00:00z", "2030-02-01T00:00:00+00:00", "2030-02-01T00:00:00.001Z"):
        assert not policy.authorize_capture(
            workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
            consent=consent(expires_at=malformed), retention=retention(),
            sensitivity=Sensitivity.PUBLIC, now=NOW,
        ).allowed
    assert not policy.authorize_capture(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent=consent(consent_epoch="02"), retention=retention(),
        sensitivity=Sensitivity.PUBLIC, now=NOW,
    ).allowed
    assert not policy.authorize_capture(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent=consent(consent_state="enabled"), retention=retention(),
        sensitivity=Sensitivity.PUBLIC, now=NOW,
    ).allowed
    assert not policy.authorize_serve(
        workspace_id="workspace-1", source_ref_id="source-1", project_ref_id="project-1",
        consent_epoch="0", retention_epoch="3", consent=consent(), retention=retention(),
        sensitivity=Sensitivity.PUBLIC, now=NOW,
    ).allowed


def test_body_free_consent_and_retention_rows_round_trip(tmp_path):
    database = LifecycleDatabase(tmp_path / "lifecycle.sqlite")
    database.initialize()
    with database.unit_of_work() as uow:
        uow.upsert_source_consent_state("workspace-1", "source-1", "project-1", "2", "enabled", "private", DIGEST, FUTURE, NOW)
        uow.upsert_retention_policy("workspace-1", "source-1", "project-1", "3", "active", "private", DIGEST, FUTURE, NOW)
        assert uow.get_source_consent_state("workspace-1", "source-1", "project-1")["consent_epoch"] == "2"
        assert uow.get_retention_policy("workspace-1", "source-1", "project-1")["retention_epoch"] == "3"
    assert_no_plaintext_columns(database.con)
    database.close()
