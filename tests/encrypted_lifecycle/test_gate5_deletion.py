"""Gate 5 deletion phase state machine + DeletionStateV1 builder tests."""
from __future__ import annotations

import itertools

import pytest

from wiki_spike.infrastructure.deletion import (
    DELETION_STATE_SCHEMA,
    DeletionError,
    DeletionPhase,
    ReportTierStatus,
    _PHASE_ORDER,
    advance,
    build_deletion_state,
    initial_report,
    is_crypto_shredded,
    is_vetoed,
    set_report_tier,
)

WORKSPACE_ID = "ws-alpha"
DELETION_COMMAND_ID = "a" * 64
TIMESTAMP = "2026-07-25T00:00:00Z"
HEX64_DIGEST = "b" * 64


def test_happy_path_full_walk_via_advance() -> None:
    current = _PHASE_ORDER[0]
    assert current is DeletionPhase.REQUESTED
    for expected_next in _PHASE_ORDER[1:]:
        current = advance(current, expected_next)
        assert current == expected_next
    assert current == DeletionPhase.COMPLETE


def test_illegal_same_phase_transition_rejected() -> None:
    for phase in _PHASE_ORDER:
        with pytest.raises(DeletionError) as excinfo:
            advance(phase, phase)
        assert excinfo.value.code == "illegal_deletion_transition"


def test_illegal_skip_ahead_transition_rejected() -> None:
    with pytest.raises(DeletionError) as excinfo:
        advance(DeletionPhase.REQUESTED, DeletionPhase.TOMBSTONE_ACTIVE)
    assert excinfo.value.code == "illegal_deletion_transition"


def test_illegal_backward_transition_rejected() -> None:
    with pytest.raises(DeletionError) as excinfo:
        advance(DeletionPhase.TOMBSTONE_ACTIVE, DeletionPhase.REQUESTED)
    assert excinfo.value.code == "illegal_deletion_transition"


def test_advance_from_complete_is_terminal() -> None:
    with pytest.raises(DeletionError) as excinfo:
        advance(DeletionPhase.COMPLETE, DeletionPhase.COMPLETE)
    assert excinfo.value.code == "illegal_deletion_transition"
    for target in _PHASE_ORDER:
        if target == DeletionPhase.COMPLETE:
            continue
        with pytest.raises(DeletionError) as excinfo:
            advance(DeletionPhase.COMPLETE, target)
        assert excinfo.value.code == "illegal_deletion_transition"


def test_all_non_successor_pairs_rejected() -> None:
    legal_pairs = {(a, b) for a, b in zip(_PHASE_ORDER, _PHASE_ORDER[1:])}
    for current, target in itertools.product(_PHASE_ORDER, _PHASE_ORDER):
        if (current, target) in legal_pairs:
            continue
        with pytest.raises(DeletionError) as excinfo:
            advance(current, target)
        assert excinfo.value.code == "illegal_deletion_transition"


def test_initial_report_all_three_tiers_pending() -> None:
    report = initial_report()
    assert set(report) == {"live", "backup", "egress"}
    for tier in report.values():
        assert tier == {"status": "PENDING", "verified_at": None, "evidence_digest": None}


def test_set_report_tier_updates_exactly_one_tier_independently() -> None:
    report = initial_report()
    updated = set_report_tier(
        report,
        "backup",
        status=ReportTierStatus.IN_PROGRESS.value,
        verified_at=None,
        evidence_digest=None,
    )
    assert updated["backup"] == {"status": "IN_PROGRESS", "verified_at": None, "evidence_digest": None}
    assert updated["live"] == {"status": "PENDING", "verified_at": None, "evidence_digest": None}
    assert updated["egress"] == {"status": "PENDING", "verified_at": None, "evidence_digest": None}
    # original untouched
    assert report["backup"]["status"] == "PENDING"

    updated2 = set_report_tier(
        updated,
        "egress",
        status=ReportTierStatus.COMPLETE.value,
        verified_at=TIMESTAMP,
        evidence_digest=HEX64_DIGEST,
    )
    assert updated2["egress"] == {"status": "COMPLETE", "verified_at": TIMESTAMP, "evidence_digest": HEX64_DIGEST}
    assert updated2["backup"]["status"] == "IN_PROGRESS"
    assert updated2["live"]["status"] == "PENDING"


def test_set_report_tier_rejects_unknown_tier() -> None:
    report = initial_report()
    with pytest.raises(DeletionError) as excinfo:
        set_report_tier(report, "onsite", status="PENDING", verified_at=None, evidence_digest=None)
    assert excinfo.value.code == "unknown_report_tier"


def test_set_report_tier_rejects_bad_status() -> None:
    report = initial_report()
    with pytest.raises(DeletionError) as excinfo:
        set_report_tier(report, "live", status="DONE", verified_at=None, evidence_digest=None)
    assert excinfo.value.code == "unknown_report_tier_status"


def _valid_state_kwargs(phase: DeletionPhase = DeletionPhase.REQUESTED) -> dict:
    return dict(
        workspace_id=WORKSPACE_ID,
        deletion_command_id=DELETION_COMMAND_ID,
        phase=phase,
        report=initial_report(),
        updated_at=TIMESTAMP,
    )


def test_build_deletion_state_produces_schema_valid_object() -> None:
    state = build_deletion_state(**_valid_state_kwargs())
    assert state == {
        "schema": DELETION_STATE_SCHEMA,
        "workspace_id": WORKSPACE_ID,
        "deletion_command_id": DELETION_COMMAND_ID,
        "phase": "REQUESTED",
        "report": initial_report(),
        "updated_at": TIMESTAMP,
    }


def test_build_deletion_state_accepts_string_phase() -> None:
    kwargs = _valid_state_kwargs()
    kwargs["phase"] = "CRYPTO_SHRED_COMPLETE"
    state = build_deletion_state(**kwargs)
    assert state["phase"] == "CRYPTO_SHRED_COMPLETE"


def test_build_deletion_state_rejects_bad_phase() -> None:
    kwargs = _valid_state_kwargs()
    kwargs["phase"] = "NOT_A_PHASE"
    with pytest.raises(DeletionError) as excinfo:
        build_deletion_state(**kwargs)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_build_deletion_state_rejects_bad_workspace_id_pattern() -> None:
    kwargs = _valid_state_kwargs()
    kwargs["workspace_id"] = "Not-Valid-ID"
    with pytest.raises(DeletionError) as excinfo:
        build_deletion_state(**kwargs)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_build_deletion_state_rejects_non_hex64_deletion_command_id() -> None:
    kwargs = _valid_state_kwargs()
    kwargs["deletion_command_id"] = "not-hex"
    with pytest.raises(DeletionError) as excinfo:
        build_deletion_state(**kwargs)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_build_deletion_state_rejects_extra_key() -> None:
    state = build_deletion_state(**_valid_state_kwargs())
    state["unexpected_field"] = "boom"
    from wiki_spike.infrastructure.deletion import _validate_deletion_state_schema

    with pytest.raises(DeletionError) as excinfo:
        _validate_deletion_state_schema(state)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_build_deletion_state_rejects_bad_tier_status() -> None:
    report = initial_report()
    report["live"]["status"] = "DONE"
    kwargs = _valid_state_kwargs()
    kwargs["report"] = report
    with pytest.raises(DeletionError) as excinfo:
        build_deletion_state(**kwargs)
    assert excinfo.value.code == "deletion_state_schema_violation"


def test_is_vetoed_true_across_all_phases() -> None:
    for phase in _PHASE_ORDER:
        assert is_vetoed(phase) is True
        assert is_vetoed(phase.value) is True


@pytest.mark.parametrize(
    "phase",
    [
        DeletionPhase.REQUESTED,
        DeletionPhase.API_VETO_ACTIVE,
        DeletionPhase.TOMBSTONE_ACTIVE,
        DeletionPhase.CHECKPOINT_COMMITTED,
        DeletionPhase.REVOCATION_KEYS_DESTROYED,
    ],
)
def test_is_crypto_shredded_false_before_shred_complete(phase: DeletionPhase) -> None:
    assert is_crypto_shredded(phase) is False
    assert is_crypto_shredded(phase.value) is False


@pytest.mark.parametrize(
    "phase",
    [
        DeletionPhase.CRYPTO_SHRED_COMPLETE,
        DeletionPhase.PURGE_PENDING,
        DeletionPhase.COMPLETE,
    ],
)
def test_is_crypto_shredded_true_from_shred_complete_onward(phase: DeletionPhase) -> None:
    assert is_crypto_shredded(phase) is True
    assert is_crypto_shredded(phase.value) is True
