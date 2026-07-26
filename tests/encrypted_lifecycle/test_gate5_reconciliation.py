"""Tests for the Gate 5 full ADR-0027 §3 binding-proof reconciliation
classifier (``wiki_spike.infrastructure.keystore``).

Covers ``classify_binding_reconciliation`` (all 7 disjoint outcomes, the
fail-closed QUARANTINE_UNKNOWN matrix, and decision-order precedence) and
``conditional_destroy_allowed`` (the zero-call-on-change guard used
immediately before each provider destroy).
"""
from __future__ import annotations

from dataclasses import replace

import pytest

from wiki_spike.infrastructure import keystore as ks

VALID_DIGEST = "aa" * 32


def _external(*, corrupt: bool = False, metadata_digest: str | None = VALID_DIGEST) -> ks.ExternalKeyRecord:
    return ks.ExternalKeyRecord(metadata_digest=metadata_digest, corrupt=corrupt)


_UNSET = object()


def _inputs(
    binding_status: ks.BindingStatus | None,
    *,
    external: ks.ExternalKeyRecord | None = _UNSET,
    membership_verified: bool = False,
    non_membership_verified: bool = False,
    inventories_complete: bool = False,
    collision: bool = False,
    historical_active_without_terminal: bool = False,
    metadata_matches: bool = False,
    never_active: bool = False,
) -> ks.ReconciliationInputs:
    return ks.ReconciliationInputs(
        binding_status=binding_status,
        external=_external() if external is _UNSET else external,
        membership_verified=membership_verified,
        non_membership_verified=non_membership_verified,
        inventories_complete=inventories_complete,
        collision=collision,
        historical_active_without_terminal=historical_active_without_terminal,
        metadata_matches=metadata_matches,
        never_active=never_active,
    )


# ---------------------------------------------------------------------------
# 1. Positive destroy outcomes
# ---------------------------------------------------------------------------


def test_unbound_with_full_proof_destroys_unbound():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.DESTROY_UNBOUND


def test_no_db_row_with_full_proof_destroys_unbound():
    inputs = _inputs(
        None,
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.DESTROY_UNBOUND


def test_loser_with_full_proof_destroys_loser():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.DESTROY_LOSER


def test_expired_with_full_proof_destroys_expired():
    inputs = _inputs(
        ks.BindingStatus.EXPIRED,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.DESTROY_EXPIRED


def test_expired_never_active_without_metadata_match_destroys_unbound():
    inputs = _inputs(
        ks.BindingStatus.EXPIRED,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=False,
        never_active=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.DESTROY_UNBOUND


# ---------------------------------------------------------------------------
# 2. RESUME_EXACT
# ---------------------------------------------------------------------------


def test_prepared_with_membership_and_metadata_match_resumes_exact():
    inputs = _inputs(
        ks.BindingStatus.PREPARED,
        membership_verified=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.RESUME_EXACT


# ---------------------------------------------------------------------------
# 3. QUARANTINE_ACTIVE
# ---------------------------------------------------------------------------


def test_active_binding_quarantines_active_regardless_of_other_flags():
    inputs = _inputs(
        ks.BindingStatus.ACTIVE,
        membership_verified=True,
        non_membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
        never_active=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_ACTIVE


def test_historical_active_without_terminal_quarantines_active_even_with_full_destroy_proof():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
        historical_active_without_terminal=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_ACTIVE


# ---------------------------------------------------------------------------
# 4. QUARANTINE_COLLISION
# ---------------------------------------------------------------------------


def test_collision_quarantines_collision_even_with_full_destroy_proof():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_COLLISION


def test_active_with_collision_quarantines_collision_not_active():
    # Collision (rule 2) is checked before ACTIVE (rule 3).
    inputs = _inputs(
        ks.BindingStatus.ACTIVE,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_COLLISION


# ---------------------------------------------------------------------------
# 5. QUARANTINE_UNKNOWN fail-closed matrix
# ---------------------------------------------------------------------------


def test_unbound_without_non_membership_proof_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        non_membership_verified=False,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_unbound_with_non_membership_proof_but_incomplete_inventories_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        non_membership_verified=True,
        inventories_complete=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


@pytest.mark.parametrize("missing_flag", ["membership_verified", "inventories_complete", "metadata_matches"])
def test_loser_missing_any_required_proof_quarantines_unknown(missing_flag):
    full_proof = dict(membership_verified=True, inventories_complete=True, metadata_matches=True)
    full_proof[missing_flag] = False
    inputs = _inputs(ks.BindingStatus.LOSER, **full_proof)
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


@pytest.mark.parametrize("missing_flag", ["membership_verified", "inventories_complete", "metadata_matches"])
def test_expired_missing_any_required_proof_and_not_never_active_quarantines_unknown(missing_flag):
    full_proof = dict(membership_verified=True, inventories_complete=True, metadata_matches=True)
    full_proof[missing_flag] = False
    inputs = _inputs(ks.BindingStatus.EXPIRED, never_active=False, **full_proof)
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_expired_never_active_missing_membership_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.EXPIRED,
        never_active=True,
        membership_verified=False,
        inventories_complete=True,
        metadata_matches=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_expired_never_active_missing_inventories_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.EXPIRED,
        never_active=True,
        membership_verified=True,
        inventories_complete=False,
        metadata_matches=False,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


@pytest.mark.parametrize("missing_flag", ["membership_verified", "metadata_matches"])
def test_prepared_missing_required_proof_quarantines_unknown(missing_flag):
    full_proof = dict(membership_verified=True, metadata_matches=True)
    full_proof[missing_flag] = False
    inputs = _inputs(ks.BindingStatus.PREPARED, **full_proof)
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_external_none_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        external=None,
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_external_corrupt_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        external=_external(corrupt=True),
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_external_metadata_digest_none_quarantines_unknown():
    inputs = _inputs(
        ks.BindingStatus.UNBOUND,
        external=_external(metadata_digest=None),
        non_membership_verified=True,
        inventories_complete=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


# ---------------------------------------------------------------------------
# 6. Decision-order precedence
# ---------------------------------------------------------------------------


def test_corrupt_external_checked_before_collision():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        external=_external(corrupt=True),
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_none_external_checked_before_collision():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        external=None,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_collision_checked_before_active():
    inputs = _inputs(
        ks.BindingStatus.ACTIVE,
        collision=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_COLLISION


def test_active_checked_before_any_destroy_path():
    inputs = _inputs(
        ks.BindingStatus.LOSER,
        historical_active_without_terminal=True,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    assert ks.classify_binding_reconciliation(inputs) is ks.ReconciliationOutcome.QUARANTINE_ACTIVE


# ---------------------------------------------------------------------------
# 7. conditional_destroy_allowed: zero-call-on-change guard
# ---------------------------------------------------------------------------


def test_conditional_destroy_allowed_when_reread_matches_same_destroy_outcome():
    loser_inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    pre_outcome = ks.classify_binding_reconciliation(loser_inputs)
    assert pre_outcome is ks.ReconciliationOutcome.DESTROY_LOSER
    assert ks.conditional_destroy_allowed(pre_outcome, loser_inputs) is True


def test_conditional_destroy_allowed_false_when_reread_becomes_active():
    loser_inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    pre_outcome = ks.classify_binding_reconciliation(loser_inputs)
    reread_inputs = replace(loser_inputs, binding_status=ks.BindingStatus.ACTIVE)
    assert ks.conditional_destroy_allowed(pre_outcome, reread_inputs) is False


def test_conditional_destroy_allowed_false_when_reread_drifts_to_quarantine_unknown():
    loser_inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    pre_outcome = ks.classify_binding_reconciliation(loser_inputs)
    reread_inputs = replace(loser_inputs, metadata_matches=False)
    assert ks.classify_binding_reconciliation(reread_inputs) is ks.ReconciliationOutcome.QUARANTINE_UNKNOWN
    assert ks.conditional_destroy_allowed(pre_outcome, reread_inputs) is False


def test_conditional_destroy_allowed_false_when_reread_drifts_to_different_destroy_outcome():
    loser_inputs = _inputs(
        ks.BindingStatus.LOSER,
        membership_verified=True,
        inventories_complete=True,
        metadata_matches=True,
    )
    pre_outcome = ks.classify_binding_reconciliation(loser_inputs)
    assert pre_outcome is ks.ReconciliationOutcome.DESTROY_LOSER

    expired_inputs = replace(loser_inputs, binding_status=ks.BindingStatus.EXPIRED)
    assert ks.classify_binding_reconciliation(expired_inputs) is ks.ReconciliationOutcome.DESTROY_EXPIRED
    assert ks.conditional_destroy_allowed(pre_outcome, expired_inputs) is False


def test_conditional_destroy_allowed_always_false_for_non_destroy_pre_outcome_resume_exact():
    prepared_inputs = _inputs(
        ks.BindingStatus.PREPARED,
        membership_verified=True,
        metadata_matches=True,
    )
    pre_outcome = ks.classify_binding_reconciliation(prepared_inputs)
    assert pre_outcome is ks.ReconciliationOutcome.RESUME_EXACT
    # Even though re-classifying the identical inputs matches pre_outcome,
    # a non-destroy pre_outcome must never authorize a destroy.
    assert ks.conditional_destroy_allowed(pre_outcome, prepared_inputs) is False


def test_conditional_destroy_allowed_always_false_for_non_destroy_pre_outcome_quarantine_active():
    active_inputs = _inputs(ks.BindingStatus.ACTIVE)
    pre_outcome = ks.classify_binding_reconciliation(active_inputs)
    assert pre_outcome is ks.ReconciliationOutcome.QUARANTINE_ACTIVE
    assert ks.conditional_destroy_allowed(pre_outcome, active_inputs) is False
