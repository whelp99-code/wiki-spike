"""Pin the DB-07 decision record against the cutover values the code enforces.

DB-07 is globally fatal and its signed record binds `approvers`, yet the exact
four-role set `CutoverDecisionV1` demands appeared nowhere in the repository's
documentation. A signer had to read the source to learn it. The cohort state
machine and the rollback boundary were undocumented the same way.

These tests read the enumerations out of the DB-07 prose and assert the code
accepts exactly them and rejects the near-misses, so the record and the
validator cannot drift apart.
"""
from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest

from wiki_spike.memory_core.contracts import InvalidContractValue
from wiki_spike.memory_core.second_brain_cutover import (
    CutoverDecisionV1,
    assert_destructive_decommission_authorized,
    assert_post_mutation_fail_closed,
    assert_pre_mutation_rollback_allowed,
    canonical_ledger_digest,
)
from wiki_spike.memory_core.second_brain_cutover import _COHORT_STATES

ROOT = Path(__file__).resolve().parents[2]
DB07 = ROOT / "docs" / "product" / "decisions" / "DB-07-cutover-retention.md"
TEXT = DB07.read_text(encoding="utf-8")


def _stage6():
    """Reuse the Stage 6 fixtures rather than rebuild a valid decision body."""
    path = Path(__file__).with_name("test_stage6_cutover.py")
    spec = importlib.util.spec_from_file_location("stage6_cutover_fixtures", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


STAGE6 = _stage6()


def decision_with_roles(roles: list[str]) -> CutoverDecisionV1:
    scope = STAGE6._scope()
    body = STAGE6._decision(scope, STAGE6._cohort(scope)).to_mapping()
    body["approver_roles"] = roles
    # The digest binds the normalised roles the validator derives, not the raw
    # input, so a case or ordering difference must not look like tampering.
    bound = {k: v for k, v in body.items() if k != "decision_digest"}
    bound["approver_roles"] = sorted(role.lower() for role in roles)
    body["decision_digest"] = canonical_ledger_digest("cutover-decision-v1", bound)
    return CutoverDecisionV1.from_mapping(body)


def documented_roles() -> list[str]:
    match = re.search(r"binds exactly four external approver roles: (?P<roles>[^.]+)\.", TEXT)
    assert match, "DB-07 no longer states its approver roles in the expected form"
    return re.findall(r"`([a-z]+)`", match["roles"])


def documented_states() -> list[str]:
    match = re.search(r"advances through exactly these states: (?P<states>[^.]+)\.", TEXT)
    assert match, "DB-07 no longer states its cohort states in the expected form"
    return re.findall(r"`([A-Z_]+)`", match["states"])


def documented_retention_days() -> int:
    match = re.search(r"read-only for (?P<days>\d+) days", TEXT)
    assert match, "DB-07 no longer states its retention window"
    return int(match["days"])


def test_documented_approver_roles_are_exactly_the_enforced_set():
    roles = documented_roles()
    assert len(roles) == 4 and len(set(roles)) == 4
    assert decision_with_roles(roles).approver_roles == tuple(sorted(roles))


@pytest.mark.parametrize("mutation", ["drop", "add", "duplicate"])
def test_a_narrower_broader_or_duplicated_panel_is_rejected(mutation):
    roles = documented_roles()
    candidate = {
        "drop": roles[:-1],
        "add": roles + ["legal"],
        "duplicate": roles[:-1] + [roles[0]],
    }[mutation]
    with pytest.raises(InvalidContractValue, match="approver_roles"):
        decision_with_roles(candidate)


def test_approver_roles_are_compared_case_insensitively():
    roles = documented_roles()
    assert decision_with_roles([role.upper() for role in roles]).approver_roles == tuple(
        sorted(roles)
    )


def test_documented_cohort_states_are_exactly_the_enforced_states():
    assert documented_states() == list(_COHORT_STATES)


def test_rollback_is_legal_only_from_the_documented_state():
    legal = "ROUTE_SWITCHED_NO_MUTATION"
    assert "only state from which the emergency rollback above is legal" in TEXT
    assert legal in documented_states()
    assert_pre_mutation_rollback_allowed(legal)
    for state in _COHORT_STATES:
        if state == legal:
            continue
        with pytest.raises(InvalidContractValue, match="pre-mutation rollback"):
            assert_pre_mutation_rollback_allowed(state)


@pytest.mark.parametrize("state", ["CANONICAL_MUTATED", "ROLLBACK_CLOSED", "DECOMMISSIONED"])
def test_external_rollback_is_closed_in_the_documented_states(state):
    assert f"`{state}`" in TEXT
    with pytest.raises(InvalidContractValue, match="external rollback is closed"):
        assert_post_mutation_fail_closed(state, action="external_rollback")


def test_decommission_requires_the_documented_state_and_retention_window():
    days = documented_retention_days()
    kwargs = {"evidence_backed": True, "human_external_approvals_present": True}
    assert_destructive_decommission_authorized(
        "ROLLBACK_CLOSED", retention_days_elapsed=days, **kwargs
    )
    # One day short is refused, which is what makes it a window rather than a note.
    with pytest.raises(InvalidContractValue, match="retention"):
        assert_destructive_decommission_authorized(
            "ROLLBACK_CLOSED", retention_days_elapsed=days - 1, **kwargs
        )
    # Any other state is refused even once the window has elapsed.
    with pytest.raises(InvalidContractValue, match="ROLLBACK_CLOSED"):
        assert_destructive_decommission_authorized(
            "CANONICAL_MUTATED", retention_days_elapsed=days, **kwargs
        )
