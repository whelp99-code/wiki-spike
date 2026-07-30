"""DB-03's scope inventory is written down four times; they must agree.

`docs/product/decisions/DB-03-migration-sources.md` is the authority. The same
three names also live in `second_brain_contracts._REQUIRED_SCOPE_INVENTORY`,
`second_brain_capture_contracts.MIGRATION_SOURCES`, and this change's
`MIGRATION_SOURCE_NAMES`. DB-03's expiry clause anticipates a versioned
superseding record, so the set will move; when it does, every copy must move
with it rather than one drifting silently.

This follows the existing doc-agreement convention of
`test_decision_doc_slo_agreement.py` (DB-05) and `test_db07_doc_cutover_agreement.py`.
"""
from __future__ import annotations

import re
from pathlib import Path

from wiki_spike.memory_core.second_brain_capture_contracts import MIGRATION_SOURCES
from wiki_spike.memory_core.second_brain_contracts import (
    _REQUIRED_SCOPE_INVENTORY,
    SCOPED_DECISIONS,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (
    MIGRATION_SOURCE_NAMES,
)

DOC = (
    Path(__file__).resolve().parents[2]
    / "docs" / "product" / "decisions" / "DB-03-migration-sources.md"
)


def documented_scope_names() -> set[str]:
    """Read the canonical inventory line, not the whole document.

    The line is: '- **Canonical scope inventory:** three DB-03 `migration_source`
    scope names, exactly `a`, `b`, and `c`; each is independently resolved.'
    """
    for line in DOC.read_text(encoding="utf-8").splitlines():
        if line.startswith("- **Canonical scope inventory:**"):
            names = set(re.findall(r"`([^`]+)`", line))
            names.discard("migration_source")
            return names
    raise AssertionError("DB-03 no longer states a canonical scope inventory line")


def test_the_document_still_states_exactly_three_scope_names():
    assert len(documented_scope_names()) == 3


def test_every_copy_of_the_inventory_agrees_with_the_document():
    documented = documented_scope_names()
    assert set(MIGRATION_SOURCE_NAMES) == documented
    assert _REQUIRED_SCOPE_INVENTORY["DB-03"] == documented
    assert set(MIGRATION_SOURCES) == documented


def test_the_evidence_module_lists_the_names_in_a_stable_order():
    """A tuple order that drifts would churn nothing but reviewer attention."""
    assert MIGRATION_SOURCE_NAMES == tuple(sorted(MIGRATION_SOURCE_NAMES))


def test_db03_is_still_a_scoped_decision():
    """A global DB-03 would make per-source evidence meaningless."""
    assert "DB-03" in SCOPED_DECISIONS
