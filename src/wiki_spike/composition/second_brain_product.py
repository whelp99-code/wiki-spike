"""The sole authenticated Stage-3 product composition root."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
    require_security_context_authority,
)


class ProductCompositionError(ValueError):
    """The verified Stage-0 authority or closed Stage-3 dependencies are absent."""


class _Authority(Protocol):
    def require(self, **scope: object) -> object: ...


@dataclass(frozen=True)
class SecondBrainProductV2:
    """Closed graph exposed only through authenticated V2 transports."""

    authority: SecurityContextAuthority
    ledger: SecondBrainLedgerService
    recall: SecondBrainRecallService


def compose_second_brain_product_v2(
    *, authority: SecurityContextAuthority, database: LifecycleDatabase, cas: object | None = None
) -> SecondBrainProductV2:
    """Validate Stage-0 before constructing any mutable Stage-3 authority.

    ``authority`` is deliberately opaque: callers cannot substitute a resolved
    scope mapping, a key, or a root reference for the revalidating authority.
    """
    if not isinstance(database, LifecycleDatabase) or database.con is None:
        raise ProductCompositionError("an initialized LifecycleDatabase is required")
    try:
        require_security_context_authority(authority)
    except Exception as exc:
        raise ProductCompositionError("a currently resolved Stage-0 authority is required") from exc
    ledger_authority = LifecycleLedgerAuthority(database, cas)
    return SecondBrainProductV2(
        authority=authority,
        ledger=SecondBrainLedgerService(ledger_authority, ledger_authority),
        recall=SecondBrainRecallService(ledger_authority),
    )
