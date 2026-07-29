"""The sole authenticated Stage-3 product composition root."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Mapping, Protocol

from wiki_spike.applications.second_brain_ledger_service import SecondBrainLedgerService
from wiki_spike.applications.second_brain_recall_service import SecondBrainRecallService
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.second_brain_ledger import LifecycleLedgerAuthority
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2, RecallTrustVerifierV2, mint_recall_trust_authority_v2,
)
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
    *,
    authority: SecurityContextAuthority,
    database: LifecycleDatabase,
    cas: object | None = None,
    verifier: RecallTrustVerifierV2 | None = None,
    clock: Callable[[], str] | None = None,
    provenance: Mapping[str, AuthorityProvenanceV2] | None = None,
    snapshot_signer: Callable[[bytes], str] | None = None,
    signer_ref: str | None = None,
    key_id: str | None = None,
) -> SecondBrainProductV2:
    """Construct the closed production graph with all Stage-3 trust roots."""
    if not isinstance(database, LifecycleDatabase) or database.con is None:
        raise ProductCompositionError("an initialized LifecycleDatabase is required")
    if cas is None or not callable(getattr(cas, "exists", None)):
        raise ProductCompositionError("a content-addressed existence authority is required")
    if (
        not callable(snapshot_signer)
        or not isinstance(signer_ref, str)
        or not isinstance(key_id, str)
        or verifier is None
        or clock is None
        or provenance is None
    ):
        raise ProductCompositionError("trusted Stage-3 authority dependencies are required")
    try:
        require_security_context_authority(authority)
        trust_authority = mint_recall_trust_authority_v2(authority, verifier, clock, provenance)
    except Exception as exc:
        raise ProductCompositionError("trusted Stage-3 authority dependencies are required") from exc
    ledger_authority = LifecycleLedgerAuthority(
        database, cas, trust_authority, snapshot_signer, signer_ref=signer_ref, key_id=key_id
    )
    return SecondBrainProductV2(
        authority=authority,
        ledger=SecondBrainLedgerService(ledger_authority, ledger_authority),
        recall=SecondBrainRecallService(ledger_authority),
    )
