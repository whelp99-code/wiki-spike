"""Strict, body-free authenticated V2 API adapter."""
from __future__ import annotations

from dataclasses import dataclass
from threading import Lock
from typing import Any

from wiki_spike.composition.second_brain_product import SecondBrainProductV2
from wiki_spike.memory_core.second_brain_ledger_contracts import LedgerCommandV2, RecallSnapshotRequestV2


@dataclass(frozen=True)
class CapabilityUseV2:
    """One bounded, replay-protected use of an already-issued capability."""
    capability_ref: str
    authority_epoch: str
    workspace_ref: str
    scope_digest: str
    action: str
    nonce: str
    authorized_actions: tuple[str, ...]

    def __post_init__(self) -> None:
        closed = {"command", "review", "transition", "recall", "citation", "status"}
        if self.action not in closed or not isinstance(self.authorized_actions, tuple):
            raise ValueError("action is closed")
        if not self.authorized_actions or set(self.authorized_actions) - closed or self.authorized_actions != tuple(sorted(set(self.authorized_actions))):
            raise ValueError("authorized actions must be closed, sorted, and unique")
        if self.action not in self.authorized_actions:
            raise ValueError("capability action is out of scope")
        if not all(isinstance(x, str) and x for x in (self.capability_ref, self.authority_epoch, self.workspace_ref, self.scope_digest, self.nonce)):
            raise ValueError("capability use must contain non-empty opaque bindings")
        if len(self.nonce) > 128:
            raise ValueError("nonce exceeds bound")


@dataclass(frozen=True)
class V2Result:
    code: str
    receipt: dict[str, str]

def encode_opaque_receipt_field(values: dict[str, str]) -> str:
    """Flatten a small string-only mapping into one bounded receipt field.

    Every ``RecallContinuationV2`` field is a plain opaque ref/digest/instant
    string containing neither ``;`` nor ``=``, so this reversible encoding
    needs no general-purpose serializer dependency at this closed boundary.
    The separators are enforced rather than assumed: an unexpected value fails
    closed instead of emitting a silently unparseable handle.
    """
    if any(mark in text for pair in values.items() for text in pair for mark in ";="):
        raise ValueError("receipt field values must not contain a separator")
    return ";".join(f"{key}={values[key]}" for key in sorted(values))

class SecondBrainApiV2:
    """Only bounded V2 command, recall, citation, and status operations."""
    def __init__(self, product: SecondBrainProductV2) -> None:
        if not isinstance(product, SecondBrainProductV2):
            raise TypeError("a V2 product is required")
        self._product, self._replays, self._lock = product, set(), Lock()

    def _authorize(self, use: CapabilityUseV2, action: str) -> None:
        if not isinstance(use, CapabilityUseV2) or use.action != action:
            raise PermissionError("capability action is out of scope")
        self._product.authority.require()
        with self._lock:
            key = (use.capability_ref, use.nonce)
            if key in self._replays:
                raise PermissionError("capability use was replayed")
            self._replays.add(key)

    @staticmethod
    def _bound(use: CapabilityUseV2, value: Any) -> None:
        for field in ("capability_ref", "authority_epoch", "workspace_ref"):
            if getattr(value, field) != getattr(use, field):
                raise PermissionError("capability binding does not match request")
        if hasattr(value, "scope_digest") and value.scope_digest != use.scope_digest:
            raise PermissionError("capability scope does not match request")

    def command(self, use: CapabilityUseV2, command: LedgerCommandV2) -> V2Result:
        action = "review" if command.kind.startswith("REVIEW_") else "transition" if command.kind in {"REVOKE", "FORGET", "SUPERSEDE", "CORRECT", "DECLARE_CONTRADICTION"} else "command"
        self._bound(use, command); self._authorize(use, action)
        receipt = self._product.ledger.append(command)
        return V2Result("COMMITTED", {"command_ref": receipt.command_ref, "transaction_cut": receipt.transaction_cut, "ledger_epoch": receipt.ledger_epoch, "receipt_digest": receipt.receipt_digest})

    def recall(self, use: CapabilityUseV2, request: RecallSnapshotRequestV2) -> V2Result:
        self._bound(use, request); self._authorize(use, "recall")
        answer = self._product.recall.recall(request)
        receipt = {
            "result_count": str(len(answer.results)),
            "reason": answer.reason or "",
            "has_more": "true" if answer.has_more else "false",
            "continuation": "" if answer.continuation is None else encode_opaque_receipt_field(answer.continuation.to_mapping()),
        }
        return V2Result("ABSTAINED" if answer.abstained else "OK", receipt)

    def citation(self, use: CapabilityUseV2, request: RecallSnapshotRequestV2, candidate_ref: str) -> V2Result:
        if not isinstance(candidate_ref, str) or not candidate_ref or len(candidate_ref) > 128:
            raise ValueError("candidate reference is bounded")
        self._bound(use, request); self._authorize(use, "citation")
        answer = self._product.recall.recall(request)
        citations = tuple(c for result in answer.results if result.candidate_ref == candidate_ref for c in result.citations)
        if answer.abstained:
            return V2Result("ABSTAINED", {"candidate_ref": candidate_ref, "citation_count": "0"})
        # An off-page candidate and a genuinely uncited one both show zero
        # citations in this page's ranked results, and reporting "OK" for
        # either is indistinguishable from the caller's perspective. When more
        # pages remain we cannot yet rule out "merely off-page", so we return
        # a distinct, explicit code instead of ever claiming OK/zero for a
        # candidate we have not fully resolved across every page.
        if not citations and answer.has_more:
            return V2Result("NOT_SERVED", {"candidate_ref": candidate_ref, "citation_count": "0"})
        return V2Result("OK", {"candidate_ref": candidate_ref, "citation_count": str(len(citations))})

    def status(self, use: CapabilityUseV2) -> V2Result:
        self._authorize(use, "status")
        return V2Result("OK", {"workspace_ref": use.workspace_ref, "authority_epoch": use.authority_epoch})
