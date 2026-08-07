"""Pure, deterministic runtime for a single pinned Stage-3 recall snapshot."""
from __future__ import annotations

from dataclasses import dataclass

from .second_brain_temporal import parse_utc


@dataclass(frozen=True, slots=True)
class RuntimeContinuationV2:
    continuation_ref: str
    workspace_ref: str
    capability_ref: str
    authority_epoch: str
    query_digest: str
    scope_digest: str
    cursor: str
    expires_at: str
    base_snapshot_digest: str
    transaction_cut: str
    generation_ref: str
    generation_digest: str
    checkpoint_ref: str
    checkpoint_digest: str
    freshness_digest: str
    authority_checkpoint_digest: str


@dataclass(frozen=True, slots=True)
class RuntimeCandidateV2:
    candidate_ref: str
    revision_ref: str
    state: str
    content_digest: str
    support_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "support_refs", tuple(self.support_refs))


@dataclass(frozen=True, slots=True)
class RuntimeConflictV2:
    left_candidate_ref: str
    right_candidate_ref: str
    state: str


@dataclass(frozen=True, slots=True)
class RuntimeCitationV2:
    candidate_ref: str
    source_ref: str
    citation_digest: str


@dataclass(frozen=True, slots=True)
class RuntimePinnedRecallSnapshotV2:
    snapshot_digest: str
    workspace_ref: str
    capability_ref: str
    authority_epoch: str
    query_digest: str
    transaction_cut: str
    valid_at: str
    recorded_at: str
    scope_digest: str
    generation_ref: str
    generation_digest: str
    checkpoint_ref: str
    checkpoint_digest: str
    freshness_digest: str
    authority_checkpoint_digest: str
    authorization: str
    global_floor: str
    binding: str
    recovery: str
    route: str
    cohort: str
    deletion: str
    consent: str
    candidates: tuple[RuntimeCandidateV2, ...]
    conflicts: tuple[RuntimeConflictV2, ...]
    citations: tuple[RuntimeCitationV2, ...]
    has_more: bool = False
    base_snapshot_digest: str | None = None
    incoming_cursor_digest: str | None = None
    incoming_continuation_ref: str | None = None
    continuation: RuntimeContinuationV2 | None = None
    unverified_conflicts: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for name in ("candidates", "conflicts", "citations"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
        markers = tuple(tuple(item) for item in self.unverified_conflicts)
        if any(len(item) != 2 or not all(isinstance(ref, str) and ref for ref in item) for item in markers) or tuple(sorted(set(markers))) != markers:
            raise ValueError("unverified conflicts must be sorted and unique reference pairs")
        object.__setattr__(self, "unverified_conflicts", markers)
        if len({item.candidate_ref for item in self.candidates}) != len(self.candidates):
            raise ValueError("candidate refs must be unique")
        if any(item.state not in {"OPEN", "RESOLVED"} for item in self.conflicts):
            raise ValueError("invalid conflict state")


@dataclass(frozen=True, slots=True)
class RuntimeRecallRequestV2:
    snapshot_digest: str
    workspace_ref: str
    capability_ref: str
    authority_epoch: str
    query_digest: str
    valid_at: str
    recorded_at: str
    scope_digest: str
    cursor: str | None = None
    continuation: RuntimeContinuationV2 | None = None


@dataclass(frozen=True, slots=True)
class RuntimeRecallResultV2:
    candidate_ref: str
    revision_ref: str
    content_digest: str
    citations: tuple[RuntimeCitationV2, ...]
    contrary_citations: tuple[RuntimeCitationV2, ...]
    support_count: int
    unverified_conflicts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuntimeRecallAnswerV2:
    results: tuple[RuntimeRecallResultV2, ...]
    abstained: bool
    reason: str | None
    has_more: bool = False
    continuation: RuntimeContinuationV2 | None = None


def _blocked(snapshot: RuntimePinnedRecallSnapshotV2) -> str | None:
    if snapshot.authorization != "ALLOW":
        return "authorization"
    for name in ("global_floor", "binding", "recovery", "route", "cohort"):
        if getattr(snapshot, name) != "PASS":
            return name
    for name in ("deletion", "consent"):
        if getattr(snapshot, name) != "PASS":
            return name
    return None


def _pinned_serving_fields(value: object) -> tuple[str, ...]:
    """Serving-authority identity shared by every page of one continuation chain.

    ``authority_commitment_digest`` is deliberately excluded: it binds the
    per-request ``authority_provenance_ref``/``authority_provenance_digest``, so
    it is page-scoped by construction. Core already binds the continuation to
    the page it was minted on (``RecallServeSnapshotV2`` requires an outgoing
    continuation to carry that snapshot's authority and digest) and verifies its
    signature on the way back, so no cross-page equality is available or needed.
    """
    return (value.transaction_cut, value.generation_ref, value.generation_digest,
            value.checkpoint_ref, value.checkpoint_digest, value.freshness_digest,
            value.authority_checkpoint_digest)


class SecondBrainRecallRuntime:
    """Ranks only the supplied immutable snapshot; it has no ports or storage imports."""

    def recall(self, snapshot: RuntimePinnedRecallSnapshotV2, request: RuntimeRecallRequestV2) -> RuntimeRecallAnswerV2:
        if tuple(getattr(snapshot, name) for name in ("snapshot_digest", "workspace_ref", "capability_ref", "authority_epoch", "query_digest", "valid_at", "recorded_at", "scope_digest")) != (request.snapshot_digest, request.workspace_ref, request.capability_ref, request.authority_epoch, request.query_digest, request.valid_at, request.recorded_at, request.scope_digest):
            return RuntimeRecallAnswerV2((), True, "pinned_drift")
        blocked = _blocked(snapshot)
        if blocked:
            return RuntimeRecallAnswerV2((), True, blocked)
        if request.continuation is not None:
            continuation = request.continuation
            if request.cursor != continuation.cursor or parse_utc(continuation.expires_at) <= parse_utc(request.recorded_at):
                return RuntimeRecallAnswerV2((), True, "continuation_invalid")
            continuation_fields = ("workspace_ref", "capability_ref", "authority_epoch", "query_digest", "scope_digest")
            if tuple(getattr(snapshot, field) for field in continuation_fields) != tuple(getattr(continuation, field) for field in continuation_fields) or (snapshot.base_snapshot_digest, snapshot.incoming_continuation_ref) != (continuation.base_snapshot_digest, continuation.continuation_ref) or _pinned_serving_fields(snapshot) != _pinned_serving_fields(continuation):
                return RuntimeRecallAnswerV2((), True, "continuation_drift")
        elif request.cursor is not None:
            return RuntimeRecallAnswerV2((), True, "cursor_without_continuation")
        page_state = (snapshot.has_more, snapshot.continuation if snapshot.has_more else None)
        candidates = {item.candidate_ref: item for item in snapshot.candidates if item.state == "APPROVED"}
        if not candidates:
            return RuntimeRecallAnswerV2((), True, "approval_verification", *page_state)
        citations = {ref: tuple(sorted((citation for citation in snapshot.citations if citation.candidate_ref == ref), key=lambda item: (item.source_ref, item.citation_digest))) for ref in candidates}
        eligible = {ref: item for ref, item in candidates.items() if citations[ref]}
        if not eligible:
            return RuntimeRecallAnswerV2((), True, "citation_verification", *page_state)
        open_pairs = [pair for pair in snapshot.conflicts if pair.state == "OPEN" and pair.left_candidate_ref in eligible and pair.right_candidate_ref in eligible]
        # DB-04: an approved counterpart dropped for missing citations must still be
        # signalled, so a surviving candidate is never served as unopposed.
        uncited = {ref for ref in candidates if ref not in eligible}
        unverified: dict[str, set[str]] = {}
        for near, far in snapshot.unverified_conflicts:
            unverified.setdefault(near, set()).add(far)
        for pair in snapshot.conflicts:
            if pair.state not in {"OPEN", "RESOLVED"}:
                continue
            for near, far in ((pair.left_candidate_ref, pair.right_candidate_ref), (pair.right_candidate_ref, pair.left_candidate_ref)):
                if near in eligible and far in uncited:
                    unverified.setdefault(near, set()).add(far)
        excluded: set[str] = set()
        contrary: dict[str, list[RuntimeCitationV2]] = {}
        for pair in open_pairs:
            left, right = eligible[pair.left_candidate_ref], eligible[pair.right_candidate_ref]
            left_score, right_score = len(left.support_refs), len(right.support_refs)
            if left_score == right_score:
                excluded.update((left.candidate_ref, right.candidate_ref))
            else:
                winner, loser = (left, right) if left_score > right_score else (right, left)
                contrary.setdefault(winner.candidate_ref, []).extend(citations[loser.candidate_ref])
                excluded.add(loser.candidate_ref)
        contrary = {
            ref: sorted(set(items), key=lambda item: (item.candidate_ref, item.source_ref, item.citation_digest))
            for ref, items in contrary.items()
        }
        ranked = sorted((item for ref, item in eligible.items() if ref not in excluded), key=lambda item: (-len(item.support_refs), item.candidate_ref, item.revision_ref))
        results = tuple(RuntimeRecallResultV2(item.candidate_ref, item.revision_ref, item.content_digest, citations[item.candidate_ref], tuple(contrary.get(item.candidate_ref, ())), len(item.support_refs), tuple(sorted(unverified.get(item.candidate_ref, ())))) for item in ranked)
        return RuntimeRecallAnswerV2(results, not results, "conflict" if not results else None, *page_state)


__all__ = [name for name in globals() if name.startswith("Runtime") or name == "SecondBrainRecallRuntime"]
