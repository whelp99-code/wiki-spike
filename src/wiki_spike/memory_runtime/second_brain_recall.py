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
    authority_commitment_digest: str


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
    authority_commitment_digest: str
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
    base_snapshot_digest: str | None = None
    incoming_cursor_digest: str | None = None
    incoming_continuation_ref: str | None = None
    continuation: RuntimeContinuationV2 | None = None

    def __post_init__(self) -> None:
        for name in ("candidates", "conflicts", "citations"):
            object.__setattr__(self, name, tuple(getattr(self, name)))
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


@dataclass(frozen=True, slots=True)
class RuntimeRecallAnswerV2:
    results: tuple[RuntimeRecallResultV2, ...]
    abstained: bool
    reason: str | None


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


def _pinned_fields(snapshot: RuntimePinnedRecallSnapshotV2) -> tuple[str, ...]:
    return (snapshot.transaction_cut, snapshot.generation_ref, snapshot.generation_digest,
            snapshot.checkpoint_ref, snapshot.checkpoint_digest, snapshot.freshness_digest,
            snapshot.authority_checkpoint_digest, snapshot.authority_commitment_digest)


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
            if tuple(getattr(snapshot, field) for field in continuation_fields) != tuple(getattr(continuation, field) for field in continuation_fields) or (snapshot.base_snapshot_digest, snapshot.incoming_continuation_ref) != (continuation.base_snapshot_digest, continuation.continuation_ref) or _pinned_fields(snapshot) != (continuation.transaction_cut, continuation.generation_ref, continuation.generation_digest, continuation.checkpoint_ref, continuation.checkpoint_digest, continuation.freshness_digest, continuation.authority_checkpoint_digest, continuation.authority_commitment_digest):
                return RuntimeRecallAnswerV2((), True, "continuation_drift")
        elif request.cursor is not None:
            return RuntimeRecallAnswerV2((), True, "cursor_without_continuation")
        candidates = {item.candidate_ref: item for item in snapshot.candidates if item.state == "APPROVED"}
        citations = {ref: tuple(sorted((citation for citation in snapshot.citations if citation.candidate_ref == ref), key=lambda item: (item.source_ref, item.citation_digest))) for ref in candidates}
        eligible = {ref: item for ref, item in candidates.items() if citations[ref]}
        if not eligible:
            return RuntimeRecallAnswerV2((), True, "citation_verification")
        open_pairs = [pair for pair in snapshot.conflicts if pair.state == "OPEN" and pair.left_candidate_ref in eligible and pair.right_candidate_ref in eligible]
        excluded: set[str] = set()
        contrary: dict[str, tuple[RuntimeCitationV2, ...]] = {}
        for pair in open_pairs:
            left, right = eligible[pair.left_candidate_ref], eligible[pair.right_candidate_ref]
            left_score, right_score = len(left.support_refs), len(right.support_refs)
            if left_score == right_score:
                excluded.update((left.candidate_ref, right.candidate_ref))
            else:
                winner, loser = (left, right) if left_score > right_score else (right, left)
                contrary[winner.candidate_ref] = citations[loser.candidate_ref]
                excluded.add(loser.candidate_ref)
        ranked = sorted((item for ref, item in eligible.items() if ref not in excluded), key=lambda item: (-len(item.support_refs), item.candidate_ref, item.revision_ref))
        results = tuple(RuntimeRecallResultV2(item.candidate_ref, item.revision_ref, item.content_digest, citations[item.candidate_ref], contrary.get(item.candidate_ref, ()), len(item.support_refs)) for item in ranked)
        return RuntimeRecallAnswerV2(results, not results, "conflict" if not results else None)


__all__ = [name for name in globals() if name.startswith("Runtime") or name == "SecondBrainRecallRuntime"]
