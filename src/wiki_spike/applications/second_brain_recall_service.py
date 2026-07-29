"""Single-acquisition application boundary for Stage-3 recall."""
from __future__ import annotations

from wiki_spike.memory_core.second_brain_ledger_contracts import RecallContinuationV2, RecallSnapshotRequestV2
from wiki_spike.memory_core.second_brain_ledger_ports import AtomicRecallSnapshotPort, ValidatedRecallSnapshotAcquisitionV2
from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeCandidateV2,
    RuntimeCitationV2,
    RuntimeConflictV2,
    RuntimeContinuationV2,
    RuntimePinnedRecallSnapshotV2,
    RuntimeRecallAnswerV2,
    RuntimeRecallRequestV2,
    RuntimeRecallResultV2,
    SecondBrainRecallRuntime,
)


def _continuation(value: object) -> RuntimeContinuationV2 | None:
    if value is None:
        return None
    return RuntimeContinuationV2(
        value.continuation_ref, value.workspace_ref, value.capability_ref, value.authority_epoch,
        value.query_digest, value.scope_digest, value.cursor_handle_ref, value.expires_at,
        value.base_snapshot_digest, value.transaction_cut, value.generation_ref,
        value.generation_digest, value.checkpoint_ref, value.checkpoint_digest,
        value.freshness_digest, value.authority_checkpoint_digest,
    )


def convert_validated_recall_snapshot(acquisition: ValidatedRecallSnapshotAcquisitionV2) -> tuple[RuntimePinnedRecallSnapshotV2, RuntimeRecallRequestV2]:
    """Pure total conversion of Core's already-validated acquisition proof.

    This function intentionally performs no port, filesystem, clock, or network reads.
    """
    if not isinstance(acquisition, ValidatedRecallSnapshotAcquisitionV2):
        raise TypeError("acquisition must be ValidatedRecallSnapshotAcquisitionV2")
    source, request = acquisition.snapshot, acquisition.request
    snapshot = RuntimePinnedRecallSnapshotV2(
        source.snapshot_digest, source.workspace_ref, source.capability_ref, source.authority_epoch,
        source.query_digest, source.transaction_cut, source.valid_at, source.recorded_at,
        source.scope_digest, source.generation_ref, source.generation_digest,
        source.checkpoint_ref, source.checkpoint_digest, source.freshness_digest,
        source.authority_checkpoint_digest,
        source.authorization.decision, source.global_floor.state, source.binding.state,
        source.recovery.state, source.route.state, source.cohort.state, source.deletion.state,
        source.consent.state,
        tuple(RuntimeCandidateV2(item.candidate_ref, item.revision_ref, item.state, item.content_digest, item.support_refs) for item in source.candidates),
        tuple(RuntimeConflictV2(item.left_candidate_ref, item.right_candidate_ref, item.state) for item in source.conflicts),
        tuple(RuntimeCitationV2(item.candidate_ref, item.evidence.immutable_source_ref, item.citation_digest) for item in source.citations),
        source.has_more,
        source.base_snapshot_digest, source.incoming_cursor_digest, source.incoming_continuation_ref,
        _continuation(source.continuation),
    )
    return snapshot, RuntimeRecallRequestV2(
        snapshot.snapshot_digest, request.workspace_ref, request.capability_ref,
        request.authority_epoch, request.query_digest, request.valid_at, request.recorded_at,
        request.scope_digest, None if request.continuation is None else request.continuation.cursor_handle_ref,
        _continuation(request.continuation),
    )


class SecondBrainRecallAnswerV2:
    """Application-boundary recall answer.

    Wraps the pure ``RuntimeRecallAnswerV2`` with the real, Core-signed
    ``RecallContinuationV2`` a caller needs to actually request the next page.
    ``SecondBrainRecallRuntime`` only ever sees the reduced, pure
    ``RuntimePinnedRecallSnapshotV2.continuation`` projection (no signature, no
    trust fields); the full signed continuation a caller must echo back on a
    follow-up ``RecallSnapshotRequestV2`` lives only on Core's
    ``ValidatedRecallSnapshotAcquisitionV2.snapshot``, which is available only
    here at the application boundary and deliberately never inside the pure
    runtime.
    """

    __slots__ = ("results", "abstained", "reason", "has_more", "continuation")

    def __init__(
        self,
        results: tuple[RuntimeRecallResultV2, ...],
        abstained: bool,
        reason: str | None,
        has_more: bool,
        continuation: RecallContinuationV2 | None,
    ) -> None:
        self.results = results
        self.abstained = abstained
        self.reason = reason
        self.has_more = has_more
        self.continuation = continuation


class SecondBrainRecallService:
    """Acquires exactly one Core snapshot before invoking the pure runtime."""

    def __init__(self, snapshots: AtomicRecallSnapshotPort, runtime: SecondBrainRecallRuntime | None = None) -> None:
        self._snapshots = snapshots
        self._runtime = runtime or SecondBrainRecallRuntime()

    def recall(self, request: RecallSnapshotRequestV2) -> SecondBrainRecallAnswerV2:
        acquisition = self._snapshots.acquire_recall_snapshot(request)
        snapshot, runtime_request = convert_validated_recall_snapshot(acquisition)
        answer: RuntimeRecallAnswerV2 = self._runtime.recall(snapshot, runtime_request)
        continuation = acquisition.snapshot.continuation if answer.has_more else None
        return SecondBrainRecallAnswerV2(answer.results, answer.abstained, answer.reason, answer.has_more, continuation)
