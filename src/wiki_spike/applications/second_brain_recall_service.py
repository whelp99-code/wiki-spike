"""Single-acquisition application boundary for Stage-3 recall."""
from __future__ import annotations

from wiki_spike.memory_core.second_brain_ledger_contracts import RecallSnapshotRequestV2
from wiki_spike.memory_core.second_brain_ledger_ports import AtomicRecallSnapshotPort, ValidatedRecallSnapshotAcquisitionV2
from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeCandidateV2,
    RuntimeCitationV2,
    RuntimeConflictV2,
    RuntimeContinuationV2,
    RuntimePinnedRecallSnapshotV2,
    RuntimeRecallAnswerV2,
    RuntimeRecallRequestV2,
    SecondBrainRecallRuntime,
)


def _continuation(value: object) -> RuntimeContinuationV2 | None:
    if value is None:
        return None
    return RuntimeContinuationV2(
        value.continuation_ref, value.workspace_ref, value.capability_ref, value.authority_epoch,
        value.query_digest, value.scope_digest, value.cursor, value.expires_at,
        value.base_snapshot_digest, value.transaction_cut, value.generation_ref,
        value.generation_digest, value.checkpoint_ref, value.checkpoint_digest,
        value.freshness_digest, value.authority_checkpoint_digest,
        value.authority_commitment_digest,
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
        source.authority_checkpoint_digest, source.authority_commitment_digest,
        source.authorization.decision, source.global_floor.state, source.binding.state,
        source.recovery.state, source.route.state, source.cohort.state, source.deletion.state,
        source.consent.state,
        tuple(RuntimeCandidateV2(item.candidate_ref, item.revision_ref, item.state, item.content_digest, item.support_refs) for item in source.candidates),
        tuple(RuntimeConflictV2(item.left_candidate_ref, item.right_candidate_ref, item.state) for item in source.conflicts),
        tuple(RuntimeCitationV2(item.candidate_ref, item.source_ref, item.citation_digest) for item in source.citations),
        source.base_snapshot_digest, source.incoming_cursor_digest, source.incoming_continuation_ref,
        _continuation(source.continuation),
    )
    return snapshot, RuntimeRecallRequestV2(
        snapshot.snapshot_digest, request.workspace_ref, request.capability_ref,
        request.authority_epoch, request.query_digest, request.valid_at, request.recorded_at,
        request.scope_digest, None if request.continuation is None else request.continuation.cursor,
        _continuation(request.continuation),
    )


class SecondBrainRecallService:
    """Acquires exactly one Core snapshot before invoking the pure runtime."""

    def __init__(self, snapshots: AtomicRecallSnapshotPort, runtime: SecondBrainRecallRuntime | None = None) -> None:
        self._snapshots = snapshots
        self._runtime = runtime or SecondBrainRecallRuntime()

    def recall(self, request: RecallSnapshotRequestV2) -> RuntimeRecallAnswerV2:
        acquisition = self._snapshots.acquire_recall_snapshot(request)
        snapshot, runtime_request = convert_validated_recall_snapshot(acquisition)
        return self._runtime.recall(snapshot, runtime_request)
