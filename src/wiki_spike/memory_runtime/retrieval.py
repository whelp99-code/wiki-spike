"""P4-04 generation-aware Retrieval Broker.

The broker treats every projection as an untrusted candidate source.  It pins
results to an explicit generation and re-checks lifecycle, workspace, and
sensitivity through authoritative metadata before returning references.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import (
    SENSITIVITY_RANK,
    canonical_int,
    content_id, verify_content_id,
    hex64,
    nonempty,
    safe_code,
    sensitivity,
    string_tuple,
)

RETRIEVAL_QUERY_VERSION = "phase4-retrieval-query-v1"
RETRIEVAL_CANDIDATE_VERSION = "phase4-retrieval-candidate-v1"
RETRIEVAL_RESULT_VERSION = "phase4-retrieval-result-v1"


class RetrievalChannel(str, Enum):
    EXACT = "exact"
    KEYWORD = "keyword"
    CHRONOLOGY = "chronology"
    SEMANTIC = "semantic"
    RELATION = "relation"


CHANNEL_ORDER = {
    RetrievalChannel.EXACT.value: 0,
    RetrievalChannel.KEYWORD.value: 1,
    RetrievalChannel.CHRONOLOGY.value: 2,
    RetrievalChannel.SEMANTIC.value: 3,
    RetrievalChannel.RELATION.value: 4,
}


@dataclass(frozen=True)
class RetrievalQuery:
    retrieval_query_version: str
    query_id: str
    operation_id: str
    workspace_id: str
    actor_id: str
    generation_id: str
    query_digest: str
    maximum_sensitivity: str
    limit: str
    temporal_start: str | None
    temporal_end: str | None
    optional_channels: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        workspace_id: str,
        actor_id: str,
        generation_id: str,
        query_digest: str,
        maximum_sensitivity: str,
        limit: str,
        temporal_start: str | None = None,
        temporal_end: str | None = None,
        optional_channels: Sequence[str] = (),
    ) -> "RetrievalQuery":
        channels = tuple(sorted(set(optional_channels)))
        payload = {
            "retrieval_query_version": RETRIEVAL_QUERY_VERSION,
            "operation_id": operation_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "generation_id": generation_id,
            "query_digest": query_digest,
            "maximum_sensitivity": maximum_sensitivity,
            "limit": limit,
            "temporal_start": temporal_start,
            "temporal_end": temporal_end,
            "optional_channels": list(channels),
        }
        return cls(query_id=content_id("wiki.runtime.retrieval-query.v1", payload), optional_channels=channels, **{k: v for k, v in payload.items() if k != "optional_channels"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.retrieval_query_version != RETRIEVAL_QUERY_VERSION:
            raise InvalidContractValue("unsupported retrieval query version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.workspace_id, "workspace_id")
        nonempty(self.actor_id, "actor_id")
        nonempty(self.generation_id, "generation_id")
        hex64(self.query_digest, "query_digest")
        sensitivity(self.maximum_sensitivity, "maximum_sensitivity")
        canonical_int(self.limit, "limit", maximum=1000)
        channels = string_tuple(self.optional_channels, "optional_channels", sorted_unique=True, codes=True)
        if any(channel not in {RetrievalChannel.SEMANTIC.value, RetrievalChannel.RELATION.value} for channel in channels):
            raise InvalidContractValue("optional_channels may contain only semantic/relation")
        if (self.temporal_start is None) != (self.temporal_end is None):
            raise InvalidContractValue("temporal range requires both start and end")
        verify_content_id(self.query_id, "wiki.runtime.retrieval-query.v1", self.to_mapping(), "query_id", "retrieval query_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "retrieval_query_version": self.retrieval_query_version,
            "query_id": self.query_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "generation_id": self.generation_id,
            "query_digest": self.query_digest,
            "maximum_sensitivity": self.maximum_sensitivity,
            "limit": self.limit,
            "temporal_start": self.temporal_start,
            "temporal_end": self.temporal_end,
            "optional_channels": list(self.optional_channels),
        }


@dataclass(frozen=True)
class RetrievalCandidate:
    retrieval_candidate_version: str
    candidate_id: str
    object_id: str
    revision_id: str
    workspace_id: str
    generation_id: str
    channel: str
    score_micros: str
    sensitivity: str
    lifecycle_status: str
    occurred_at: str | None
    payload_digest: str
    locator_refs: tuple[str, ...]
    conflict_key: str | None = None

    @classmethod
    def create(
        cls,
        *,
        object_id: str,
        revision_id: str,
        workspace_id: str,
        generation_id: str,
        channel: str,
        score_micros: str,
        sensitivity: str,
        lifecycle_status: str,
        occurred_at: str | None,
        payload_digest: str,
        locator_refs: Sequence[str],
        conflict_key: str | None = None,
    ) -> "RetrievalCandidate":
        refs = tuple(sorted(set(locator_refs)))
        payload = {
            "retrieval_candidate_version": RETRIEVAL_CANDIDATE_VERSION,
            "object_id": object_id,
            "revision_id": revision_id,
            "workspace_id": workspace_id,
            "generation_id": generation_id,
            "channel": channel,
            "score_micros": score_micros,
            "sensitivity": sensitivity,
            "lifecycle_status": lifecycle_status,
            "occurred_at": occurred_at,
            "payload_digest": payload_digest,
            "locator_refs": list(refs),
            "conflict_key": conflict_key,
        }
        return cls(candidate_id=content_id("wiki.runtime.retrieval-candidate.v1", payload), locator_refs=refs, **{k: v for k, v in payload.items() if k != "locator_refs"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.retrieval_candidate_version != RETRIEVAL_CANDIDATE_VERSION:
            raise InvalidContractValue("unsupported retrieval candidate version")
        for field in ("object_id", "revision_id", "workspace_id", "generation_id"):
            nonempty(getattr(self, field), field)
        try:
            RetrievalChannel(self.channel)
        except ValueError as exc:
            raise InvalidContractValue("unsupported retrieval channel") from exc
        canonical_int(self.score_micros, "score_micros", maximum=1_000_000)
        sensitivity(self.sensitivity)
        safe_code(self.lifecycle_status, "lifecycle_status")
        hex64(self.payload_digest, "payload_digest")
        string_tuple(self.locator_refs, "locator_refs", sorted_unique=True)
        if self.conflict_key is not None:
            nonempty(self.conflict_key, "conflict_key")
        verify_content_id(self.candidate_id, "wiki.runtime.retrieval-candidate.v1", self.to_mapping(), "candidate_id", "retrieval candidate_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "retrieval_candidate_version": self.retrieval_candidate_version,
            "candidate_id": self.candidate_id,
            "object_id": self.object_id,
            "revision_id": self.revision_id,
            "workspace_id": self.workspace_id,
            "generation_id": self.generation_id,
            "channel": self.channel,
            "score_micros": self.score_micros,
            "sensitivity": self.sensitivity,
            "lifecycle_status": self.lifecycle_status,
            "occurred_at": self.occurred_at,
            "payload_digest": self.payload_digest,
            "locator_refs": list(self.locator_refs),
            "conflict_key": self.conflict_key,
        }


@dataclass(frozen=True)
class AuthoritativeObjectState:
    workspace_id: str
    object_id: str
    generation_id: str
    revision_id: str
    lifecycle_status: str
    sensitivity: str


class RetrievalProjection(Protocol):
    def search(self, query: RetrievalQuery, channel: str) -> Sequence[RetrievalCandidate]: ...


class AuthoritativeStateReader(Protocol):
    def state_at(self, workspace_id: str, object_id: str, generation_id: str) -> AuthoritativeObjectState | None: ...


@dataclass(frozen=True)
class RetrievalResult:
    retrieval_result_version: str
    result_id: str
    query_id: str
    generation_id: str
    candidates: tuple[RetrievalCandidate, ...]
    omitted_candidate_ids: tuple[str, ...]
    degraded_channels: tuple[str, ...]
    stale_detected: bool

    @classmethod
    def create(
        cls,
        *,
        query_id: str,
        generation_id: str,
        candidates: Sequence[RetrievalCandidate],
        omitted_candidate_ids: Sequence[str],
        degraded_channels: Sequence[str],
        stale_detected: bool,
    ) -> "RetrievalResult":
        values = tuple(candidates)
        omitted = tuple(sorted(set(omitted_candidate_ids)))
        degraded = tuple(sorted(set(degraded_channels)))
        payload = {
            "retrieval_result_version": RETRIEVAL_RESULT_VERSION,
            "query_id": query_id,
            "generation_id": generation_id,
            "candidates": [value.to_mapping() for value in values],
            "omitted_candidate_ids": list(omitted),
            "degraded_channels": list(degraded),
            "stale_detected": stale_detected,
        }
        return cls(result_id=content_id("wiki.runtime.retrieval-result.v1", payload), candidates=values, omitted_candidate_ids=omitted, degraded_channels=degraded, **{k: v for k, v in payload.items() if k not in {"candidates", "omitted_candidate_ids", "degraded_channels"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.retrieval_result_version != RETRIEVAL_RESULT_VERSION:
            raise InvalidContractValue("unsupported retrieval result version")
        hex64(self.query_id, "query_id")
        nonempty(self.generation_id, "generation_id")
        string_tuple(self.omitted_candidate_ids, "omitted_candidate_ids", sorted_unique=True)
        string_tuple(self.degraded_channels, "degraded_channels", sorted_unique=True, codes=True)
        if not isinstance(self.stale_detected, bool):
            raise InvalidContractValue("stale_detected must be boolean")
        verify_content_id(self.result_id, "wiki.runtime.retrieval-result.v1", self.to_mapping(), "result_id", "retrieval result_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "retrieval_result_version": self.retrieval_result_version,
            "result_id": self.result_id,
            "query_id": self.query_id,
            "generation_id": self.generation_id,
            "candidates": [value.to_mapping() for value in self.candidates],
            "omitted_candidate_ids": list(self.omitted_candidate_ids),
            "degraded_channels": list(self.degraded_channels),
            "stale_detected": self.stale_detected,
        }


class RetrievalBroker:
    def __init__(self, projection: RetrievalProjection, state_reader: AuthoritativeStateReader) -> None:
        self.projection = projection
        self.state_reader = state_reader

    def retrieve(self, query: RetrievalQuery) -> RetrievalResult:
        channels = [
            RetrievalChannel.EXACT.value,
            RetrievalChannel.KEYWORD.value,
            RetrievalChannel.CHRONOLOGY.value,
            *query.optional_channels,
        ]
        raw: list[RetrievalCandidate] = []
        degraded: list[str] = []
        for channel in channels:
            try:
                raw.extend(self.projection.search(query, channel))
            except Exception:
                if channel in {RetrievalChannel.SEMANTIC.value, RetrievalChannel.RELATION.value}:
                    degraded.append(channel)
                    continue
                raise

        omitted: list[str] = []
        stale = False
        best: dict[str, RetrievalCandidate] = {}
        for candidate in raw:
            state = self.state_reader.state_at(query.workspace_id, candidate.object_id, query.generation_id)
            if candidate.workspace_id != query.workspace_id or state is None:
                omitted.append(candidate.candidate_id)
                continue
            if candidate.generation_id != query.generation_id:
                stale = True
            if state.generation_id != query.generation_id or state.revision_id != candidate.revision_id:
                stale = True
                omitted.append(candidate.candidate_id)
                continue
            if state.lifecycle_status not in {"active", "accepted"}:
                omitted.append(candidate.candidate_id)
                continue
            if SENSITIVITY_RANK[state.sensitivity] > SENSITIVITY_RANK[query.maximum_sensitivity]:
                omitted.append(candidate.candidate_id)
                continue
            normalized = RetrievalCandidate.create(
                object_id=candidate.object_id,
                revision_id=state.revision_id,
                workspace_id=query.workspace_id,
                generation_id=query.generation_id,
                channel=candidate.channel,
                score_micros=candidate.score_micros,
                sensitivity=state.sensitivity,
                lifecycle_status=state.lifecycle_status,
                occurred_at=candidate.occurred_at,
                payload_digest=candidate.payload_digest,
                locator_refs=candidate.locator_refs,
                conflict_key=candidate.conflict_key,
            )
            previous = best.get(normalized.object_id)
            key = (CHANNEL_ORDER[normalized.channel], -int(normalized.score_micros), normalized.candidate_id)
            if previous is None:
                best[normalized.object_id] = normalized
            else:
                previous_key = (CHANNEL_ORDER[previous.channel], -int(previous.score_micros), previous.candidate_id)
                if key < previous_key:
                    omitted.append(previous.candidate_id)
                    best[normalized.object_id] = normalized
                else:
                    omitted.append(normalized.candidate_id)

        ordered = sorted(
            best.values(),
            key=lambda value: (CHANNEL_ORDER[value.channel], -int(value.score_micros), value.object_id),
        )[: int(query.limit)]
        selected_ids = {value.candidate_id for value in ordered}
        omitted.extend(value.candidate_id for value in best.values() if value.candidate_id not in selected_ids)
        return RetrievalResult.create(
            query_id=query.query_id,
            generation_id=query.generation_id,
            candidates=ordered,
            omitted_candidate_ids=omitted,
            degraded_channels=degraded,
            stale_detected=stale,
        )


__all__ = [
    "RETRIEVAL_QUERY_VERSION", "RETRIEVAL_CANDIDATE_VERSION", "RETRIEVAL_RESULT_VERSION",
    "RetrievalChannel", "RetrievalQuery", "RetrievalCandidate", "AuthoritativeObjectState",
    "RetrievalProjection", "AuthoritativeStateReader", "RetrievalResult", "RetrievalBroker",
]
