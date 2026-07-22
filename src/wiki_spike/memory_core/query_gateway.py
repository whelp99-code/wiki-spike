"""Generation-pinned query orchestration with fail-closed post-filtering."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .contracts import CONTRACT_VERSION, CoreResult, JsonValue, QueryEnvelope
from .policy import CapabilityToken, PolicyEngine, PolicyRequest, Sensitivity


@dataclass(frozen=True)
class MemoryRecord:
    object_id: str
    workspace_id: str
    sensitivity: Sensitivity
    lifecycle_status: str
    data: dict[str, JsonValue]


@dataclass(frozen=True)
class QueryBatch:
    generation_id: str
    records: tuple[MemoryRecord, ...]


class QueryBackend(Protocol):
    def read(self, query: QueryEnvelope, *, use_projection: bool) -> QueryBatch: ...


class QueryCapabilityResolver(Protocol):
    def resolve(self, workspace_id: str, actor_id: str) -> CapabilityToken | None: ...


class ObjectStateReader(Protocol):
    def lifecycle_status_at(self, workspace_id: str, object_id: str, generation_id: str) -> str | None: ...


class MemoryQueryGateway:
    def __init__(
        self,
        backend: QueryBackend,
        capability_resolver: QueryCapabilityResolver,
        state_reader: ObjectStateReader,
        *,
        policy: PolicyEngine | None = None,
        now: str,
    ) -> None:
        self.backend = backend
        self.capability_resolver = capability_resolver
        self.state_reader = state_reader
        self.policy = policy or PolicyEngine()
        self.now = now

    def query(self, query: QueryEnvelope) -> CoreResult:
        token = self.capability_resolver.resolve(query.workspace_id, query.actor_id)
        if token is None:
            return self._result(query.query_id, "rejected", query.as_of_generation_id, {}, "capability_missing")

        use_projection = query.consistency == "projection_ok"
        try:
            batch = self.backend.read(query, use_projection=use_projection)
        except Exception:
            return self._result(query.query_id, "retry_later", query.as_of_generation_id, {}, "query_backend_unavailable")

        stale = batch.generation_id != query.as_of_generation_id
        if stale and not use_projection:
            return self._result(
                query.query_id,
                "retry_later",
                query.as_of_generation_id,
                {},
                "authoritative_generation_mismatch",
            )

        visible: list[dict[str, JsonValue]] = []
        for record in batch.records:
            if record.workspace_id != query.workspace_id:
                continue
            current_state = self.state_reader.lifecycle_status_at(
                query.workspace_id,
                record.object_id,
                query.as_of_generation_id,
            )
            if current_state not in {"active", "accepted"}:
                continue
            decision = self.policy.authorize(
                token,
                PolicyRequest(
                    workspace_id=query.workspace_id,
                    actor_id=query.actor_id,
                    action=query.query_type,
                    now=self.now,
                    object_sensitivity=record.sensitivity,
                ),
            )
            if not decision.allowed:
                continue
            visible.append({
                "object_id": record.object_id,
                "sensitivity": record.sensitivity.value,
                "lifecycle_status": current_state,
                "data": record.data,
            })

        return self._result(
            query.query_id,
            "ok",
            query.as_of_generation_id,
            {
                "records": visible,
                "stale": stale,
                "source_generation_id": batch.generation_id,
                "as_of_generation_id": query.as_of_generation_id,
            },
            None,
        )

    @staticmethod
    def _result(
        request_id: str,
        status: str,
        generation_id: str | None,
        result: dict[str, JsonValue],
        error_code: str | None,
    ) -> CoreResult:
        return CoreResult(CONTRACT_VERSION, request_id, status, generation_id, result, error_code)
