from __future__ import annotations

from wiki_spike.memory_core import (
    CONTRACT_VERSION,
    CapabilityToken,
    MemoryQueryGateway,
    MemoryRecord,
    QueryBatch,
    QueryEnvelope,
    Sensitivity,
)


class Resolver:
    def __init__(self, max_sensitivity=Sensitivity.PRIVATE, actions=frozenset({"memory.search"})):
        self.max_sensitivity = max_sensitivity
        self.actions = actions

    def resolve(self, workspace_id, actor_id):
        return CapabilityToken(
            token_id="tok-q",
            workspace_id=workspace_id,
            actor_id=actor_id,
            actions=self.actions,
            max_sensitivity=self.max_sensitivity,
            expires_at="2026-07-23T00:00:00Z",
        )


class Backend:
    def __init__(self, batch, *, fail=False):
        self.batch = batch
        self.fail = fail
        self.calls = []

    def read(self, query, *, use_projection):
        self.calls.append(use_projection)
        if self.fail:
            raise RuntimeError("down")
        return self.batch


class States:
    def __init__(self, mapping):
        self.mapping = mapping

    def lifecycle_status_at(self, workspace_id, object_id, generation_id):
        return self.mapping.get((workspace_id, object_id, generation_id))


def query(consistency="projection_ok", as_of="gen-2"):
    return QueryEnvelope.from_mapping({
        "contract_version": CONTRACT_VERSION,
        "query_id": "qry-1",
        "workspace_id": "ws-1",
        "actor_id": "user-1",
        "query_type": "memory.search",
        "as_of_generation_id": as_of,
        "consistency": consistency,
        "parameters": {"term": "alpha"},
    })


def record(object_id, sensitivity=Sensitivity.INTERNAL, workspace_id="ws-1"):
    return MemoryRecord(
        object_id=object_id,
        workspace_id=workspace_id,
        sensitivity=sensitivity,
        lifecycle_status="active",
        data={"title": object_id},
    )


def test_stale_projection_is_marked_and_post_filtered_against_as_of_state():
    backend = Backend(QueryBatch("gen-1", (record("live"), record("gone"))))
    states = States({
        ("ws-1", "live", "gen-2"): "active",
        ("ws-1", "gone", "gen-2"): "tombstoned",
    })
    result = MemoryQueryGateway(
        backend,
        Resolver(),
        states,
        now="2026-07-22T00:00:00Z",
    ).query(query())
    assert result.status == "ok"
    assert result.result["stale"] is True
    assert [item["object_id"] for item in result.result["records"]] == ["live"]
    assert result.result["source_generation_id"] == "gen-1"
    assert backend.calls == [True]


def test_authoritative_generation_mismatch_returns_retry_later():
    backend = Backend(QueryBatch("gen-1", (record("a"),)))
    states = States({("ws-1", "a", "gen-2"): "active"})
    result = MemoryQueryGateway(backend, Resolver(), states, now="2026-07-22T00:00:00Z").query(
        query(consistency="authoritative")
    )
    assert result.status == "retry_later"
    assert result.error_code == "authoritative_generation_mismatch"
    assert result.result == {}


def test_denied_objects_are_omitted_without_count_or_identifier_disclosure():
    batch = QueryBatch("gen-2", (
        record("visible", Sensitivity.INTERNAL),
        record("hidden", Sensitivity("secret")),
    ))
    states = States({
        ("ws-1", "visible", "gen-2"): "active",
        ("ws-1", "hidden", "gen-2"): "active",
    })
    result = MemoryQueryGateway(
        Backend(batch),
        Resolver(max_sensitivity=Sensitivity.INTERNAL),
        states,
        now="2026-07-22T00:00:00Z",
    ).query(query())
    serialized = result.canonical_bytes().decode("utf-8")
    assert [item["object_id"] for item in result.result["records"]] == ["visible"]
    assert "hidden" not in serialized
    assert "denied" not in serialized


def test_cross_workspace_record_is_silently_filtered():
    batch = QueryBatch("gen-2", (record("foreign", workspace_id="ws-2"),))
    states = States({("ws-2", "foreign", "gen-2"): "active"})
    result = MemoryQueryGateway(Backend(batch), Resolver(), states, now="2026-07-22T00:00:00Z").query(query())
    assert result.result["records"] == []


def test_retracted_and_missing_state_are_filtered():
    batch = QueryBatch("gen-2", (record("retracted"), record("missing")))
    states = States({("ws-1", "retracted", "gen-2"): "retracted"})
    result = MemoryQueryGateway(Backend(batch), Resolver(), states, now="2026-07-22T00:00:00Z").query(query())
    assert result.result["records"] == []


def test_backend_failure_returns_retry_later_without_data():
    result = MemoryQueryGateway(
        Backend(QueryBatch("gen-2", ()), fail=True),
        Resolver(),
        States({}),
        now="2026-07-22T00:00:00Z",
    ).query(query())
    assert result.status == "retry_later"
    assert result.error_code == "query_backend_unavailable"
    assert result.result == {}
