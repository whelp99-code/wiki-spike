from __future__ import annotations

from dataclasses import replace

import pytest

from wiki_spike.memory_core import (
    CONTRACT_VERSION,
    CapabilityToken,
    DeterministicProjectionBuilder,
    InMemoryProjectionPointerStore,
    InMemoryProjectionSource,
    MemoryQueryGateway,
    MemoryRecord,
    ProjectionContractError,
    ProjectionCoordinator,
    ProjectionRecord,
    ProjectionSpec,
    ProjectionStagingManifest,
    QueryBatch,
    QueryEnvelope,
    Sensitivity,
)


def record(
    object_id: str,
    *,
    workspace_id: str = "ws-1",
    revision_id: str | None = None,
    occurred_at: str | None = None,
    lifecycle_status: str = "active",
):
    return ProjectionRecord(
        object_id=object_id,
        workspace_id=workspace_id,
        revision_id=revision_id or f"rev-{object_id}",
        kind="note",
        lifecycle_status=lifecycle_status,
        captured_at="2026-07-22T00:00:00Z",
        occurred_at=occurred_at,
        data={"title": f"Title {object_id}"},
    )


def specs(*optional: str):
    values = [
        ProjectionSpec("identity", "identity-v1", True),
        ProjectionSpec("chronology", "chronology-v1", True),
    ]
    values.extend(ProjectionSpec(name, f"{name}-v1", False) for name in optional)
    return values


def coordinator(*, builder=None, store=None, source=None, projections=None):
    return ProjectionCoordinator(
        source or InMemoryProjectionSource(),
        builder or DeterministicProjectionBuilder(),
        store or InMemoryProjectionPointerStore(),
        projections or specs("semantic", "graph"),
    )


class SelectiveFailureBuilder(DeterministicProjectionBuilder):
    def __init__(self, failures=()):
        self.failures = set(failures)

    def build(self, spec, workspace_id, source_generation_id, records):
        if spec.name in self.failures:
            raise RuntimeError(f"injected failure: {spec.name}")
        return super().build(spec, workspace_id, source_generation_id, records)


class RequiredConflictStore(InMemoryProjectionPointerStore):
    def publish_required(self, workspace_id, staging_manifest_digest, expected, artifacts):
        return False


class OptionalConflictStore(InMemoryProjectionPointerStore):
    def __init__(self, conflict_name):
        super().__init__()
        self.conflict_name = conflict_name

    def publish_optional(self, workspace_id, staging_manifest_digest, expected, artifact):
        if artifact.projection_name == self.conflict_name:
            return False
        return super().publish_optional(
            workspace_id, staging_manifest_digest, expected, artifact
        )


def test_minimum_profile_requires_exactly_identity_and_chronology():
    source = InMemoryProjectionSource()
    store = InMemoryProjectionPointerStore()
    builder = DeterministicProjectionBuilder()
    with pytest.raises(ProjectionContractError):
        ProjectionCoordinator(source, builder, store, [ProjectionSpec("identity", "v1", True)])
    with pytest.raises(ProjectionContractError):
        ProjectionCoordinator(
            source,
            builder,
            store,
            specs() + [ProjectionSpec("semantic", "v1", True)],
        )


def test_required_projection_failure_advances_nothing():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    store = InMemoryProjectionPointerStore()
    result = coordinator(
        source=source,
        store=store,
        builder=SelectiveFailureBuilder({"identity"}),
        projections=specs("semantic"),
    ).rebuild("ws-1", "g1")
    assert result.status == "retry_later"
    assert result.error_code == "required_projection_failed"
    assert result.failed_required == ("identity",)
    assert store.current("ws-1", "identity") is None
    assert store.current("ws-1", "chronology") is None
    assert store.current("ws-1", "semantic") is None


def test_optional_failure_advances_minimum_and_preserves_lkg():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    source.put("ws-1", "g2", [record("a", revision_id="rev-a-2"), record("b")])
    store = InMemoryProjectionPointerStore()
    builder = SelectiveFailureBuilder()
    core = coordinator(source=source, store=store, builder=builder, projections=specs("semantic"))
    first = core.rebuild("ws-1", "g1")
    assert first.status == "ok"
    assert store.current("ws-1", "semantic").generation_id == "g1"

    builder.failures.add("semantic")
    second = core.rebuild("ws-1", "g2")
    assert second.status == "ok"
    assert second.failed_optional == ("semantic",)
    assert store.current("ws-1", "identity").generation_id == "g2"
    assert store.current("ws-1", "chronology").generation_id == "g2"
    assert store.current("ws-1", "semantic").generation_id == "g1"
    assert store.last_known_good("ws-1", "semantic").generation_id == "g1"


def test_required_pointer_conflict_has_no_partial_advance():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    store = RequiredConflictStore()
    result = coordinator(source=source, store=store, projections=specs()).rebuild("ws-1", "g1")
    assert result.status == "retry_later"
    assert result.error_code == "required_projection_pointer_conflict"
    assert store.current("ws-1", "identity") is None
    assert store.current("ws-1", "chronology") is None


def test_pointer_store_required_cas_checks_all_before_update():
    builder = DeterministicProjectionBuilder()
    store = InMemoryProjectionPointerStore()
    records = [record("a")]
    g1_artifacts = tuple(builder.build(spec, "ws-1", "g1", records) for spec in specs())
    g1_manifest = ProjectionStagingManifest.create("ws-1", "g1", g1_artifacts)
    store.stage(g1_manifest)
    assert store.publish_required(
        "ws-1",
        g1_manifest.manifest_digest,
        {"identity": None, "chronology": None},
        g1_artifacts,
    )

    g2_artifacts = tuple(builder.build(spec, "ws-1", "g2", records) for spec in specs())
    g2_manifest = ProjectionStagingManifest.create("ws-1", "g2", g2_artifacts)
    store.stage(g2_manifest)
    wrong_expected = {
        "identity": store.current("ws-1", "identity"),
        "chronology": None,
    }
    assert not store.publish_required(
        "ws-1", g2_manifest.manifest_digest, wrong_expected, g2_artifacts
    )
    assert store.current("ws-1", "identity").generation_id == "g1"
    assert store.current("ws-1", "chronology").generation_id == "g1"


def test_optional_pointer_conflict_does_not_rollback_minimum():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    store = OptionalConflictStore("semantic")
    result = coordinator(source=source, store=store, projections=specs("semantic")).rebuild(
        "ws-1", "g1"
    )
    assert result.status == "ok"
    assert result.failed_optional == ("semantic",)
    assert store.current("ws-1", "identity").generation_id == "g1"
    assert store.current("ws-1", "chronology").generation_id == "g1"
    assert store.current("ws-1", "semantic") is None


def test_optional_pointers_are_independent():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    source.put("ws-1", "g2", [record("a"), record("b")])
    store = InMemoryProjectionPointerStore()
    builder = SelectiveFailureBuilder()
    core = coordinator(
        source=source,
        store=store,
        builder=builder,
        projections=specs("semantic", "graph"),
    )
    assert core.rebuild("ws-1", "g1").status == "ok"
    builder.failures.add("graph")
    result = core.rebuild("ws-1", "g2")
    assert result.status == "ok"
    assert store.current("ws-1", "semantic").generation_id == "g2"
    assert store.current("ws-1", "graph").generation_id == "g1"
    assert store.current("ws-1", "identity").generation_id == "g2"


def test_workspace_pointers_and_empty_artifacts_are_isolated():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [])
    source.put("ws-2", "g1", [])
    store = InMemoryProjectionPointerStore()
    core = coordinator(source=source, store=store, projections=specs())
    assert core.rebuild("ws-1", "g1").status == "ok"
    assert core.rebuild("ws-2", "g1").status == "ok"
    ws1 = store.current("ws-1", "identity")
    ws2 = store.current("ws-2", "identity")
    assert ws1.workspace_id == "ws-1"
    assert ws2.workspace_id == "ws-2"
    assert ws1.artifact_digest != ws2.artifact_digest


def test_rebuild_is_deterministic_across_input_and_spec_order():
    source_a = InMemoryProjectionSource()
    source_b = InMemoryProjectionSource()
    records = [
        record("b", occurred_at="2026-07-21T00:00:00Z"),
        record("a", occurred_at="2026-07-20T00:00:00Z"),
    ]
    source_a.put("ws-1", "g1", records)
    source_b.put("ws-1", "g1", list(reversed(records)))
    first = coordinator(source=source_a, projections=specs("semantic")).rebuild("ws-1", "g1")
    second = coordinator(
        source=source_b,
        projections=list(reversed(specs("semantic"))),
    ).rebuild("ws-1", "g1")
    assert first.status == second.status == "ok"
    assert first.staging_manifest_digest == second.staging_manifest_digest


def test_same_generation_rebuild_is_idempotent():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g1", [record("a")])
    store = InMemoryProjectionPointerStore()
    core = coordinator(source=source, store=store, projections=specs("semantic"))
    first = core.rebuild("ws-1", "g1")
    names = ("identity", "chronology", "semantic")
    pointers = {name: store.current("ws-1", name) for name in names}
    second = core.rebuild("ws-1", "g1")
    assert second.status == "ok"
    assert second.staging_manifest_digest == first.staging_manifest_digest
    assert {name: store.current("ws-1", name) for name in names} == pointers


def test_staging_manifest_rejects_unbound_artifact():
    builder = DeterministicProjectionBuilder()
    store = InMemoryProjectionPointerStore()
    semantic = builder.build(
        ProjectionSpec("semantic", "v1", False), "ws-1", "g1", [record("a")]
    )
    manifest = ProjectionStagingManifest.create("ws-1", "g1", [semantic])
    store.stage(manifest)
    tampered = replace(semantic, artifact_digest="0" * 64)
    with pytest.raises(ProjectionContractError):
        store.publish_optional("ws-1", manifest.manifest_digest, None, tampered)


def test_source_unavailable_returns_retry_later():
    result = coordinator(projections=specs()).rebuild("ws-1", "missing")
    assert result.status == "retry_later"
    assert result.error_code == "projection_source_unavailable"


def test_cross_workspace_source_is_rejected():
    class BadSource:
        def records_at(self, workspace_id, generation_id):
            return [record("a", workspace_id="ws-other")]

    result = coordinator(source=BadSource(), projections=specs()).rebuild("ws-1", "g1")
    assert result.status == "rejected"
    assert result.error_code == "projection_workspace_mismatch"


def test_raw_number_in_projection_data_is_rejected():
    with pytest.raises(ValueError):
        ProjectionRecord(
            "a",
            "ws-1",
            "rev-a",
            "note",
            "active",
            "2026-07-22T00:00:00Z",
            None,
            {"score": 1},
        )


def test_empty_generation_builds_deterministic_minimum_profile():
    source = InMemoryProjectionSource()
    source.put("ws-1", "g-empty", [])
    store = InMemoryProjectionPointerStore()
    result = coordinator(source=source, store=store, projections=specs()).rebuild(
        "ws-1", "g-empty"
    )
    assert result.status == "ok"
    assert store.current("ws-1", "identity").generation_id == "g-empty"
    assert store.current("ws-1", "chronology").generation_id == "g-empty"


def test_stale_projection_is_post_filtered_against_as_of_state():
    class Backend:
        def read(self, query, *, use_projection):
            assert use_projection is True
            return QueryBatch(
                "g1",
                (
                    MemoryRecord("a", "ws-1", Sensitivity.INTERNAL, "active", {"title": "A"}),
                    MemoryRecord("b", "ws-1", Sensitivity.INTERNAL, "active", {"title": "B"}),
                ),
            )

    class Resolver:
        def resolve(self, workspace_id, actor_id):
            return CapabilityToken(
                "tok-1",
                workspace_id,
                actor_id,
                frozenset({"memory.read"}),
                Sensitivity.PRIVATE,
                "2026-07-23T00:00:00Z",
            )

    class States:
        def lifecycle_status_at(self, workspace_id, object_id, generation_id):
            assert generation_id == "g2"
            return {"a": "active", "b": "retracted"}[object_id]

    query = QueryEnvelope.from_mapping(
        {
            "contract_version": CONTRACT_VERSION,
            "query_id": "q-1",
            "workspace_id": "ws-1",
            "actor_id": "user-1",
            "query_type": "memory.read",
            "as_of_generation_id": "g2",
            "consistency": "projection_ok",
            "parameters": {},
        }
    )
    result = MemoryQueryGateway(
        Backend(), Resolver(), States(), now="2026-07-22T00:00:00Z"
    ).query(query)
    assert result.status == "ok"
    assert result.result["stale"] is True
    assert [item["object_id"] for item in result.result["records"]] == ["a"]


def test_adversarial_report_contains_exactly_20_rounds():
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/adversarial/P3-06_ADVERSARIAL_VALIDATION_20R_KR.md").read_text("utf-8")
    rounds = [int(value) for value in re.findall(r"^## Round (\d{2})", text, re.M)]
    assert rounds == list(range(1, 21))
