"""Deterministic projection coordination with independent, generation-pinned pointers.

This module is deliberately storage-independent.  It coordinates projection builders
through Protocols and keeps the minimum Core profile (identity + chronology) atomic,
while optional projections retain independent last-known-good pointers.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Mapping, Protocol, Sequence

from .contracts import JsonValue, canonical_bytes

MINIMUM_PROJECTIONS = frozenset({"identity", "chronology"})


class ProjectionContractError(ValueError):
    """Fail-closed validation error for projection contracts."""


@dataclass(frozen=True)
class ProjectionRecord:
    object_id: str
    workspace_id: str
    revision_id: str
    kind: str
    lifecycle_status: str
    captured_at: str
    occurred_at: str | None
    data: dict[str, JsonValue]

    def __post_init__(self) -> None:
        for name in (
            "object_id",
            "workspace_id",
            "revision_id",
            "kind",
            "lifecycle_status",
            "captured_at",
        ):
            if not isinstance(getattr(self, name), str) or not getattr(self, name):
                raise ProjectionContractError(f"{name} must be a non-empty string")
        if self.occurred_at is not None and (
            not isinstance(self.occurred_at, str) or not self.occurred_at
        ):
            raise ProjectionContractError("occurred_at must be null or a non-empty string")
        canonical_bytes({"data": self.data})


@dataclass(frozen=True)
class ProjectionSpec:
    name: str
    schema_version: str
    required: bool

    def __post_init__(self) -> None:
        if not self.name or not self.schema_version:
            raise ProjectionContractError("projection name and schema_version are required")


@dataclass(frozen=True)
class ProjectionArtifact:
    projection_name: str
    source_generation_id: str
    schema_version: str
    required: bool
    artifact_digest: str
    records_root: str
    record_count: str

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "projection_name": self.projection_name,
            "source_generation_id": self.source_generation_id,
            "schema_version": self.schema_version,
            "required": self.required,
            "artifact_digest": self.artifact_digest,
            "records_root": self.records_root,
            "record_count": self.record_count,
        }


@dataclass(frozen=True)
class ProjectionStagingManifest:
    schema_version: str
    workspace_id: str
    source_generation_id: str
    artifacts: tuple[ProjectionArtifact, ...]
    manifest_digest: str

    @classmethod
    def create(
        cls,
        workspace_id: str,
        source_generation_id: str,
        artifacts: Sequence[ProjectionArtifact],
    ) -> "ProjectionStagingManifest":
        ordered = tuple(sorted(artifacts, key=lambda item: item.projection_name))
        if not workspace_id or not source_generation_id or not ordered:
            raise ProjectionContractError("workspace, generation, and artifacts are required")
        if len({item.projection_name for item in ordered}) != len(ordered):
            raise ProjectionContractError("duplicate projection artifact")
        if any(item.source_generation_id != source_generation_id for item in ordered):
            raise ProjectionContractError("artifact generation mismatch")
        body = {
            "schema_version": "phase3-projection-staging-v1",
            "workspace_id": workspace_id,
            "source_generation_id": source_generation_id,
            "artifacts": [item.to_mapping() for item in ordered],
        }
        digest = sha256(canonical_bytes(body)).hexdigest()
        return cls(
            "phase3-projection-staging-v1",
            workspace_id,
            source_generation_id,
            ordered,
            digest,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "workspace_id": self.workspace_id,
            "source_generation_id": self.source_generation_id,
            "artifacts": [item.to_mapping() for item in self.artifacts],
            "manifest_digest": self.manifest_digest,
        }


@dataclass(frozen=True)
class ProjectionPointer:
    projection_name: str
    generation_id: str
    artifact_digest: str
    staging_manifest_digest: str


@dataclass(frozen=True)
class ProjectionRunResult:
    status: str
    source_generation_id: str
    staging_manifest_digest: str | None
    advanced: tuple[str, ...]
    failed_required: tuple[str, ...]
    failed_optional: tuple[str, ...]
    error_code: str | None = None


class ProjectionSource(Protocol):
    def records_at(self, workspace_id: str, generation_id: str) -> Sequence[ProjectionRecord]: ...


class ProjectionBuilder(Protocol):
    def build(
        self,
        spec: ProjectionSpec,
        source_generation_id: str,
        records: Sequence[ProjectionRecord],
    ) -> ProjectionArtifact: ...


class ProjectionPointerStore(Protocol):
    def current(self, projection_name: str) -> ProjectionPointer | None: ...

    def last_known_good(self, projection_name: str) -> ProjectionPointer | None: ...

    def stage(self, manifest: ProjectionStagingManifest) -> None: ...

    def publish_required(
        self,
        staging_manifest_digest: str,
        expected: Mapping[str, ProjectionPointer | None],
        artifacts: Sequence[ProjectionArtifact],
    ) -> bool: ...

    def publish_optional(
        self,
        staging_manifest_digest: str,
        expected: ProjectionPointer | None,
        artifact: ProjectionArtifact,
    ) -> bool: ...


class DeterministicProjectionBuilder:
    """Reference builder used to prove deterministic roots and pointer semantics."""

    @staticmethod
    def _identity(record: ProjectionRecord) -> dict[str, JsonValue]:
        return {
            "object_id": record.object_id,
            "workspace_id": record.workspace_id,
            "revision_id": record.revision_id,
            "kind": record.kind,
            "lifecycle_status": record.lifecycle_status,
        }

    @staticmethod
    def _chronology(record: ProjectionRecord) -> dict[str, JsonValue]:
        return {
            "object_id": record.object_id,
            "workspace_id": record.workspace_id,
            "revision_id": record.revision_id,
            "timeline_at": record.occurred_at or record.captured_at,
            "captured_at": record.captured_at,
            "lifecycle_status": record.lifecycle_status,
        }

    def build(
        self,
        spec: ProjectionSpec,
        source_generation_id: str,
        records: Sequence[ProjectionRecord],
    ) -> ProjectionArtifact:
        if not source_generation_id:
            raise ProjectionContractError("source_generation_id is required")
        if spec.name == "identity":
            projected = [self._identity(item) for item in records]
            projected.sort(key=lambda item: (str(item["object_id"]), str(item["revision_id"])))
        elif spec.name == "chronology":
            projected = [self._chronology(item) for item in records]
            projected.sort(
                key=lambda item: (
                    str(item["timeline_at"]),
                    str(item["object_id"]),
                    str(item["revision_id"]),
                )
            )
        else:
            projected = [
                {
                    "object_id": item.object_id,
                    "workspace_id": item.workspace_id,
                    "revision_id": item.revision_id,
                    "kind": item.kind,
                    "lifecycle_status": item.lifecycle_status,
                    "captured_at": item.captured_at,
                    "occurred_at": item.occurred_at,
                    "data": item.data,
                }
                for item in records
            ]
            projected.sort(key=lambda item: (str(item["object_id"]), str(item["revision_id"])))

        records_body = {"records": projected}
        records_root = sha256(canonical_bytes(records_body)).hexdigest()
        artifact_body = {
            "projection_name": spec.name,
            "source_generation_id": source_generation_id,
            "schema_version": spec.schema_version,
            "required": spec.required,
            "records_root": records_root,
            "record_count": str(len(projected)),
        }
        artifact_digest = sha256(canonical_bytes(artifact_body)).hexdigest()
        return ProjectionArtifact(
            spec.name,
            source_generation_id,
            spec.schema_version,
            spec.required,
            artifact_digest,
            records_root,
            str(len(projected)),
        )


class InMemoryProjectionSource:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], tuple[ProjectionRecord, ...]] = {}

    def put(
        self,
        workspace_id: str,
        generation_id: str,
        records: Sequence[ProjectionRecord],
    ) -> None:
        if any(item.workspace_id != workspace_id for item in records):
            raise ProjectionContractError("record workspace mismatch")
        self._records[(workspace_id, generation_id)] = tuple(records)

    def records_at(self, workspace_id: str, generation_id: str) -> Sequence[ProjectionRecord]:
        key = (workspace_id, generation_id)
        if key not in self._records:
            raise KeyError(f"source generation not available: {generation_id}")
        return self._records[key]


class InMemoryProjectionPointerStore:
    """Atomic minimum-profile CAS plus independent optional pointers."""

    def __init__(self) -> None:
        self._pointers: dict[str, ProjectionPointer] = {}
        self._lkg: dict[str, ProjectionPointer] = {}
        self._staged: dict[str, ProjectionStagingManifest] = {}
        self._lock = RLock()

    def current(self, projection_name: str) -> ProjectionPointer | None:
        with self._lock:
            return self._pointers.get(projection_name)

    def last_known_good(self, projection_name: str) -> ProjectionPointer | None:
        with self._lock:
            return self._lkg.get(projection_name)

    def stage(self, manifest: ProjectionStagingManifest) -> None:
        with self._lock:
            existing = self._staged.get(manifest.manifest_digest)
            if existing is not None and existing != manifest:
                raise ProjectionContractError("staging manifest digest collision")
            self._staged[manifest.manifest_digest] = manifest

    def _assert_staged(
        self,
        manifest_digest: str,
        artifacts: Sequence[ProjectionArtifact],
    ) -> ProjectionStagingManifest:
        manifest = self._staged.get(manifest_digest)
        if manifest is None:
            raise ProjectionContractError("staging manifest is missing")
        expected = {item.projection_name: item for item in manifest.artifacts}
        for artifact in artifacts:
            if expected.get(artifact.projection_name) != artifact:
                raise ProjectionContractError("artifact is not bound to staging manifest")
        return manifest

    @staticmethod
    def _pointer(manifest_digest: str, artifact: ProjectionArtifact) -> ProjectionPointer:
        return ProjectionPointer(
            artifact.projection_name,
            artifact.source_generation_id,
            artifact.artifact_digest,
            manifest_digest,
        )

    def publish_required(
        self,
        staging_manifest_digest: str,
        expected: Mapping[str, ProjectionPointer | None],
        artifacts: Sequence[ProjectionArtifact],
    ) -> bool:
        with self._lock:
            self._assert_staged(staging_manifest_digest, artifacts)
            names = {item.projection_name for item in artifacts}
            if names != MINIMUM_PROJECTIONS or any(not item.required for item in artifacts):
                raise ProjectionContractError("required publication must contain identity and chronology")
            if set(expected) != MINIMUM_PROJECTIONS:
                raise ProjectionContractError("expected pointer set does not match minimum profile")
            if any(self._pointers.get(name) != expected[name] for name in MINIMUM_PROJECTIONS):
                return False
            updates = {
                item.projection_name: self._pointer(staging_manifest_digest, item)
                for item in artifacts
            }
            self._pointers.update(updates)
            self._lkg.update(updates)
            return True

    def publish_optional(
        self,
        staging_manifest_digest: str,
        expected: ProjectionPointer | None,
        artifact: ProjectionArtifact,
    ) -> bool:
        with self._lock:
            self._assert_staged(staging_manifest_digest, (artifact,))
            if artifact.required or artifact.projection_name in MINIMUM_PROJECTIONS:
                raise ProjectionContractError("minimum projections use atomic required publication")
            if self._pointers.get(artifact.projection_name) != expected:
                return False
            pointer = self._pointer(staging_manifest_digest, artifact)
            self._pointers[artifact.projection_name] = pointer
            self._lkg[artifact.projection_name] = pointer
            return True


class ProjectionCoordinator:
    def __init__(
        self,
        source: ProjectionSource,
        builder: ProjectionBuilder,
        pointers: ProjectionPointerStore,
        specs: Sequence[ProjectionSpec],
    ) -> None:
        ordered = tuple(sorted(specs, key=lambda item: item.name))
        if not ordered or len({item.name for item in ordered}) != len(ordered):
            raise ProjectionContractError("projection specs must be unique and non-empty")
        required_names = {item.name for item in ordered if item.required}
        if required_names != MINIMUM_PROJECTIONS:
            raise ProjectionContractError("identity and chronology are the exact minimum profile")
        self.source = source
        self.builder = builder
        self.pointers = pointers
        self.specs = ordered

    def rebuild(self, workspace_id: str, source_generation_id: str) -> ProjectionRunResult:
        try:
            records = tuple(self.source.records_at(workspace_id, source_generation_id))
        except Exception:
            return ProjectionRunResult(
                "retry_later",
                source_generation_id,
                None,
                (),
                tuple(sorted(MINIMUM_PROJECTIONS)),
                (),
                "projection_source_unavailable",
            )
        if any(item.workspace_id != workspace_id for item in records):
            return ProjectionRunResult(
                "rejected",
                source_generation_id,
                None,
                (),
                tuple(sorted(MINIMUM_PROJECTIONS)),
                (),
                "projection_workspace_mismatch",
            )

        artifacts: dict[str, ProjectionArtifact] = {}
        failed_required: list[str] = []
        failed_optional: list[str] = []
        for spec in self.specs:
            try:
                artifacts[spec.name] = self.builder.build(spec, source_generation_id, records)
            except Exception:
                (failed_required if spec.required else failed_optional).append(spec.name)
        if failed_required:
            return ProjectionRunResult(
                "retry_later",
                source_generation_id,
                None,
                (),
                tuple(sorted(failed_required)),
                tuple(sorted(failed_optional)),
                "required_projection_failed",
            )

        manifest = ProjectionStagingManifest.create(
            workspace_id,
            source_generation_id,
            tuple(artifacts.values()),
        )
        try:
            self.pointers.stage(manifest)
        except Exception:
            return ProjectionRunResult(
                "retry_later",
                source_generation_id,
                None,
                (),
                (),
                tuple(sorted(failed_optional)),
                "projection_staging_failed",
            )

        required = tuple(artifacts[name] for name in sorted(MINIMUM_PROJECTIONS))
        expected_required = {name: self.pointers.current(name) for name in MINIMUM_PROJECTIONS}
        try:
            required_published = self.pointers.publish_required(
                manifest.manifest_digest,
                expected_required,
                required,
            )
        except Exception:
            required_published = False
        if not required_published:
            return ProjectionRunResult(
                "retry_later",
                source_generation_id,
                manifest.manifest_digest,
                (),
                tuple(sorted(MINIMUM_PROJECTIONS)),
                tuple(sorted(failed_optional)),
                "required_projection_pointer_conflict",
            )

        advanced = list(sorted(MINIMUM_PROJECTIONS))
        for spec in self.specs:
            if spec.required or spec.name not in artifacts:
                continue
            expected = self.pointers.current(spec.name)
            try:
                published = self.pointers.publish_optional(
                    manifest.manifest_digest,
                    expected,
                    artifacts[spec.name],
                )
            except Exception:
                published = False
            if published:
                advanced.append(spec.name)
            else:
                failed_optional.append(spec.name)

        return ProjectionRunResult(
            "ok",
            source_generation_id,
            manifest.manifest_digest,
            tuple(sorted(advanced)),
            (),
            tuple(sorted(set(failed_optional))),
            None,
        )
