"""AcceptedChangeSet construction and fail-closed storage publication adapter."""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Protocol, Sequence

from ..claims import CompiledClaim
from ..controlplane import CASConflict
from ..hashing import canonical_hash
from ..publish import PreparedPublication, PublishService
from .contracts import AcceptedChangeSet, CONTRACT_VERSION, CoreResult, canonical_bytes


class ChangeSetPublicationError(ValueError):
    error_code = "changeset_invalid"


class ChangeSetRootMismatch(ChangeSetPublicationError):
    error_code = "changeset_root_mismatch"


class ChangeSetIncomplete(ChangeSetPublicationError):
    error_code = "changeset_incomplete"


class ChangeSetStaleParent(ChangeSetPublicationError):
    error_code = "stale_generation"


class ChangeSetBindingMismatch(ChangeSetPublicationError):
    error_code = "changeset_binding_mismatch"


@dataclass(frozen=True)
class ResolvedChangeObject:
    object_ref: str
    revision_hash: str
    compiled_claim: CompiledClaim


class ChangeObjectResolver(Protocol):
    def resolve(self, workspace_id: str, object_ref: str) -> ResolvedChangeObject | None: ...


def compiled_claim_hash(claim: CompiledClaim) -> str:
    return canonical_hash(
        {
            "identity": {
                "claim_id": claim.identity.claim_id,
                "subject_id": claim.identity.subject_id,
                "predicate_id": claim.identity.predicate_id,
                "object": claim.identity.obj,
                "polarity": claim.identity.polarity,
                "scope": claim.identity.scope,
            },
            "assertion": {
                "assertion_id": claim.assertion.assertion_id,
                "claim_id": claim.assertion.claim_id,
                "source_id": claim.assertion.source_id,
                "evidence_ids": list(claim.assertion.evidence_ids),
                "modality": claim.assertion.modality,
            },
            "evidence": {
                "evidence_id": claim.evidence.evidence_id,
                "source_object_hash": claim.evidence.source_object_hash,
                "representation_hash": claim.evidence.representation_hash,
                "quote_hash": claim.evidence.quote_hash,
                "locators": list(claim.evidence.locators),
            },
        }
    )


def claim_object_ref(claim: CompiledClaim) -> str:
    revision_hash = compiled_claim_hash(claim)
    return f"claim_assertion:{claim.assertion.assertion_id}:{revision_hash}"


def compute_changes_root(
    workspace_id: str,
    parent_generation_id: str | None,
    command_ids: Sequence[str],
    objects: Sequence[ResolvedChangeObject],
) -> str:
    payload = {
        "workspace_id": workspace_id,
        "parent_generation_id": parent_generation_id,
        "command_ids": sorted(command_ids),
        "objects": [
            {"object_ref": item.object_ref, "revision_hash": item.revision_hash}
            for item in sorted(objects, key=lambda item: item.object_ref)
        ],
    }
    return sha256(canonical_bytes(payload)).hexdigest()


class ChangeSetBuilder:
    @staticmethod
    def build(
        *,
        workspace_id: str,
        parent_generation_id: str | None,
        command_ids: Sequence[str],
        objects: Sequence[ResolvedChangeObject],
    ) -> AcceptedChangeSet:
        commands = tuple(sorted(command_ids))
        refs = tuple(sorted(item.object_ref for item in objects))
        if not workspace_id or not commands or not refs:
            raise ChangeSetIncomplete("workspace, command_ids, and object_refs are required")
        if len(commands) != len(set(commands)) or len(refs) != len(set(refs)):
            raise ChangeSetIncomplete("duplicate command_id or object_ref")
        root = compute_changes_root(workspace_id, parent_generation_id, commands, objects)
        identity = {
            "contract_version": CONTRACT_VERSION,
            "workspace_id": workspace_id,
            "parent_generation_id": parent_generation_id,
            "command_ids": list(commands),
            "object_refs": list(refs),
            "changes_root": root,
        }
        changeset_id = sha256(canonical_bytes(identity)).hexdigest()
        return AcceptedChangeSet(
            CONTRACT_VERSION,
            changeset_id,
            workspace_id,
            parent_generation_id,
            commands,
            refs,
            root,
        )


class InMemoryChangeObjectStore:
    def __init__(self) -> None:
        self._objects: dict[tuple[str, str], ResolvedChangeObject] = {}

    def add(self, workspace_id: str, claim: CompiledClaim) -> ResolvedChangeObject:
        revision_hash = compiled_claim_hash(claim)
        item = ResolvedChangeObject(claim_object_ref(claim), revision_hash, claim)
        self._objects[(workspace_id, item.object_ref)] = item
        return item

    def resolve(self, workspace_id: str, object_ref: str) -> ResolvedChangeObject | None:
        return self._objects.get((workspace_id, object_ref))


@dataclass(frozen=True)
class PreparedChangeSetPublication:
    changeset: AcceptedChangeSet
    publication: PreparedPublication


class StoragePublicationAdapter:
    def __init__(self, publisher: PublishService, resolver: ChangeObjectResolver) -> None:
        self.publisher = publisher
        self.resolver = resolver

    def _resolve(self, changeset: AcceptedChangeSet) -> list[ResolvedChangeObject]:
        if changeset.contract_version != CONTRACT_VERSION:
            raise ChangeSetIncomplete("unsupported changeset contract version")
        if tuple(sorted(changeset.command_ids)) != changeset.command_ids:
            raise ChangeSetIncomplete("command_ids must be sorted")
        if tuple(sorted(changeset.object_refs)) != changeset.object_refs:
            raise ChangeSetIncomplete("object_refs must be sorted")
        if len(set(changeset.command_ids)) != len(changeset.command_ids):
            raise ChangeSetIncomplete("duplicate command_id")
        if len(set(changeset.object_refs)) != len(changeset.object_refs):
            raise ChangeSetIncomplete("duplicate object_ref")
        resolved: list[ResolvedChangeObject] = []
        for object_ref in changeset.object_refs:
            item = self.resolver.resolve(changeset.workspace_id, object_ref)
            if item is None:
                raise ChangeSetIncomplete(f"unresolved object_ref: {object_ref}")
            if item.object_ref != object_ref:
                raise ChangeSetBindingMismatch("resolver returned a different object_ref")
            actual_revision_hash = compiled_claim_hash(item.compiled_claim)
            if item.revision_hash != actual_revision_hash or claim_object_ref(item.compiled_claim) != object_ref:
                raise ChangeSetBindingMismatch("object revision hash does not match content")
            resolved.append(item)
        expected_root = compute_changes_root(
            changeset.workspace_id,
            changeset.parent_generation_id,
            changeset.command_ids,
            resolved,
        )
        if expected_root != changeset.changes_root:
            raise ChangeSetRootMismatch("changes_root does not match resolved revisions")
        expected_id = sha256(
            canonical_bytes(
                {
                    "contract_version": changeset.contract_version,
                    "workspace_id": changeset.workspace_id,
                    "parent_generation_id": changeset.parent_generation_id,
                    "command_ids": list(changeset.command_ids),
                    "object_refs": list(changeset.object_refs),
                    "changes_root": changeset.changes_root,
                }
            )
        ).hexdigest()
        if expected_id != changeset.changeset_id:
            raise ChangeSetBindingMismatch("changeset_id does not match canonical content")
        return resolved

    @staticmethod
    def _binding(changeset: AcceptedChangeSet) -> dict[str, object]:
        return {
            "contract_version": changeset.contract_version,
            "changeset_id": changeset.changeset_id,
            "workspace_id": changeset.workspace_id,
            "parent_generation_id": changeset.parent_generation_id or "",
            "command_ids": list(changeset.command_ids),
            "object_refs": list(changeset.object_refs),
            "changes_root": changeset.changes_root,
        }

    def _current_changeset_matches(self, changeset: AcceptedChangeSet) -> str | None:
        generation_id = self.publisher.cp.current_pointer()
        if generation_id is None:
            return None
        commit = self.publisher.cp.generation_commit(generation_id)
        if commit is None or not self.publisher.builder.verify_manifest(commit, generation_id):
            return None
        raw = self.publisher.builder.repo.cat_file(f"{commit}:manifest/{generation_id}.json")
        descriptor = json.loads(raw).get("descriptor", {})
        binding = descriptor.get("accepted_changeset")
        if isinstance(binding, dict) and binding.get("changeset_id") == changeset.changeset_id:
            return generation_id
        return None

    def prepare(self, changeset: AcceptedChangeSet) -> PreparedChangeSetPublication:
        current = self.publisher.cp.current_pointer()
        if current != changeset.parent_generation_id:
            raise ChangeSetStaleParent(
                f"expected parent {changeset.parent_generation_id!r}, found {current!r}"
            )
        resolved = self._resolve(changeset)
        source_hash = canonical_hash(
            {"changeset_id": changeset.changeset_id, "changes_root": changeset.changes_root}
        )
        publication = self.publisher.prepare(
            [item.compiled_claim for item in resolved],
            source_hash,
            expected_parent_generation_id=changeset.parent_generation_id,
            changeset_binding=self._binding(changeset),
        )
        if publication.candidate is not None:
            actual = publication.candidate.descriptor.get("accepted_changeset")
            if actual != self._binding(changeset):
                raise ChangeSetBindingMismatch("candidate is not bound to the accepted changeset")
        return PreparedChangeSetPublication(changeset, publication)

    def activate(self, prepared: PreparedChangeSetPublication) -> CoreResult:
        publication = prepared.publication
        if publication.candidate is not None:
            actual = publication.candidate.descriptor.get("accepted_changeset")
            if actual != self._binding(prepared.changeset):
                return self._result(
                    prepared.changeset,
                    "rejected",
                    self.publisher.cp.current_pointer(),
                    "changeset_binding_mismatch",
                    {},
                )
        try:
            result = self.publisher.activate_prepared(publication)
        except CASConflict:
            return self._result(
                prepared.changeset,
                "retry_later",
                self.publisher.cp.current_pointer(),
                "stale_generation",
                {},
            )
        return self._result(
            prepared.changeset,
            "ok",
            result.generation_id or self.publisher.cp.current_pointer(),
            None,
            {
                "changeset_id": prepared.changeset.changeset_id,
                "candidate_commit_oid": result.candidate_commit_oid,
                "release_commit_oid": result.release_commit_oid,
                "replayed": False,
                "noop": result.noop,
            },
        )

    def publish(self, changeset: AcceptedChangeSet) -> CoreResult:
        replay_generation = self._current_changeset_matches(changeset)
        if replay_generation is not None:
            self.publisher.repair_published_generation(replay_generation)
            return self._result(
                changeset,
                "ok",
                replay_generation,
                None,
                {"changeset_id": changeset.changeset_id, "replayed": True},
            )
        try:
            prepared = self.prepare(changeset)
        except ChangeSetPublicationError as exc:
            return self._result(
                changeset,
                "retry_later" if isinstance(exc, ChangeSetStaleParent) else "rejected",
                self.publisher.cp.current_pointer(),
                exc.error_code,
                {},
            )
        except CASConflict:
            return self._result(
                changeset,
                "retry_later",
                self.publisher.cp.current_pointer(),
                "stale_generation",
                {},
            )
        except Exception:
            return self._result(
                changeset,
                "retry_later",
                self.publisher.cp.current_pointer(),
                "storage_prepare_failed",
                {},
            )
        return self.activate(prepared)

    @staticmethod
    def _result(
        changeset: AcceptedChangeSet,
        status: str,
        generation_id: str | None,
        error_code: str | None,
        result: dict[str, object],
    ) -> CoreResult:
        return CoreResult(
            CONTRACT_VERSION,
            changeset.changeset_id,
            status,
            generation_id,
            result,  # type: ignore[arg-type]
            error_code,
        )
