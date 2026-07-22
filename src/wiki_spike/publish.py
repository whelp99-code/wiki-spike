"""Publish orchestrator with explicit prepare/activate boundaries.

The legacy ``publish`` method remains backward compatible. Phase 3 adapters use
``prepare`` and ``activate_prepared`` so a validated AcceptedChangeSet can be
bound to a signed generation before the publication pointer is moved.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes
from .controlplane import CASConflict, ControlPlane
from .generation import CandidateResult, GenerationBuilder
from .hashing import canonical_hash


@dataclass
class PublishResult:
    generation_id: str | None
    candidate_commit_oid: str | None
    release_commit_oid: str | None
    attempts: int
    noop: bool = False


@dataclass
class PreparedPublication:
    parent_generation_id: str | None
    candidate: CandidateResult | None
    release_commit_oid: str | None
    surviving: tuple[Any, ...]
    revoked_claim_ids: tuple[str, ...]
    attempts: int
    noop: bool = False


_ANY_PARENT = object()


class PublishService:
    def __init__(self, builder: GenerationBuilder, cp: ControlPlane) -> None:
        self.builder = builder
        self.cp = cp

    def _parent_claims(self, parent_gen: str | None) -> list:
        if parent_gen is None:
            return []
        commit = self.cp.generation_commit(parent_gen)
        if commit is None or not self.builder.verify_manifest(commit, parent_gen):
            raise RuntimeError(f"parent generation artifact failed verification: {parent_gen}")
        from .assembler import parse_snapshot

        return parse_snapshot(self.builder.repo.cat_file(f"{commit}:knowledge/snapshot.json"))

    def _build_release_commit(self, cand: CandidateResult, previous_release_oid: str | None) -> str:
        body = {
            "generation_id": cand.generation_id,
            "candidate_commit_oid": cand.commit_oid,
            "publication_profile": self.builder.profile,
            "required_read_models": [
                {"model_name": "wiki_files", "artifact_manifest_digest": cand.wiki_files_root},
                {"model_name": "citation_index", "artifact_manifest_digest": cand.citation_index_digest},
            ],
            "previous_release_commit_oid": previous_release_oid or "",
            "signer_key_id": self.builder.key_id,
        }
        signature = self.builder.keyring.sign_domain(
            self.builder.key_id, "wiki.release.v1", canonical_hash(body).encode()
        ).hex()
        release_manifest = dict(body, signature=signature)
        files = {f"release/{cand.generation_id}.json": canonical_bytes(release_manifest)}
        tree = self.builder.repo.write_tree_from_files(files)
        release_oid = self.builder.repo.commit_tree(
            tree, f"release {cand.generation_id}", parent=cand.commit_oid
        )
        ref = f"refs/wiki/release-objects/{cand.generation_id}"
        existing = self.builder.repo.read_ref(ref)
        if existing is None:
            self.builder.repo.create_ref_only(ref, release_oid)
        elif existing != release_oid:
            raise ValueError(f"release ref {ref} already points to {existing}, refusing to move")
        return release_oid

    def prepare(
        self,
        new_claims: list,
        source_snapshot_hash: str,
        *,
        revokes: list[str] | None = None,
        expected_parent_generation_id: str | None | object = _ANY_PARENT,
        changeset_binding: dict[str, Any] | None = None,
        attempts: int = 1,
    ) -> PreparedPublication:
        """Prepare immutable Git artifacts and DB registration without activation.

        A supplied expected parent is strict. Unlike the legacy ingestion path,
        an AcceptedChangeSet is never silently rebased onto a newer generation.
        """
        revokes_set = set(revokes or [])
        parent = self.cp.current_pointer()
        if expected_parent_generation_id is not _ANY_PARENT and parent != expected_parent_generation_id:
            raise CASConflict(
                f"expected parent {expected_parent_generation_id!r}, found {parent!r}"
            )

        for compiled in new_claims:
            self.cp.upsert_claim_and_assertion(compiled)

        parent_claims = self._parent_claims(parent)
        by_assertion = {item.assertion.assertion_id: item for item in parent_claims}
        for item in new_claims:
            by_assertion[item.assertion.assertion_id] = item
        surviving = [
            item for item in by_assertion.values() if item.identity.claim_id not in revokes_set
        ]
        surviving.sort(key=lambda item: item.assertion.assertion_id)
        surviving_ids = {item.assertion.assertion_id for item in surviving}
        parent_ids = {item.assertion.assertion_id for item in parent_claims}
        if surviving_ids == parent_ids:
            return PreparedPublication(
                parent_generation_id=parent,
                candidate=None,
                release_commit_oid=None,
                surviving=tuple(surviving),
                revoked_claim_ids=tuple(sorted(revokes_set)),
                attempts=attempts,
                noop=True,
            )

        from .models import ResolutionDecision, accepted_claim_set_root

        claim_ids = sorted({item.identity.claim_id for item in surviving})
        decisions = [
            ResolutionDecision(
                claim_id,
                "accepted",
                tuple(
                    sorted(
                        item.assertion.assertion_id
                        for item in surviving
                        if item.identity.claim_id == claim_id
                    )
                ),
                "spike-policy@0",
                "accept",
            )
            for claim_id in claim_ids
        ]
        root = accepted_claim_set_root(decisions)
        previous_release = self.cp.current_release_oid() if parent else None
        candidate = self.builder.build_candidate(
            surviving,
            parent,
            source_snapshot_hash,
            root,
            changeset_binding=changeset_binding,
        )
        release_oid = self._build_release_commit(candidate, previous_release)

        self.cp.register_generation(
            candidate.generation_id,
            parent,
            candidate.commit_oid,
            canonical_hash(candidate.manifest),
            manifest_json=json.dumps(candidate.manifest, sort_keys=True),
            release_commit_oid=release_oid,
        )
        self.cp.mark_read_model(candidate.generation_id, "wiki_files", candidate.wiki_files_root)
        self.cp.mark_read_model(
            candidate.generation_id, "citation_index", candidate.citation_index_digest
        )
        self.cp.set_read_models_ready(candidate.generation_id)
        return PreparedPublication(
            parent_generation_id=parent,
            candidate=candidate,
            release_commit_oid=release_oid,
            surviving=tuple(surviving),
            revoked_claim_ids=tuple(sorted(revokes_set)),
            attempts=attempts,
        )

    def activate_prepared(self, prepared: PreparedPublication) -> PublishResult:
        if prepared.noop or prepared.candidate is None or prepared.release_commit_oid is None:
            return PublishResult(None, None, None, prepared.attempts, noop=True)

        candidate = prepared.candidate
        current = self.cp.current_pointer()
        state = self.cp.generation_state(candidate.generation_id)
        if current == candidate.generation_id and state == "published":
            self._post_publish(
                candidate, list(prepared.surviving), set(prepared.revoked_claim_ids)
            )
            return PublishResult(
                candidate.generation_id,
                candidate.commit_oid,
                prepared.release_commit_oid,
                prepared.attempts,
            )

        self.cp.activate(
            candidate.generation_id,
            expected_parent=prepared.parent_generation_id,
            release_commit_oid=prepared.release_commit_oid,
        )
        self._post_publish(candidate, list(prepared.surviving), set(prepared.revoked_claim_ids))
        return PublishResult(
            candidate.generation_id,
            candidate.commit_oid,
            prepared.release_commit_oid,
            prepared.attempts,
        )

    def repair_published_generation(self, generation_id: str) -> None:
        """Idempotently rebuild mandatory DB materialization from a signed snapshot."""
        commit = self.cp.generation_commit(generation_id)
        if commit is None or not self.builder.verify_manifest(commit, generation_id):
            raise RuntimeError(f"generation artifact failed verification: {generation_id}")
        from .assembler import parse_snapshot

        claims = parse_snapshot(self.builder.repo.cat_file(f"{commit}:knowledge/snapshot.json"))
        candidate = type("RecoveredCandidate", (), {"generation_id": generation_id})()
        self._post_publish(candidate, claims, set())

    def publish(
        self,
        new_claims: list,
        source_snapshot_hash: str,
        accepted_claim_set_root: str = "",
        revokes: list[str] | None = None,
        max_retries: int = 3,
        *,
        expected_parent_generation_id: str | None | object = _ANY_PARENT,
        changeset_binding: dict[str, Any] | None = None,
    ) -> PublishResult:
        attempts = 0
        while True:
            attempts += 1
            try:
                prepared = self.prepare(
                    new_claims,
                    source_snapshot_hash,
                    revokes=revokes,
                    expected_parent_generation_id=expected_parent_generation_id,
                    changeset_binding=changeset_binding,
                    attempts=attempts,
                )
                return self.activate_prepared(prepared)
            except CASConflict:
                if expected_parent_generation_id is not _ANY_PARENT or attempts >= max_retries:
                    raise

    def _post_publish(self, cand: Any, surviving: list, revokes: set[str]) -> None:
        generation_id = cand.generation_id
        self.cp.add_generation_assertions(
            generation_id, [item.assertion.assertion_id for item in surviving]
        )
        for item in surviving:
            self.cp.record_resolution(generation_id, item.identity.claim_id, "accepted")
        for claim_id in revokes:
            self.cp.record_resolution(generation_id, claim_id, "retracted")
        seen: set[str] = set()
        entries: list[tuple[str, str, str, str]] = []
        for item in surviving:
            if item.identity.claim_id in seen:
                continue
            seen.add(item.identity.claim_id)
            entries.append(
                (
                    item.identity.claim_id,
                    item.identity.subject_id,
                    item.identity.predicate_id,
                    item.identity.obj,
                )
            )
        self.cp.build_search_index(generation_id, entries)
        self.cp.set_search_pointer(generation_id)
