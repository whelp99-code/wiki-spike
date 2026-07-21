"""Publish orchestrator — assertion-level accumulation (Round 7: #3.1,#3.3,#3.4,#3.6,#3.10,#3.11).

Membership unit is the ASSERTION, not the claim. The next generation's assertion set is
    parent_accepted_assertions  UNION  new_source_assertions  MINUS  authorized-revoked-claims
A second independent source for an existing claim adds a NEW assertion, so it is NOT a
no-op and its citation is preserved. Parent state is restored from the parent's SIGNED
knowledge snapshot, not from the mutable global tables.

Revokes here are AUTHORIZED (trusted-policy) claim_ids only. Untrusted source-proposed
REVOKE never reaches this method — the Workspace quarantines such sources (#3.10).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .canonical import canonical_bytes
from .controlplane import CASConflict, ControlPlane
from .generation import GenerationBuilder
from .hashing import canonical_hash


@dataclass
class PublishResult:
    generation_id: str | None
    candidate_commit_oid: str | None
    release_commit_oid: str | None
    attempts: int
    noop: bool = False


class PublishService:
    def __init__(self, builder: GenerationBuilder, cp: ControlPlane) -> None:
        self.builder = builder
        self.cp = cp

    # -- parent restoration from the SIGNED snapshot (#3.3) ---------------- #
    def _parent_claims(self, parent_gen: str | None) -> list:
        if parent_gen is None:
            return []
        commit = self.cp.generation_commit(parent_gen)
        if commit is None or not self.builder.verify_manifest(commit, parent_gen):
            raise RuntimeError(f"parent generation artifact failed verification: {parent_gen}")
        from .assembler import parse_snapshot
        return parse_snapshot(self.builder.repo.cat_file(f"{commit}:knowledge/snapshot.json"))

    def _build_release_commit(self, cand, previous_release_oid: str | None) -> str:
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
        # Release manifest is signed in a SEPARATE signing domain (#3.6).
        sig = self.builder.keyring.sign_domain(
            self.builder.key_id, "wiki.release.v1", canonical_hash(body).encode()
        ).hex()
        release_manifest = dict(body, signature=sig)
        files = {f"release/{cand.generation_id}.json": canonical_bytes(release_manifest)}
        tree = self.builder.repo.write_tree_from_files(files)
        release_oid = self.builder.repo.commit_tree(
            tree, f"release {cand.generation_id}", parent=cand.commit_oid
        )
        ref = f"refs/wiki/release-objects/{cand.generation_id}"
        if self.builder.repo.read_ref(ref) is None:
            self.builder.repo.create_ref_only(ref, release_oid)
        return release_oid

    def publish(
        self,
        new_claims: list,
        source_snapshot_hash: str,
        accepted_claim_set_root: str = "",
        revokes: list[str] | None = None,   # AUTHORIZED claim_ids only
        max_retries: int = 3,
    ) -> PublishResult:
        revokes = set(revokes or [])
        # Persist claim identities + assertions into the immutable dedup store.
        for c in new_claims:
            self.cp.upsert_claim_and_assertion(c)
        new_assertion_ids = {c.assertion.assertion_id for c in new_claims}

        attempts = 0
        while True:
            attempts += 1
            parent = self.cp.current_pointer()
            parent_claims = self._parent_claims(parent)
            parent_by_assertion = {c.assertion.assertion_id: c for c in parent_claims}
            for c in new_claims:
                parent_by_assertion[c.assertion.assertion_id] = c
            surviving = [c for c in parent_by_assertion.values()
                         if c.identity.claim_id not in revokes]
            surviving.sort(key=lambda c: c.assertion.assertion_id)
            surviving_assertions = {c.assertion.assertion_id for c in surviving}
            parent_assertions = {c.assertion.assertion_id for c in parent_claims}
            if surviving_assertions == parent_assertions:
                return PublishResult(None, None, None, attempts, noop=True)

            from .models import ResolutionDecision, accepted_claim_set_root as acsr

            claim_ids = sorted({c.identity.claim_id for c in surviving})
            decisions = [
                ResolutionDecision(cid, "accepted", tuple(sorted(
                    c.assertion.assertion_id for c in surviving if c.identity.claim_id == cid)),
                    "spike-policy@0", "accept")
                for cid in claim_ids
            ]
            root = acsr(decisions)

            prev_release = self.cp.current_release_oid() if parent else None
            cand = self.builder.build_candidate(surviving, parent, source_snapshot_hash, root)
            release_oid = self._build_release_commit(cand, prev_release)

            self.cp.register_generation(
                cand.generation_id, parent, cand.commit_oid, canonical_hash(cand.manifest),
                manifest_json=json.dumps(cand.manifest, sort_keys=True),
                release_commit_oid=release_oid,
            )
            self.cp.mark_read_model(cand.generation_id, "wiki_files", cand.wiki_files_root)
            self.cp.mark_read_model(cand.generation_id, "citation_index", cand.citation_index_digest)
            self.cp.set_read_models_ready(cand.generation_id)

            try:
                self.cp.activate(cand.generation_id, expected_parent=parent, release_commit_oid=release_oid)
                self._post_publish(cand, surviving, revokes)
                return PublishResult(cand.generation_id, cand.commit_oid, release_oid, attempts)
            except CASConflict:
                if attempts >= max_retries:
                    raise
                continue

    def _post_publish(self, cand, surviving, revokes) -> None:
        gen = cand.generation_id
        self.cp.add_generation_assertions(gen, [c.assertion.assertion_id for c in surviving])
        for c in surviving:
            self.cp.record_resolution(gen, c.identity.claim_id, "accepted")
        for rid in revokes:
            self.cp.record_resolution(gen, rid, "retracted")
        # search index deduped by claim
        seen = set()
        entries = []
        for c in surviving:
            if c.identity.claim_id in seen:
                continue
            seen.add(c.identity.claim_id)
            entries.append((c.identity.claim_id, c.identity.subject_id,
                            c.identity.predicate_id, c.identity.obj))
        self.cp.build_search_index(gen, entries)
        self.cp.set_search_pointer(gen)
