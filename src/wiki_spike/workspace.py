"""Workspace: end-to-end wiring of Phase 1a + 1b + SUB-07 (persistent).

Round-6 fixes:
- unique per-instance lease holder (UUID) so two processes cannot both publish (#6);
- knowledge accumulation via PublishService (new sources ADD, never wipe) (#1);
- zero-new-claim ingest is a NO-OP (no empty generation) (#2);
- re-ingesting an already-published source is a NO-OP (not an exception).
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .cas import ContentAddressedStore
from .claims import DeterministicMockExtractor
from .controlplane import ControlPlane, LeaseError
from .generation import GenerationBuilder
from .gitrepo import GitRepo
from .ingest import IngestService
from .mirror import RemoteMirror
from .publish import PublishResult, PublishService
from .search import SearchResponse, SearchService
from .signing import Keyring

KEY_ID = "k1"
LEASE_TTL = 30


@dataclass
class IngestPublishResult:
    source_id: str
    new_claims: int
    revokes: int
    publish: PublishResult
    quarantined: bool = False


class Workspace:
    def __init__(self, root: str | Path, holder: str | None = None, extractor=None) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        # Unique holder per process/instance (fixes the shared-"cli" lease bug).
        self.holder = holder or f"cli-{uuid.uuid4()}"

        gitdir = self.root / "repo.git"
        self.repo = GitRepo.init_bare(gitdir) if not (gitdir / "HEAD").exists() else GitRepo(gitdir)

        self.keyring = Keyring()
        self.keyring.load_or_create(KEY_ID, self.root / "signing.key")

        self.cp = ControlPlane(self.root / "control.sqlite")
        self.cas = ContentAddressedStore(self.root / "cas")
        # Pluggable extractor: default deterministic mock; a real LLMExtractor can be
        # injected once an exact model id is locked (P0).
        self.ingest = IngestService(self.cas, extractor or DeterministicMockExtractor())
        self.builder = GenerationBuilder(self.repo, self.keyring, KEY_ID)
        self.publisher = PublishService(self.builder, self.cp)
        self.search = SearchService(self.cp)
        self.mirror = RemoteMirror(self.repo, self.root / "remote.git")

    def ingest_and_publish(self, path: str | Path) -> IngestPublishResult:
        now = int(time.time())
        if self.cp.acquire_lease(self.holder, now, LEASE_TTL) is None:
            raise LeaseError(f"another publisher holds the lease: {self.cp.lease_holder(now)}")
        try:
            r = self.ingest.receive(path)
            c = self.ingest.compile(r.source_id)
            # #3.10: an untrusted raw source may NOT revoke existing knowledge. A source
            # proposing REVOKE is quarantined; nothing is published, pointer unchanged.
            if c.revokes:
                return IngestPublishResult(
                    source_id=r.source_id, new_claims=len(c.claims), revokes=len(c.revokes),
                    publish=PublishResult(None, None, None, 0, noop=True), quarantined=True,
                )
            res = self.publisher.publish(c.claims, source_snapshot_hash=r.content_hash)
            return IngestPublishResult(
                source_id=r.source_id, new_claims=len(c.claims), revokes=0, publish=res
            )
        finally:
            self.cp.release_lease(self.holder)

    def admin_revoke(self, claim_ids: list[str], reason: str = "admin") -> PublishResult:
        """Trusted-policy revoke path (the ONLY way to retract published claims)."""
        now = int(time.time())
        if self.cp.acquire_lease(self.holder, now, LEASE_TTL) is None:
            raise LeaseError(f"another publisher holds the lease: {self.cp.lease_holder(now)}")
        try:
            return self.publisher.publish([], source_snapshot_hash=f"admin:{reason}", revokes=claim_ids)
        finally:
            self.cp.release_lease(self.holder)

    def mirror_now(self) -> int:
        return self.mirror.process_outbox(self.cp)

    def query(self, term: str) -> SearchResponse:
        return self.search.query(term)

    def close(self) -> None:
        self.cp.close()
