"""IngestService walking skeleton (Phase 1a, v3.3 §5, §13).

Phase 1a scope ONLY: receive -> CAS store + manifest, then compile -> Claim IR.
NO publication, NO generation commit, NO read models. Those are Phase 1b (NO-GO).

All triggers (future watcher/API/MCP) will call this same service; the CLI is the
only adapter in Phase 1a.
"""
from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .cas import ContentAddressedStore
from .claims import ClaimExtractor, CompiledClaim
from .hashing import sha256_hex
from .models import SourceManifest


@dataclass
class ReceiveResult:
    source_id: str
    content_hash: str
    representation_hash: str
    status: str
    idempotent: bool


@dataclass
class CompileResult:
    source_id: str
    claims: list[CompiledClaim] = field(default_factory=list)
    revokes: list[str] = field(default_factory=list)
    status: str = "validated"


def _representation(text: str) -> tuple[str, bytes]:
    """Normalize source text to a canonical representation (NFC, LF) and hash it."""
    norm = unicodedata.normalize("NFC", text).replace("\r\n", "\n").replace("\r", "\n")
    rep_bytes = norm.encode("utf-8")
    return sha256_hex(rep_bytes), rep_bytes


class IngestService:
    def __init__(self, cas: ContentAddressedStore, extractor: ClaimExtractor) -> None:
        self.cas = cas
        self.extractor = extractor
        self._manifests: dict[str, SourceManifest] = {}
        self._representations: dict[str, str] = {}  # source_id -> representation_hash

    # -- receive ----------------------------------------------------------- #
    def receive(self, path: str | Path) -> ReceiveResult:
        raw = Path(path).read_bytes()
        # Idempotency in Phase 1a keys off the PERSISTENT CAS (no SQLite yet). If the
        # exact bytes already exist, this receive is a no-op re-ingest.
        already = self.cas.exists(sha256_hex(raw))
        content_hash = self.cas.put(raw)  # write-once
        source_id = content_hash  # spike: source_id == content_hash

        text = raw.decode("utf-8", errors="strict")
        rep_hash, rep_bytes = _representation(text)
        self.cas.put(rep_bytes)  # store representation blob too
        self._representations[source_id] = rep_hash

        manifest = self._manifests.get(source_id)
        if manifest is None:
            manifest = SourceManifest(source_id=source_id, content_hash=content_hash)
            manifest.transition("staged")
            self._manifests[source_id] = manifest

        return ReceiveResult(
            source_id=source_id,
            content_hash=content_hash,
            representation_hash=rep_hash,
            status=manifest.status,
            idempotent=already,
        )

    # -- compile ----------------------------------------------------------- #
    def compile(self, source_id: str) -> CompileResult:
        # No persistent control-plane in Phase 1a: reconstruct from the CAS content
        # blob. representation is a pure function of content, so compile is
        # deterministic across processes (source_id == content_hash).
        if not self.cas.exists(source_id):
            raise KeyError(f"unknown source_id: {source_id}")

        manifest = self._manifests.get(source_id)
        if manifest is None:
            manifest = SourceManifest(source_id=source_id, content_hash=source_id)
            manifest.transition("staged")  # existence in CAS implies it was received
            self._manifests[source_id] = manifest
        if manifest.status not in ("staged", "validated"):
            raise RuntimeError(f"source not compilable in state {manifest.status!r}")

        raw_text = self.cas.get(source_id).decode("utf-8")
        rep_hash, rep_bytes = _representation(raw_text)
        text = rep_bytes.decode("utf-8")  # offsets align with representation_hash
        result = self.extractor.extract(text, source_id, rep_hash)
        if manifest.status == "staged":
            manifest.transition("validated")
        return CompileResult(
            source_id=source_id, claims=result.claims, revokes=result.revokes, status=manifest.status
        )

    def manifest(self, source_id: str) -> SourceManifest:
        return self._manifests[source_id]
