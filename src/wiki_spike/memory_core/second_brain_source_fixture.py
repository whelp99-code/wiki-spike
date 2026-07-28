"""Closed, fixture-only source-manifest verification for Stage 1.

This module validates metadata only.  It neither opens a source nor resolves a
credential; ``FixtureSourceSandbox`` is the sole local-file reader.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Any

from .contracts import canonical_bytes
from .errors import InvalidContractValue
from .second_brain_security_contracts import SourceFixtureManifestV1

SOURCE_FIXTURE_MANIFEST_VERSION = "second-brain-source-fixture-manifest-v1"
FIXTURE_PROFILE = "fixture-local-v1"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_REF = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")


class SourceFixtureVerificationError(InvalidContractValue):
    """A fixture manifest is malformed or does not bind its declared contents."""


@dataclass(frozen=True)
class SourceFixtureEntry:
    source_fixture_ref: str
    path: str
    sha256: str
    byte_count: int
    page_count: int


@dataclass(frozen=True)
class VerifiedSourceFixtureManifest:
    manifest_ref: str
    fixture_revision: str
    manifest_digest: str
    source_ref_id: str
    project_ref_id: str
    consent_epoch: str
    entries: tuple[SourceFixtureEntry, ...]
    fixture_profile: str = FIXTURE_PROFILE


class SourceFixtureVerifier:
    """Verify the local extension of the frozen S1 fixture-manifest wire.

    The S1 projection is parsed by ``SourceFixtureManifestV1`` first.  The
    extension adds only local-file identity, integrity, and consent binding;
    no connector, route, endpoint, credential, or environment setting exists.
    """

    _FIELDS = frozenset({
        "security_version", "manifest_ref", "fixture_revision", "source_fixture_refs",
        "manifest_digest", "fixture_profile", "source_ref_id", "project_ref_id",
        "consent_epoch", "entries",
    })
    _ENTRY_FIELDS = frozenset({"source_fixture_ref", "path", "sha256", "byte_count", "page_count"})

    def verify(self, manifest: Mapping[str, Any]) -> VerifiedSourceFixtureManifest:
        if not isinstance(manifest, Mapping) or set(manifest) != self._FIELDS:
            raise SourceFixtureVerificationError("source fixture manifest fields are invalid")
        projection = {name: manifest[name] for name in SourceFixtureManifestV1.FIELDS}
        try:
            security = SourceFixtureManifestV1.from_mapping(projection)
        except InvalidContractValue as exc:
            raise SourceFixtureVerificationError(str(exc)) from exc
        if manifest["fixture_profile"] != FIXTURE_PROFILE:
            raise SourceFixtureVerificationError("only fixture-local-v1 is permitted")
        source_ref_id = self._opaque(manifest["source_ref_id"], "source_ref_id")
        project_ref_id = self._opaque(manifest["project_ref_id"], "project_ref_id")
        consent_epoch = self._positive(manifest["consent_epoch"], "consent_epoch")
        entries_raw = manifest["entries"]
        if not isinstance(entries_raw, list) or not entries_raw:
            raise SourceFixtureVerificationError("entries must be a non-empty array")
        entries = tuple(self._entry(raw) for raw in entries_raw)
        refs = tuple(entry.source_fixture_ref for entry in entries)
        if refs != security.source_fixture_refs or len(set(refs)) != len(refs):
            raise SourceFixtureVerificationError("entries must exactly match sorted source_fixture_refs")
        digest_body = dict(manifest)
        del digest_body["manifest_digest"]
        actual = sha256(canonical_bytes(digest_body)).hexdigest()
        if actual != security.manifest_digest:
            raise SourceFixtureVerificationError("manifest_digest does not bind fixture manifest")
        return VerifiedSourceFixtureManifest(
            security.manifest_ref, security.fixture_revision, security.manifest_digest,
            source_ref_id, project_ref_id, consent_epoch, entries,
        )

    def _entry(self, raw: Any) -> SourceFixtureEntry:
        if not isinstance(raw, Mapping) or set(raw) != self._ENTRY_FIELDS:
            raise SourceFixtureVerificationError("fixture entry fields are invalid")
        ref = self._ref(raw["source_fixture_ref"], "source_fixture_ref")
        path = raw["path"]
        if not isinstance(path, str) or not path or not self._safe_relative_path(path):
            raise SourceFixtureVerificationError("fixture path must be a canonical relative local path")
        digest = raw["sha256"]
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise SourceFixtureVerificationError("fixture sha256 must be a lowercase SHA-256 digest")
        return SourceFixtureEntry(ref, path, digest, self._decimal(raw["byte_count"], "byte_count"), self._decimal(raw["page_count"], "page_count"))

    @staticmethod
    def _safe_relative_path(path: str) -> bool:
        if "\\" in path or ":" in path or "$" in path or "{" in path or "}" in path or path.startswith(("/", "~")) or "//" in path:
            return False
        parts = path.split("/")
        return all(part not in {"", ".", ".."} for part in parts)

    @staticmethod
    def _decimal(value: Any, field: str) -> int:
        if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
            raise SourceFixtureVerificationError(f"{field} must be a canonical decimal string")
        return int(value)

    @staticmethod
    def _positive(value: Any, field: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[1-9][0-9]*", value) is None:
            raise SourceFixtureVerificationError(f"{field} must be a canonical positive decimal string")
        return value

    @staticmethod
    def _opaque(value: Any, field: str) -> str:
        if not isinstance(value, str) or not value:
            raise SourceFixtureVerificationError(f"{field} must be a non-empty opaque identifier")
        return value

    @staticmethod
    def _ref(value: Any, field: str) -> str:
        if not isinstance(value, str) or _REF.fullmatch(value) is None:
            raise SourceFixtureVerificationError(f"{field} must be a canonical keyed digest reference")
        return value
