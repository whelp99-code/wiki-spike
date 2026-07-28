"""Local fixture-root reader; this is not a typed connector or an OS sandbox."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import os
from pathlib import Path
import stat
import time
from typing import Callable

from wiki_spike.memory_core.policy import Sensitivity
from wiki_spike.memory_core.second_brain_consent import (
    ConsentRetentionPolicy,
    RetentionPolicy,
    SourceConsentState,
)
from wiki_spike.memory_core.second_brain_source_fixture import (
    SourceFixtureEntry,
    VerifiedSourceFixtureManifest,
)
from wiki_spike.memory_core.second_brain_capture_ports import CaptureFilesystemPort


@dataclass(frozen=True)
class FixtureLimitPolicy:
    max_items: int
    max_pages: int
    max_bytes: int
    deadline_seconds: float
    chunk_bytes: int = 65536

    def __post_init__(self) -> None:
        if self.max_items < 1 or self.max_pages < 1 or self.max_bytes < 1:
            raise ValueError("fixture limits must be positive")
        if self.deadline_seconds <= 0 or self.chunk_bytes < 1:
            raise ValueError("fixture deadline and chunk size must be positive")

    def preflight(self, entries: tuple[SourceFixtureEntry, ...]) -> None:
        if len(entries) > self.max_items:
            raise FixtureLimitExceeded("item limit exceeded")
        if sum(item.page_count for item in entries) > self.max_pages:
            raise FixtureLimitExceeded("page limit exceeded")
        if sum(item.byte_count for item in entries) > self.max_bytes:
            raise FixtureLimitExceeded("byte limit exceeded")


class SourceSandboxDisposition(str, Enum):
    ACCEPTED = "accepted"
    QUARANTINED = "quarantined"


class FixtureSandboxError(ValueError):
    pass


class FixtureLimitExceeded(FixtureSandboxError):
    pass


class FixtureReadDeadlineExceeded(FixtureSandboxError):
    pass


@dataclass(frozen=True)
class FixtureSourceItem:
    source_fixture_ref: str
    content: bytes


@dataclass(frozen=True)
class FixtureSandboxResult:
    disposition: SourceSandboxDisposition
    checkpoint_advanced: bool
    items: tuple[FixtureSourceItem, ...]
    quarantine_reason: str | None

    @property
    def accepted(self) -> bool:
        return self.disposition is SourceSandboxDisposition.ACCEPTED


class FixtureSourceSandbox:
    """Read verified fixture files below one canonical local root only.

    No URL parser, connector, environment lookup, credential lookup, subprocess,
    or network API is used.  Any rejection produces a body-free quarantine result
    and never advances a checkpoint.
    """

    def __init__(self, fixture_root: str | Path, limits: FixtureLimitPolicy, *, clock: Callable[[], float] = time.monotonic) -> None:
        root = Path(fixture_root)
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise FixtureSandboxError("fixture root must be an existing non-symlink directory")
        self._root = root.resolve(strict=True)
        self._limits = limits
        self._clock = clock

    def read(
        self,
        manifest: VerifiedSourceFixtureManifest,
        *,
        consent: SourceConsentState | None,
        retention: RetentionPolicy | None,
        sensitivity: Sensitivity,
        now: str,
        consent_policy: ConsentRetentionPolicy | None = None,
    ) -> FixtureSandboxResult:
        if not isinstance(manifest, VerifiedSourceFixtureManifest):
            return self._quarantine("unverified_manifest")
        authorization = (consent_policy or ConsentRetentionPolicy()).authorize_capture(
            workspace_id=consent.workspace_id if consent is not None else "",
            source_ref_id=manifest.source_ref_id,
            project_ref_id=manifest.project_ref_id,
            consent=consent, retention=retention, sensitivity=sensitivity, now=now,
        )
        if not authorization.allowed or consent is None or consent.consent_epoch != manifest.consent_epoch:
            return self._quarantine("consent_denied")
        try:
            self._limits.preflight(manifest.entries)
            deadline = self._clock() + self._limits.deadline_seconds
            items: list[FixtureSourceItem] = []
            total_bytes = 0
            for entry in manifest.entries:
                self._check_deadline(deadline)
                content = self._read_entry(entry, deadline, total_bytes)
                total_bytes += len(content)
                items.append(FixtureSourceItem(entry.source_fixture_ref, content))
            return FixtureSandboxResult(SourceSandboxDisposition.ACCEPTED, False, tuple(items), None)
        except FixtureSandboxError as exc:
            return self._quarantine(str(exc))
        except OSError:
            return self._quarantine("fixture_read_failed")

    ingest = read

    def _read_entry(self, entry: SourceFixtureEntry, deadline: float, total_before: int) -> bytes:
        candidate = self._root / entry.path
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self._root)
        except (OSError, ValueError) as exc:
            raise FixtureSandboxError("fixture path escapes root") from exc
        if candidate.is_symlink() or not resolved.is_file():
            raise FixtureSandboxError("fixture must be a regular non-symlink file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(resolved, flags)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise FixtureSandboxError("fixture must be a regular file")
            data = bytearray()
            digest = sha256()
            while True:
                self._check_deadline(deadline)
                block = os.read(fd, self._limits.chunk_bytes)
                if not block:
                    break
                data.extend(block)
                digest.update(block)
                if len(data) > entry.byte_count or total_before + len(data) > self._limits.max_bytes:
                    raise FixtureLimitExceeded("byte limit exceeded during read")
            if len(data) != entry.byte_count or digest.hexdigest() != entry.sha256:
                raise FixtureSandboxError("fixture content does not match verified manifest")
            return bytes(data)
        finally:
            os.close(fd)

    def _check_deadline(self, deadline: float) -> None:
        if self._clock() > deadline:
            raise FixtureReadDeadlineExceeded("fixture read deadline exceeded")

    @staticmethod
    def _quarantine(reason: str) -> FixtureSandboxResult:
        return FixtureSandboxResult(SourceSandboxDisposition.QUARANTINED, False, (), reason)


class SandboxFixtureCaptureFilesystem(CaptureFilesystemPort):
    """Fixture-only filesystem port built from an accepted sandbox result."""

    def __init__(self, result: FixtureSandboxResult) -> None:
        if not result.accepted:
            raise FixtureSandboxError("quarantined fixture result cannot become a capture client")
        self._items = {item.source_fixture_ref: item.content for item in result.items}

    def read_fixture_ciphertext(self, fixture_ref: str) -> bytes:
        try:
            return self._items[fixture_ref]
        except KeyError as exc:
            raise FixtureSandboxError("unknown fixture reference") from exc
