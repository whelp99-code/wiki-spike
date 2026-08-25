"""Read-only Git source adapter and Stage-2 fixture connector."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from wiki_spike.applications.second_brain_source_sync_contracts import (
    SourceSyncAdapterErrorV1,
    SourceSyncAdapterFailureV1,
    SourceSyncTaskContextV1,
)

from . import FixtureConnectorReader

_OID: Final = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_ALLOWED: Final = frozenset({"rev-parse", "cat-file", "ls-tree", "show-ref", "diff-files", "diff-index", "status", "symbolic-ref"})
_DENIED_NAMES: Final = frozenset({".env", ".netrc", "cookies", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa", "known_hosts"})
_DENIED_SUFFIXES: Final = frozenset({".cer", ".crt", ".der", ".key", ".pem", ".p12", ".pfx"})
_MAX_BYTES: Final = 1_048_576
_MAX_FILES: Final = 5_000


class GitFixtureConnector(FixtureConnectorReader):
    source_profile = "Git"
    source_domain = "git"


@dataclass(frozen=True, slots=True)
class GitCommandError(Exception):
    argv: tuple[str, ...]
    detail: str

    def __str__(self) -> str:
        return self.detail


@dataclass(frozen=True, slots=True)
class GitBlobLocatorV1:
    commit_oid: str
    path: str
    blob_oid: str


@dataclass(frozen=True, slots=True)
class GitCommitMetadataV1:
    commit_oid: str
    tree_oid: str
    parents: tuple[str, ...]
    author_name: str
    author_email: str
    authored_at: str
    subject: str
    shallow: bool


@dataclass(frozen=True, slots=True)
class GitTrackedTextV1:
    locator: GitBlobLocatorV1
    payload: bytes
    tombstone: bool


@dataclass(frozen=True, slots=True)
class GitScanV1:
    commit: GitCommitMetadataV1
    items: tuple[GitTrackedTextV1, ...]


class GitReadOnlyExecutor:
    """Closed git verb runner that never updates refs, index, worktree, or remotes."""

    def run(self, root: Path, args: Sequence[str]) -> bytes:
        if not args or args[0] not in _ALLOWED:
            raise GitCommandError(tuple(args), "git command is not a closed read-only verb")
        env = {
            **os.environ,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_ASKPASS": "/usr/bin/true",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GCM_INTERACTIVE": "never",
        }
        flags = (
            "core.hooksPath=/dev/null",
            "core.untrackedCache=false",
            "core.fsmonitor=",
            "gc.auto=0",
            "credential.helper=",
            "protocol.file.allow=never",
        )
        completed = subprocess.run(
            ["git", "-C", str(root), *(part for flag in flags for part in ("-c", flag)), "--no-optional-locks", *args],
            capture_output=True,
            check=False,
            env=env,
            timeout=30,
        )
        if completed.returncode != 0:
            raise GitCommandError(tuple(args), completed.stderr.decode("utf-8", "replace"))
        return completed.stdout


class GitSourceAdapter:
    """Typed canonical Git reader for approved tracked text and selected commit metadata."""

    def __init__(
        self,
        root: Path,
        previous: tuple[GitBlobLocatorV1, ...] = (),
        executor: GitReadOnlyExecutor | None = None,
    ) -> None:
        self._root = root
        self._previous = previous
        self._executor = executor or GitReadOnlyExecutor()

    def read(self, context: SourceSyncTaskContextV1) -> GitScanV1 | SourceSyncAdapterFailureV1:
        if context.is_cancelled() or not self._root.is_absolute():
            return SourceSyncAdapterFailureV1(
                SourceSyncAdapterErrorV1.SYNC_TIMEOUT if context.is_cancelled() else SourceSyncAdapterErrorV1.DEPENDENCY_UNAVAILABLE
            )
        try:
            before = self._fingerprint()
            commit = self._commit()
            entries = self._ls_tree(commit.commit_oid)
            if len(entries) > _MAX_FILES:
                return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.LIMIT_EXCEEDED)
            items, present = self._text_items(commit.commit_oid, entries, context)
            if items is None:
                return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.SYNC_TIMEOUT)
            for locator in self._previous:
                if locator.path not in present:
                    items.append(GitTrackedTextV1(GitBlobLocatorV1(commit.commit_oid, locator.path, locator.blob_oid), b"", True))
            after = self._fingerprint()
        except subprocess.TimeoutExpired:
            return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.SYNC_TIMEOUT)
        except FileNotFoundError:
            return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.DEPENDENCY_UNAVAILABLE)
        except GitCommandError:
            try:
                self._git("rev-parse", "--is-inside-work-tree")
            except GitCommandError:
                return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.DEPENDENCY_UNAVAILABLE)
            return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.QUARANTINED)
        if after != before:
            return SourceSyncAdapterFailureV1(SourceSyncAdapterErrorV1.SOURCE_MUTATED)
        items.sort(key=lambda item: (item.tombstone, item.locator.path))
        return GitScanV1(commit, tuple(items))

    def _git(self, *args: str) -> bytes:
        return self._executor.run(self._root, args)

    def _fingerprint(self) -> tuple[bytes, bytes, bytes, bytes]:
        return (
            self._git("rev-parse", "HEAD"),
            self._git("show-ref", "--head"),
            self._git("diff-files", "--raw"),
            self._git("diff-index", "--raw", "HEAD"),
        )

    def _commit(self) -> GitCommitMetadataV1:
        commit_oid = self._git("rev-parse", "--verify", "HEAD").decode().strip()
        if _OID.fullmatch(commit_oid) is None:
            raise GitCommandError(("rev-parse",), "HEAD is not a git object id")
        shallow = self._git("rev-parse", "--is-shallow-repository").decode().strip() == "true"
        return _parse_commit(commit_oid, self._git("cat-file", "-p", commit_oid).decode("utf-8", "replace"), shallow)

    def _ls_tree(self, commit_oid: str) -> tuple[tuple[str, str], ...]:
        entries: list[tuple[str, str]] = []
        for record in self._git("ls-tree", "-r", "-z", commit_oid).split(b"\0"):
            if not record:
                continue
            meta, path_bytes = record.split(b"\t", 1)
            mode, kind, oid = meta.decode().split(" ", 2)
            if kind != "blob" or mode not in {"100644", "100755"}:
                continue
            path = path_bytes.decode("utf-8")
            if _OID.fullmatch(oid) is None or not _safe_path(path):
                raise GitCommandError(("ls-tree",), "tracked path or oid is invalid")
            entries.append((path, oid))
        return tuple(entries)

    def _text_items(
        self,
        commit_oid: str,
        entries: tuple[tuple[str, str], ...],
        context: SourceSyncTaskContextV1,
    ) -> tuple[list[GitTrackedTextV1] | None, set[str]]:
        items: list[GitTrackedTextV1] = []
        present: set[str] = set()
        for path, blob_oid in entries:
            if context.is_cancelled():
                return None, present
            if not _approved_text_path(path):
                continue
            payload = self._git("cat-file", "blob", blob_oid)
            if not payload or b"\x00" in payload or len(payload) > _MAX_BYTES:
                continue
            present.add(path)
            items.append(GitTrackedTextV1(GitBlobLocatorV1(commit_oid, path, blob_oid), payload, False))
        return items, present


def _safe_path(path: str) -> bool:
    return (
        bool(path)
        and not path.startswith("/")
        and "\\" not in path
        and not any(part in {"", ".", "..", ".git"} for part in path.split("/"))
    )


def _approved_text_path(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    suffix = name[name.rfind(".") :].lower() if "." in name else ""
    return name not in _DENIED_NAMES and suffix not in _DENIED_SUFFIXES


def _parse_commit(commit_oid: str, raw: str, shallow: bool) -> GitCommitMetadataV1:
    tree = ""
    parents: list[str] = []
    author_name = ""
    author_email = ""
    authored_at = ""
    subject = ""
    in_body = False
    for line in raw.splitlines():
        if in_body:
            if line:
                subject = line
                break
            continue
        if line == "":
            in_body = True
            continue
        if line.startswith("tree "):
            tree = line[5:]
        elif line.startswith("parent "):
            parents.append(line[7:])
        elif line.startswith("author "):
            author_name, author_email, authored_at = _parse_ident(line[7:])
    if _OID.fullmatch(tree) is None or not subject:
        raise GitCommandError(("cat-file",), "commit metadata is incomplete")
    return GitCommitMetadataV1(commit_oid, tree, tuple(parents), author_name, author_email, authored_at, subject, shallow)


def _parse_ident(value: str) -> tuple[str, str, str]:
    name, _, rest = value.partition(" <")
    email, _, tail = rest.partition("> ")
    unix, _, _tz = tail.partition(" ")
    try:
        stamped = datetime.fromtimestamp(int(unix), UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, OSError, OverflowError) as exc:
        raise GitCommandError(("cat-file",), "author timestamp is invalid") from exc
    return name, email, stamped


__all__ = [
    "GitBlobLocatorV1",
    "GitCommitMetadataV1",
    "GitCommandError",
    "GitFixtureConnector",
    "GitReadOnlyExecutor",
    "GitScanV1",
    "GitSourceAdapter",
    "GitTrackedTextV1",
]
