"""Workspace-format marker and root admission guard.

Marker parsing and root classification are side-effect-free.  The explicitly
named ``prepare_workspace_root`` initializer creates only a strict marker
after admitting an absent or empty real directory; it never opens a legacy,
unknown, mixed, or symlinked root.
"""
from __future__ import annotations

import json
import os
import stat
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from wiki_spike.memory_core.contracts import canonical_bytes

WORKSPACE_FORMAT_SCHEMA = "wiki-spike-workspace-format-v1"
WORKSPACE_FORMAT_SCHEMA_VERSION = "1"
WORKSPACE_FORMAT_FILENAME = "workspace-format.json"


class ProfileSelection(str, Enum):
    """Pre-initialization, no-runtime-fallback storage profile choice.

    A: SQLCipher-profile (whole-database encryption).
    B: field-AEAD-profile (per-field envelope encryption).
    Exactly one profile is selected once, permanently, at workspace
    creation; there is no runtime fallback between A and B.
    """

    SQLCIPHER = "A"
    FIELD_AEAD = "B"


class WorkspaceFormatError(ValueError):
    """Raised when a workspace-format marker mapping is malformed."""


class WorkspaceRootError(WorkspaceFormatError):
    """Raised when a root is not safe for product initialization or opening."""


class WorkspaceRootState(str, Enum):
    """Closed, side-effect-free classification of a candidate workspace root."""

    ABSENT = "absent"
    EMPTY = "empty"
    RECOGNIZED_ENCRYPTED = "recognized-encrypted"
    LEGACY = "legacy"
    UNKNOWN = "unknown"
    MIXED = "mixed"


@dataclass(frozen=True)
class WorkspaceFormatMarker:
    schema: str
    schema_version: str
    workspace_id: str
    profile_selection: ProfileSelection
    encrypted_lifecycle_enabled: bool

    def to_mapping(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "workspace_id": self.workspace_id,
            "profile_selection": self.profile_selection.value,
            "encrypted_lifecycle_enabled": self.encrypted_lifecycle_enabled,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        profile_selection: ProfileSelection,
        encrypted_lifecycle_enabled: bool,
    ) -> "WorkspaceFormatMarker":
        return cls(
            schema=WORKSPACE_FORMAT_SCHEMA,
            schema_version=WORKSPACE_FORMAT_SCHEMA_VERSION,
            workspace_id=workspace_id,
            profile_selection=profile_selection,
            encrypted_lifecycle_enabled=encrypted_lifecycle_enabled,
        )


_REQUIRED_FIELDS = {
    "schema",
    "schema_version",
    "workspace_id",
    "profile_selection",
    "encrypted_lifecycle_enabled",
}


def parse_marker(data: Mapping[str, Any]) -> WorkspaceFormatMarker:
    """Strict, side-effect-free parse of a workspace-format marker mapping.

    Raises :class:`WorkspaceFormatError` on any unknown/missing field,
    unsupported schema/version, or invalid profile_selection.
    """
    if not isinstance(data, Mapping):
        raise WorkspaceFormatError("workspace-format marker must be an object")
    unknown = set(data) - _REQUIRED_FIELDS
    if unknown:
        raise WorkspaceFormatError(f"unknown workspace-format marker fields: {sorted(unknown)}")
    missing = _REQUIRED_FIELDS - set(data)
    if missing:
        raise WorkspaceFormatError(f"missing workspace-format marker fields: {sorted(missing)}")
    if data["schema"] != WORKSPACE_FORMAT_SCHEMA:
        raise WorkspaceFormatError(f"unsupported workspace-format schema: {data['schema']!r}")
    if data["schema_version"] != WORKSPACE_FORMAT_SCHEMA_VERSION:
        raise WorkspaceFormatError(f"unsupported workspace-format schema_version: {data['schema_version']!r}")
    workspace_id = data["workspace_id"]
    if not isinstance(workspace_id, str) or not workspace_id:
        raise WorkspaceFormatError("workspace_id must be a non-empty string")
    try:
        profile_selection = ProfileSelection(data["profile_selection"])
    except (TypeError, ValueError) as exc:
        raise WorkspaceFormatError(f"unsupported profile_selection: {data['profile_selection']!r}") from exc
    encrypted_lifecycle_enabled = data["encrypted_lifecycle_enabled"]
    if not isinstance(encrypted_lifecycle_enabled, bool):
        raise WorkspaceFormatError("encrypted_lifecycle_enabled must be a boolean")
    return WorkspaceFormatMarker(
        schema=data["schema"],
        schema_version=data["schema_version"],
        workspace_id=workspace_id,
        profile_selection=profile_selection,
        encrypted_lifecycle_enabled=encrypted_lifecycle_enabled,
    )


def assert_marker_matches(marker: WorkspaceFormatMarker, *, expected_profile: ProfileSelection) -> None:
    """Pure assertion: the marker's recorded profile must equal
    ``expected_profile`` exactly. No runtime profile fallback is permitted:
    a mismatch is always a hard error, never a silent coercion."""
    if marker.profile_selection is not expected_profile:
        raise WorkspaceFormatError(
            f"workspace-format profile mismatch: marker records {marker.profile_selection.value!r}, "
            f"caller expected {expected_profile.value!r}; no runtime profile fallback is permitted"
        )
_LEGACY_ENTRIES = frozenset(
    {"repo.git", "signing.key", "control.sqlite", "control.sqlite-shm", "control.sqlite-wal", "cas", "remote.git"}
)
_ENCRYPTED_ENTRIES = _LEGACY_ENTRIES | {WORKSPACE_FORMAT_FILENAME}


def classify_workspace_root(root: str | Path) -> WorkspaceRootState:
    """Classify ``root`` without creating, changing, or following symlinks.

    Only an absent root, an empty real directory, and a real directory with a
    strict encrypted-format marker and known workspace entries are admissible.
    All other observations are denied by :func:`prepare_workspace_root`.
    """

    path = Path(root)
    if _has_symlink_ancestor(path):
        return WorkspaceRootState.UNKNOWN
    try:
        root_stat = os.lstat(path)
    except FileNotFoundError:
        return WorkspaceRootState.ABSENT
    except OSError:
        return WorkspaceRootState.UNKNOWN
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        return WorkspaceRootState.UNKNOWN

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory_fd = os.open(path, flags)
    except OSError:
        return WorkspaceRootState.UNKNOWN
    try:
        names = set(os.listdir(directory_fd))
        if not names:
            return WorkspaceRootState.EMPTY
        has_marker = WORKSPACE_FORMAT_FILENAME in names
        legacy_names = names & _LEGACY_ENTRIES
        unknown_names = names - _ENCRYPTED_ENTRIES
        if has_marker:
            if unknown_names or not _marker_is_valid(directory_fd):
                return WorkspaceRootState.MIXED
            return WorkspaceRootState.RECOGNIZED_ENCRYPTED
        if legacy_names and unknown_names:
            return WorkspaceRootState.MIXED
        if legacy_names:
            return WorkspaceRootState.LEGACY
        return WorkspaceRootState.UNKNOWN
    except OSError:
        return WorkspaceRootState.UNKNOWN
    finally:
        os.close(directory_fd)


def _marker_is_valid(directory_fd: int) -> bool:
    """Read and validate the marker through an already verified directory fd."""

    try:
        marker_fd = os.open(
            WORKSPACE_FORMAT_FILENAME,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=directory_fd,
        )
    except OSError:
        return False
    try:
        marker_stat = os.fstat(marker_fd)
        if not stat.S_ISREG(marker_stat.st_mode):
            return False
        with os.fdopen(marker_fd, "rb", closefd=False) as marker_file:
            raw = marker_file.read()
        data = json.loads(raw.decode("utf-8"))
        if raw != canonical_bytes(data):
            return False
        marker = parse_marker(data)
        return marker.encrypted_lifecycle_enabled
    except (OSError, TypeError, UnicodeDecodeError, json.JSONDecodeError, WorkspaceFormatError):
        return False
    finally:
        os.close(marker_fd)
def _has_symlink_ancestor(path: Path) -> bool:
    """Reject a lexical path whose existing ancestors cross a symlink."""

    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            mode = os.lstat(current).st_mode
        except FileNotFoundError:
            return False
        except OSError:
            return True
        if stat.S_ISLNK(mode):
            return True
    return False




def prepare_workspace_root(root: str | Path) -> WorkspaceRootState:
    """Create a new encrypted workspace marker only after a safe classification.

    The initial observation is always made before ``mkdir`` or any other
    write.  A second observation after directory creation prevents a raced
    replacement from being opened as an empty workspace.
    """

    path = Path(root)
    state = classify_workspace_root(path)
    if state is WorkspaceRootState.ABSENT:
        try:
            path.mkdir(parents=True, exist_ok=False)
        except FileExistsError:
            pass
        state = classify_workspace_root(path)
    if state is WorkspaceRootState.EMPTY:
        marker = WorkspaceFormatMarker.create(
            workspace_id=str(uuid.uuid4()),
            profile_selection=ProfileSelection.FIELD_AEAD,
            encrypted_lifecycle_enabled=True,
        )
        try:
            directory_fd = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except OSError:
            state = WorkspaceRootState.UNKNOWN
        else:
            try:
                if os.listdir(directory_fd):
                    state = WorkspaceRootState.UNKNOWN
                else:
                    marker_fd = os.open(
                        WORKSPACE_FORMAT_FILENAME,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                        dir_fd=directory_fd,
                    )
                    try:
                        with os.fdopen(marker_fd, "wb", closefd=False) as marker_file:
                            marker_file.write(marker.canonical_bytes())
                    finally:
                        os.close(marker_fd)
                    state = classify_workspace_root(path)
            except OSError:
                state = WorkspaceRootState.UNKNOWN
            finally:
                os.close(directory_fd)
    if state is not WorkspaceRootState.RECOGNIZED_ENCRYPTED:
        raise WorkspaceRootError(f"workspace root denied: {state.value}")
    return state
