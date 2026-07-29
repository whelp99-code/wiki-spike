"""Workspace-format marker parsing and conservative root classification.

A format marker records an intended encrypted-lifecycle format; it is not proof
that the legacy workspace implementation is encrypted.  This module therefore
never admits a marked root to the legacy ``Workspace`` or creates a V2 marker.
"""
from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from wiki_spike.memory_core.contracts import canonical_bytes

WORKSPACE_FORMAT_SCHEMA = "wiki-spike-workspace-format-v1"
WORKSPACE_FORMAT_SCHEMA_VERSION = "1"
WORKSPACE_FORMAT_FILENAME = "workspace-format.json"


class ProfileSelection(str, Enum):
    """Storage profile selected by an encrypted-lifecycle implementation."""

    SQLCIPHER = "A"
    FIELD_AEAD = "B"


class WorkspaceFormatError(ValueError):
    """Raised when a workspace-format marker mapping is malformed."""


class WorkspaceRootError(WorkspaceFormatError):
    """Raised when a root is unsafe or unsupported for the requested runtime."""


class WorkspaceRootState(str, Enum):
    ABSENT = "absent"
    EMPTY = "empty"
    MARKED_UNSUPPORTED = "marked-unsupported"
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
    "schema", "schema_version", "workspace_id", "profile_selection", "encrypted_lifecycle_enabled"
}
_LEGACY_CHILD_TYPES = {
    "repo.git": stat.S_IFDIR,
    "signing.key": stat.S_IFREG,
    "control.sqlite": stat.S_IFREG,
    "control.sqlite-shm": stat.S_IFREG,
    "control.sqlite-wal": stat.S_IFREG,
    "cas": stat.S_IFDIR,
    "remote.git": stat.S_IFDIR,
}
_LEGACY_ENTRIES = frozenset(_LEGACY_CHILD_TYPES)


def parse_marker(data: Mapping[str, Any]) -> WorkspaceFormatMarker:
    """Strict, side-effect-free parsing of a workspace-format marker."""
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
        schema=data["schema"], schema_version=data["schema_version"], workspace_id=workspace_id,
        profile_selection=profile_selection, encrypted_lifecycle_enabled=encrypted_lifecycle_enabled,
    )


def assert_marker_matches(marker: WorkspaceFormatMarker, *, expected_profile: ProfileSelection) -> None:
    """Require an encrypted implementation to select the recorded profile exactly."""
    if marker.profile_selection is not expected_profile:
        raise WorkspaceFormatError(
            f"workspace-format profile mismatch: marker records {marker.profile_selection.value!r}, "
            f"caller expected {expected_profile.value!r}; no runtime profile fallback is permitted"
        )
    if not marker.encrypted_lifecycle_enabled:
        raise WorkspaceFormatError("workspace-format encrypted lifecycle is disabled")


def classify_workspace_root(root: str | Path) -> WorkspaceRootState:
    """Classify a root without following links or changing the filesystem."""
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
        if has_marker:
            # A marker cannot establish encryption/signature authority for this runtime.
            return WorkspaceRootState.MIXED if legacy_names or len(names) > 1 else WorkspaceRootState.MARKED_UNSUPPORTED
        if legacy_names and len(names) != len(legacy_names):
            return WorkspaceRootState.MIXED
        return WorkspaceRootState.LEGACY if legacy_names else WorkspaceRootState.UNKNOWN
    except OSError:
        return WorkspaceRootState.UNKNOWN
    finally:
        os.close(directory_fd)


def _has_symlink_ancestor(path: Path) -> bool:
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


@dataclass(frozen=True)
class V2WorkspaceRoot:
    """Read-only admission result for the authenticated encrypted product.

    A V2 marker is necessary but not sufficient authority.  Product
    composition separately requires a currently resolved security authority.
    This class intentionally never creates roots or child storage.
    """

    path: Path
    marker: WorkspaceFormatMarker

    @classmethod
    def inspect(cls, root: str | Path) -> "V2WorkspaceRoot":
        path = Path(root)
        state = classify_workspace_root(path)
        if state is not WorkspaceRootState.MARKED_UNSUPPORTED:
            raise WorkspaceRootError(f"workspace root denied: {state.value}")
        marker_path = path / WORKSPACE_FORMAT_FILENAME
        try:
            marker_stat = os.lstat(marker_path)
            if stat.S_ISLNK(marker_stat.st_mode) or not stat.S_ISREG(marker_stat.st_mode):
                raise WorkspaceRootError("workspace root denied: invalid marker")
            with marker_path.open(encoding="utf-8") as marker_file:
                marker = parse_marker(json.load(marker_file))
        except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
            if isinstance(exc, WorkspaceRootError):
                raise
            raise WorkspaceRootError("workspace root denied: invalid marker") from exc
        if not marker.encrypted_lifecycle_enabled:
            raise WorkspaceRootError("workspace root denied: encrypted lifecycle disabled")
        return cls(path=path, marker=marker)

@dataclass(frozen=True)
class LegacyWorkspaceRoot:
    """Admission result for the plaintext legacy runtime.

    This is deliberately not descriptor-pinned: legacy storage APIs consume
    paths.  ``assert_current`` detects replacement before each path is handed
    to such an API, but cannot make a path-based backend race-free.
    """

    path: Path
    device: int
    inode: int

    @classmethod
    def open(cls, root: str | Path) -> "LegacyWorkspaceRoot":
        path = Path(root)
        state = classify_workspace_root(path)
        if state is WorkspaceRootState.ABSENT:
            try:
                path.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                pass
            state = classify_workspace_root(path)
        if state not in (WorkspaceRootState.EMPTY, WorkspaceRootState.LEGACY):
            raise WorkspaceRootError(f"workspace root denied: {state.value}")
        root_stat = os.lstat(path)
        if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
            raise WorkspaceRootError("workspace root denied: replaced")
        _assert_existing_legacy_children(path)
        return cls(path, root_stat.st_dev, root_stat.st_ino)

    def assert_current(self) -> None:
        try:
            root_stat = os.lstat(self.path)
        except OSError as exc:
            raise WorkspaceRootError("workspace root denied: replaced") from exc
        if (
            not stat.S_ISDIR(root_stat.st_mode)
            or stat.S_ISLNK(root_stat.st_mode)
            or (root_stat.st_dev, root_stat.st_ino) != (self.device, self.inode)
            or classify_workspace_root(self.path) not in (WorkspaceRootState.EMPTY, WorkspaceRootState.LEGACY)
        ):
            raise WorkspaceRootError("workspace root denied: replaced")
        _assert_existing_legacy_children(self.path)

    def child(self, name: str) -> Path:
        expected_type = _LEGACY_CHILD_TYPES.get(name)
        if expected_type is None:
            raise WorkspaceRootError(f"workspace child denied: {name}")
        self.assert_current()
        _assert_legacy_child_type(self.path, name, expected_type)
        return self.path / name


def _assert_existing_legacy_children(root: Path) -> None:
    for name, expected_type in _LEGACY_CHILD_TYPES.items():
        _assert_legacy_child_type(root, name, expected_type)


def _assert_legacy_child_type(root: Path, name: str, expected_type: int) -> None:
    """Allow an absent child, but deny links and every unexpected existing type."""
    try:
        child_stat = os.lstat(root / name)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise WorkspaceRootError(f"workspace child denied: {name}") from exc
    if stat.S_ISLNK(child_stat.st_mode) or stat.S_IFMT(child_stat.st_mode) != expected_type:
        raise WorkspaceRootError(f"workspace child denied: {name}")


def prepare_workspace_root(root: str | Path, **_unsupported: object) -> WorkspaceRootState:
    """Fail closed: this repository has no encrypted V2 initializer.

    Callers requiring V2 must use an implementation that establishes trusted
    keys, authoritative scope inventory, and aggregate signatures.
    """
    state = classify_workspace_root(root)
    raise WorkspaceRootError(f"encrypted V2 workspace unavailable: {state.value}")
