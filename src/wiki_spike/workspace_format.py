"""Immutable workspace-format marker for the Encrypted Single-Memory Lifecycle.

This module is pure inspect/assert: it defines the marker shape (selected
storage profile A|B, schema version, encrypted-lifecycle enablement) and a
canonical (de)serializer built on the frozen Core canonicalizer. It
deliberately does NOT create directories, keys, a database, or CAS — atomic
workspace initialization is owned by a later Gate 2 slice. Calling any
function here must never have a filesystem side effect.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from wiki_spike.memory_core.contracts import canonical_bytes

WORKSPACE_FORMAT_SCHEMA = "wiki-workspace-format-marker-v1"
WORKSPACE_FORMAT_SCHEMA_VERSION = "1"


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
    except ValueError as exc:
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
