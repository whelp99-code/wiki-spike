from __future__ import annotations

import os
from pathlib import Path

import pytest

from wiki_spike.workspace import Workspace
from wiki_spike.workspace_format import (
    WORKSPACE_FORMAT_FILENAME,
    ProfileSelection,
    WorkspaceFormatMarker,
    WorkspaceRootError,
    WorkspaceRootState,
    classify_workspace_root,
)


def _marker(root: Path) -> None:
    marker = WorkspaceFormatMarker.create(
        workspace_id="test-workspace",
        profile_selection=ProfileSelection.FIELD_AEAD,
        encrypted_lifecycle_enabled=True,
    )
    (root / WORKSPACE_FORMAT_FILENAME).write_bytes(marker.canonical_bytes())


def _entries(root: Path) -> dict[str, bytes | None]:
    return {
        entry.name: entry.read_bytes() if entry.is_file() and not entry.is_symlink() else None
        for entry in root.iterdir()
    }


def test_root_classifier_closed_truth_table(tmp_path: Path) -> None:
    absent = tmp_path / "absent"
    empty = tmp_path / "empty"; empty.mkdir()
    encrypted = tmp_path / "encrypted"; encrypted.mkdir(); _marker(encrypted)
    legacy = tmp_path / "legacy"; legacy.mkdir(); (legacy / "control.sqlite").write_bytes(b"old")
    unknown = tmp_path / "unknown"; unknown.mkdir(); (unknown / "notes.txt").write_text("x")
    mixed = tmp_path / "mixed"; mixed.mkdir(); (mixed / "control.sqlite").write_bytes(b"old"); (mixed / "notes.txt").write_text("x")

    assert classify_workspace_root(absent) is WorkspaceRootState.ABSENT
    assert classify_workspace_root(empty) is WorkspaceRootState.EMPTY
    assert classify_workspace_root(encrypted) is WorkspaceRootState.RECOGNIZED_ENCRYPTED
    assert classify_workspace_root(legacy) is WorkspaceRootState.LEGACY
    assert classify_workspace_root(unknown) is WorkspaceRootState.UNKNOWN
    assert classify_workspace_root(mixed) is WorkspaceRootState.MIXED


@pytest.mark.parametrize("name", ["legacy", "unknown", "mixed"])
def test_workspace_denial_has_no_filesystem_side_effects(tmp_path: Path, name: str) -> None:
    root = tmp_path / name
    root.mkdir()
    if name != "unknown":
        (root / "control.sqlite").write_bytes(b"legacy")
    if name != "legacy":
        (root / "foreign").write_bytes(b"foreign")
    before = _entries(root)

    with pytest.raises(WorkspaceRootError):
        Workspace(root)

    assert _entries(root) == before


def test_classifier_rejects_root_and_ancestor_symlinks_without_writing(tmp_path: Path) -> None:
    target = tmp_path / "target"; target.mkdir()
    link = tmp_path / "root-link"; link.symlink_to(target, target_is_directory=True)
    parent_target = tmp_path / "parent-target"; parent_target.mkdir()
    parent_link = tmp_path / "parent-link"; parent_link.symlink_to(parent_target, target_is_directory=True)

    assert classify_workspace_root(link) is WorkspaceRootState.UNKNOWN
    assert classify_workspace_root(parent_link / "new-root") is WorkspaceRootState.UNKNOWN
    with pytest.raises(WorkspaceRootError):
        Workspace(link)
    assert list(target.iterdir()) == []
    assert list(parent_target.iterdir()) == []
