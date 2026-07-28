from __future__ import annotations

import os
from pathlib import Path

import pytest

from wiki_spike.workspace import Workspace
from wiki_spike.workspace_format import (
    WORKSPACE_FORMAT_FILENAME,
    LegacyWorkspaceRoot,
    ProfileSelection,
    WorkspaceFormatMarker,
    WorkspaceRootError,
    WorkspaceRootState,
    classify_workspace_root,
    prepare_workspace_root,
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


def test_root_classifier_does_not_treat_marker_as_encrypted_storage(tmp_path: Path) -> None:
    absent = tmp_path / "absent"
    empty = tmp_path / "empty"; empty.mkdir()
    marked = tmp_path / "marked"; marked.mkdir(); _marker(marked)
    legacy = tmp_path / "legacy"; legacy.mkdir(); (legacy / "control.sqlite").write_bytes(b"old")
    mixed = tmp_path / "mixed"; mixed.mkdir(); _marker(mixed); (mixed / "control.sqlite").write_bytes(b"old")

    assert classify_workspace_root(absent) is WorkspaceRootState.ABSENT
    assert classify_workspace_root(empty) is WorkspaceRootState.EMPTY
    assert classify_workspace_root(marked) is WorkspaceRootState.MARKED_UNSUPPORTED
    assert classify_workspace_root(legacy) is WorkspaceRootState.LEGACY
    assert classify_workspace_root(mixed) is WorkspaceRootState.MIXED


def test_marker_plus_legacy_is_rejected_without_plaintext_storage_access(tmp_path: Path) -> None:
    root = tmp_path / "workspace"; root.mkdir(); _marker(root)
    (root / "control.sqlite").write_bytes(b"legacy plaintext")
    before = _entries(root)

    with pytest.raises(WorkspaceRootError, match="mixed"):
        Workspace(root)
    with pytest.raises(WorkspaceRootError, match="encrypted V2 workspace unavailable"):
        prepare_workspace_root(root)

    assert _entries(root) == before


@pytest.mark.parametrize("name", ["unknown", "mixed"])
def test_workspace_denial_has_no_filesystem_side_effects(tmp_path: Path, name: str) -> None:
    root = tmp_path / name
    root.mkdir()
    (root / "foreign").write_bytes(b"foreign")
    if name == "mixed":
        (root / "control.sqlite").write_bytes(b"legacy")
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


def test_legacy_boundary_rejects_root_replacement_before_path_consumption(tmp_path: Path) -> None:
    root = tmp_path / "workspace"; root.mkdir()
    boundary = LegacyWorkspaceRoot.open(root)
    original = tmp_path / "original"
    attacker = tmp_path / "attacker"; attacker.mkdir()
    root.rename(original)
    attacker.rename(root)

    with pytest.raises(WorkspaceRootError, match="replaced"):
        boundary.child("cas")

@pytest.mark.parametrize(
    ("name", "kind"),
    [
        ("signing.key", "symlink"),
        ("cas", "symlink"),
        ("signing.key", "fifo"),
        ("cas", "file"),
    ],
)
def test_workspace_denies_unsafe_existing_children_before_any_writes(
    tmp_path: Path, name: str, kind: str
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    target = tmp_path / "outside"
    if kind == "symlink":
        if name == "cas":
            target.mkdir()
            (target / "sentinel").write_bytes(b"outside")
            (root / name).symlink_to(target, target_is_directory=True)
        else:
            target.write_bytes(b"outside")
            (root / name).symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(root / name)
    else:
        (root / name).write_bytes(b"wrong type")
    before = _entries(root)
    target_before = (
        _entries(target) if target.is_dir() else target.read_bytes()
    ) if target.exists() else None

    with pytest.raises(WorkspaceRootError, match=f"workspace child denied: {name}"):
        Workspace(root)

    assert _entries(root) == before
    if target_before is None:
        assert not target.exists()
    else:
        assert (_entries(target) if target.is_dir() else target.read_bytes()) == target_before
