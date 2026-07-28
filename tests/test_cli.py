from __future__ import annotations

from pathlib import Path

import pytest

from wiki_spike.cli import main
from wiki_spike.workspace_format import (
    WORKSPACE_FORMAT_FILENAME,
    ProfileSelection,
    WorkspaceFormatMarker,
)


_COMMANDS = (
    ("receive", "missing-source"),
    ("compile", "source-id"),
    ("status", "source-id"),
    ("ingest", "missing-source"),
    ("search", "term"),
    ("admin-revoke", "claim-id"),
    ("mirror",),
    ("log",),
)


def _make_root(tmp_path: Path, kind: str) -> Path:
    root = tmp_path / kind
    root.mkdir()
    if kind != "unknown":
        (root / "control.sqlite").write_bytes(b"legacy")
    if kind != "legacy":
        (root / "foreign").write_bytes(b"foreign")
    return root


def _snapshot(root: Path) -> dict[str, bytes | None]:
    return {
        path.name: path.read_bytes() if path.is_file() and not path.is_symlink() else None
        for path in root.iterdir()
    }


@pytest.mark.parametrize("kind", ["unknown", "mixed"])
@pytest.mark.parametrize("command", _COMMANDS)
def test_every_cli_command_denies_unsafe_root_before_writes(
    tmp_path: Path, kind: str, command: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    root = _make_root(tmp_path, kind)
    before = _snapshot(root)

    assert main(["--root", str(root), *command]) == 1

    assert _snapshot(root) == before
    assert f"workspace root denied: {kind}" in capsys.readouterr().err


def test_cli_denies_symlink_root_without_writing_target(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    target = tmp_path / "target"; target.mkdir()
    root = tmp_path / "root-link"; root.symlink_to(target, target_is_directory=True)

    assert main(["--root", str(root), "log"]) == 1

    assert list(target.iterdir()) == []
    assert "workspace root denied: unknown" in capsys.readouterr().err


@pytest.mark.parametrize("command", _COMMANDS)
def test_every_cli_command_denies_marker_before_storage_access(
    tmp_path: Path, command: tuple[str, ...], capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "marked"; root.mkdir()
    marker = WorkspaceFormatMarker.create(
        workspace_id="marked",
        profile_selection=ProfileSelection.FIELD_AEAD,
        encrypted_lifecycle_enabled=True,
    )
    (root / WORKSPACE_FORMAT_FILENAME).write_bytes(marker.canonical_bytes())
    (root / "control.sqlite").write_bytes(b"legacy plaintext")
    before = _snapshot(root)

    assert main(["--root", str(root), *command]) == 1
    assert _snapshot(root) == before
    assert "workspace root denied: mixed" in capsys.readouterr().err
