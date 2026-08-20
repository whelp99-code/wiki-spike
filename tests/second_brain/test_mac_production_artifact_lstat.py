"""Closed Mac artifact paths are inspected without following or creating them."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_support import (
    bomb_storage,
    isolate_home,
    marked_root,
    tree_snapshot,
)
from wiki_spike.composition.mac_production import main

SIGNED_AUTHORITY_ABSENT_TOKEN = "signed authority is absent"
PERSISTENCE_PROFILE_ABSENT_TOKEN = "persistence profile is absent"
SERVING_READY_ABSENT_TOKEN = "SERVING_READY is absent"


@pytest.mark.parametrize(
    "artifact_name",
    [
        "signed-authority.json",
        "persistence-profile.json",
        "persistence-receipt.json",
    ],
)
def test_status_refuses_when_closed_artifact_is_symlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    artifact_name: str,
) -> None:
    isolate_home(tmp_path, monkeypatch)
    home = tmp_path / "home"
    artifact = (
        home
        / "Library"
        / "Application Support"
        / "wiki-spike"
        / "second-brain-v1"
        / artifact_name
    )
    artifact.parent.mkdir(parents=True)
    artifact.symlink_to(tmp_path / "missing-target")
    artifacts_seen = {"saw": False}
    real_lstat = os.lstat

    def recording_lstat(path: str | bytes | os.PathLike[str]) -> os.stat_result:
        if str(path) == str(artifact):
            artifacts_seen["saw"] = True
        return real_lstat(path)

    monkeypatch.setattr(
        "wiki_spike.composition.mac_production.os.lstat", recording_lstat
    )
    root = marked_root(tmp_path)
    bomb_storage(monkeypatch)
    before = tree_snapshot(home)

    code = main(["--root", str(root), "status"])

    captured = capsys.readouterr()
    assert code == 1
    assert SIGNED_AUTHORITY_ABSENT_TOKEN in captured.err
    assert PERSISTENCE_PROFILE_ABSENT_TOKEN in captured.err
    assert SERVING_READY_ABSENT_TOKEN in captured.err
    assert tree_snapshot(home) == before
    assert artifacts_seen["saw"]
