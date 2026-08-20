"""Bounded, descriptor-relative Mac artifact reader: fail-closed on every refusal."""

from __future__ import annotations

import dataclasses
import os
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_support import tree_snapshot
from wiki_spike.composition.mac_artifact_io import (
    MacArtifactBundle,
    MacArtifactReadError,
    read_mac_artifact_bundle,
)

ARTIFACT_NAMES = (
    "signed-authority.json",
    "persistence-profile.json",
    "persistence-receipt.json",
)
AUTHORITY_LIMIT = 1024 * 1024
PROFILE_LIMIT = 16 * 1024
RECEIPT_LIMIT = 16 * 1024


def _v1_dir(tmp_path: Path) -> Path:
    v1 = tmp_path / "second-brain-v1"
    v1.mkdir()
    return v1


def _write_all(v1: Path, contents: dict[str, bytes]) -> None:
    for name, payload in contents.items():
        _ = (v1 / name).write_bytes(payload)


def _happy_contents() -> dict[str, bytes]:
    return {
        "signed-authority.json": b'{"authority":"signed"}',
        "persistence-profile.json": b'{"profile":true}',
        "persistence-receipt.json": b'{"receipt":"ok"}',
    }


def test_reads_exact_bytes_when_all_three_regular(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    contents = _happy_contents()
    _write_all(v1, contents)

    bundle = read_mac_artifact_bundle(v1)

    assert bundle.authority == contents["signed-authority.json"]
    assert bundle.profile == contents["persistence-profile.json"]
    assert bundle.receipt == contents["persistence-receipt.json"]


def test_returns_frozen_byte_bundle_when_read(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())

    bundle = read_mac_artifact_bundle(v1)

    assert isinstance(bundle, MacArtifactBundle)
    assert dataclasses.is_dataclass(bundle)
    with pytest.raises(dataclasses.FrozenInstanceError):
        bundle.__setattr__("authority", b"mutated")


def test_refuses_when_v1_dir_missing(tmp_path: Path) -> None:
    missing = tmp_path / "second-brain-v1"

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(missing)

    assert excinfo.value.code == "directory_missing"


def test_refuses_when_v1_dir_is_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real-v1"
    target.mkdir()
    _write_all(target, _happy_contents())
    link = tmp_path / "second-brain-v1"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(link)

    assert excinfo.value.code == "directory_invalid"


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_refuses_when_artifact_missing(tmp_path: Path, name: str) -> None:
    v1 = _v1_dir(tmp_path)
    contents = _happy_contents()
    del contents[name]
    _write_all(v1, contents)

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_missing"
    assert excinfo.value.target == name


@pytest.mark.parametrize("name", ARTIFACT_NAMES)
def test_refuses_when_leaf_is_symlink(tmp_path: Path, name: str) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    leaf = v1 / name
    leaf.unlink()
    leaf.symlink_to(tmp_path / "outside-target")

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_open_refused"
    assert excinfo.value.target == name


def test_refuses_when_leaf_is_fifo(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    fifo = v1 / "persistence-profile.json"
    fifo.unlink()
    os.mkfifo(fifo)

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_not_regular"
    assert excinfo.value.target == "persistence-profile.json"


def test_refuses_when_leaf_is_directory(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    leaf = v1 / "persistence-receipt.json"
    leaf.unlink()
    leaf.mkdir()

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_not_regular"


@pytest.mark.parametrize(
    ("name", "limit"),
    [
        ("signed-authority.json", AUTHORITY_LIMIT),
        ("persistence-profile.json", PROFILE_LIMIT),
        ("persistence-receipt.json", RECEIPT_LIMIT),
    ],
)
def test_refuses_when_artifact_oversize(
    tmp_path: Path,
    name: str,
    limit: int,
) -> None:
    v1 = _v1_dir(tmp_path)
    contents = _happy_contents()
    contents[name] = b"x" * (limit + 1)
    _write_all(v1, contents)

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_oversize"
    assert excinfo.value.target == name


def test_refuses_when_artifact_grew_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    real_read = os.read
    state = {"calls": 0}

    def growing_read(fd: int, size: int) -> bytes:
        state["calls"] += 1
        chunk = real_read(fd, size)
        if state["calls"] == 1:
            return chunk + b"x"
        return chunk

    monkeypatch.setattr("wiki_spike.composition.mac_artifact_io.os.read", growing_read)

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_unstable"


def test_refuses_when_artifact_swapped_during_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    real_fstat = os.fstat
    state = {"calls": 0}

    def swapping_fstat(fd: int) -> os.stat_result:
        state["calls"] += 1
        meta = real_fstat(fd)
        if state["calls"] == 2:
            values = list(meta)
            values[1] = meta.st_ino + 1
            return os.stat_result(values)
        return meta

    monkeypatch.setattr(
        "wiki_spike.composition.mac_artifact_io.os.fstat", swapping_fstat
    )

    with pytest.raises(MacArtifactReadError) as excinfo:
        _ = read_mac_artifact_bundle(v1)

    assert excinfo.value.code == "artifact_unstable"


def test_read_leaves_tree_bytes_modes_and_links_unchanged(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    before = tree_snapshot(tmp_path)

    _ = read_mac_artifact_bundle(v1)

    assert tree_snapshot(tmp_path) == before


def test_refusal_leaves_tree_bytes_modes_and_links_unchanged(tmp_path: Path) -> None:
    v1 = _v1_dir(tmp_path)
    _write_all(v1, _happy_contents())
    (v1 / "persistence-receipt.json").unlink()
    before = tree_snapshot(tmp_path)

    with pytest.raises(MacArtifactReadError):
        _ = read_mac_artifact_bundle(v1)

    assert tree_snapshot(tmp_path) == before
