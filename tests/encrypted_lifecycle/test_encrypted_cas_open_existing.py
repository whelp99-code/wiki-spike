"""Existing-only encrypted CAS admission never provisions storage."""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedCASError,
    EncryptedContentStore,
)


def _layout(root: Path) -> None:
    root.mkdir(mode=0o700)
    (root / "objects").mkdir(mode=0o700)
    (root / "tombstones").mkdir(mode=0o700)


def _snapshot(root: Path) -> dict[str, tuple[int, bytes | None]]:
    result: dict[str, tuple[int, bytes | None]] = {}
    for path in [root, *sorted(root.rglob("*"))]:
        metadata = os.lstat(path)
        relative = "." if path == root else path.relative_to(root).as_posix()
        payload = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result[relative] = (stat.S_IMODE(metadata.st_mode), payload)
    return result


def test_open_existing_admits_strict_layout_without_mkdir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "cas"
    _layout(root)
    before = _snapshot(root)

    def refuse_mkdir(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("open_existing must not provision directories")

    monkeypatch.setattr(Path, "mkdir", refuse_mkdir)
    store = EncryptedContentStore.open_existing(root)

    assert type(store) is EncryptedContentStore
    assert store.root == root
    assert store.objects == root / "objects"
    assert store.tombstones == root / "tombstones"
    assert _snapshot(root) == before


def test_open_existing_reads_preexisting_ciphertext_without_writes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "cas"
    created = EncryptedContentStore(root)
    envelope = b"\x00" * 12 + b"ciphertext" * 6 + b"\xff" * 16
    blob_id = created.put(envelope)
    for path in (root, root / "objects", root / "tombstones"):
        path.chmod(0o700)
    before = _snapshot(root)

    reopened = EncryptedContentStore.open_existing(root)

    assert reopened.get(blob_id) == created.get(blob_id)
    assert _snapshot(root) == before


@pytest.mark.parametrize("missing_child", [None, "objects", "tombstones"])
def test_open_existing_refuses_missing_layout_without_creating(
    tmp_path: Path,
    missing_child: str | None,
) -> None:
    root = tmp_path / "cas"
    if missing_child is not None:
        _layout(root)
        (root / missing_child).rmdir()

    with pytest.raises(EncryptedCASError, match="existing CAS"):
        _ = EncryptedContentStore.open_existing(root)

    if missing_child is None:
        assert not root.exists()
    else:
        assert not (root / missing_child).exists()


@pytest.mark.parametrize("name", [".", "objects", "tombstones"])
def test_open_existing_refuses_symlinked_layout(
    tmp_path: Path,
    name: str,
) -> None:
    real = tmp_path / "real"
    _layout(real)
    if name == ".":
        root = tmp_path / "cas"
        root.symlink_to(real, target_is_directory=True)
    else:
        root = tmp_path / "cas"
        _layout(root)
        (root / name).rmdir()
        (root / name).symlink_to(real / name, target_is_directory=True)

    with pytest.raises(EncryptedCASError, match="existing CAS"):
        _ = EncryptedContentStore.open_existing(root)


@pytest.mark.parametrize("name", [".", "objects", "tombstones"])
def test_open_existing_refuses_bad_directory_mode(
    tmp_path: Path,
    name: str,
) -> None:
    root = tmp_path / "cas"
    _layout(root)
    path = root if name == "." else root / name
    path.chmod(0o755)

    with pytest.raises(EncryptedCASError, match="mode"):
        _ = EncryptedContentStore.open_existing(root)
