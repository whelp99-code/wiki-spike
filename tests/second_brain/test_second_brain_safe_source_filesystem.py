from __future__ import annotations

import logging
import os
import threading
from pathlib import Path
from typing import Literal, Never, assert_never

import pytest

from wiki_spike.infrastructure.safe_source_filesystem import (
    SafeSourceFilesystem,
    SafeSourceFilesystemError,
    SourceFilesystemLimits,
)

type ProhibitedKind = Literal["symlink", "hardlink", "special"]


def _client(root: Path, **limits: int) -> SafeSourceFilesystem:
    return SafeSourceFilesystem(
        approved_roots=(root,),
        limits=SourceFilesystemLimits(**limits),
    )


def test_approved_tiny_root_scans_and_reads_without_source_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: one explicitly approved private source root and a write syscall trap.
    root = tmp_path / "approved"
    root.mkdir(mode=0o700)
    note = root / "note.md"
    note.write_bytes(b"approved body")
    note.chmod(0o600)
    client = _client(root)

    def forbid_write(_fd: int, _data: bytes) -> Never:
        pytest.fail("safe source client attempted a write syscall")

    monkeypatch.setattr(os, "write", forbid_write)

    # When: metadata is scanned and the admitted descriptor is read.
    entries = client.scan(root)
    with client.open_file(root, "note.md") as opened:
        body = client.read_file(opened)

    # Then: the bounded source is returned without any write syscall.
    assert [entry.relative_path for entry in entries] == ["note.md"]
    assert body == b"approved body"


def test_unapproved_root_refuses_before_open_or_body_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a client approved only for a different root.
    approved = tmp_path / "approved"
    unapproved = tmp_path / "unapproved"
    approved.mkdir()
    unapproved.mkdir()
    client = _client(approved)
    calls: list[str] = []
    original_open = os.open

    def recording_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        calls.append(os.fsdecode(path))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", recording_open)

    # When / Then: authority denial precedes every filesystem open.
    with pytest.raises(SafeSourceFilesystemError, match="approved"):
        client.scan(unapproved)
    assert calls == []


def test_symlinked_root_ancestor_refuses_before_child_open_or_body_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: an approved textual path whose parent resolves through a symlink.
    real = tmp_path / "real"
    source = real / "source"
    source.mkdir(parents=True)
    (source / "note.md").write_bytes(b"must stay unopened")
    alias = tmp_path / "alias"
    alias.symlink_to(real, target_is_directory=True)
    approved = alias / "source"
    opened_names: list[str] = []
    original_open = os.open

    def recording_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        opened_names.append(os.fsdecode(path))
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def forbid_read(_fd: int, _size: int) -> Never:
        pytest.fail("body beneath a symlinked root ancestor was read")

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "read", forbid_read)

    # When / Then: ancestor admission fails before any source child is opened.
    with pytest.raises(SafeSourceFilesystemError, match="symlink"):
        _client(approved).scan(approved)
    assert "note.md" not in opened_names


def test_credential_class_is_skipped_and_reported_without_opening_or_reading_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Given: a credential-like path alongside an admissible source file.
    root = tmp_path / "source"
    root.mkdir()
    (root / "private.key").write_bytes(b"must stay unread")
    (root / "note.md").write_bytes(b"admitted")
    client = _client(root)
    opened_names: list[str] = []
    original_open = os.open

    def recording_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        rendered = os.fsdecode(path)
        opened_names.append(rendered)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    def forbid_read(_fd: int, _size: int) -> Never:
        pytest.fail("credential body was read")

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "read", forbid_read)

    # When: the bounded metadata scan encounters the denied class.
    with caplog.at_level(logging.WARNING, logger="wiki_spike.infrastructure.safe_source_filesystem"):
        entries = client.scan(root)

    # Then: name denial occurs before the child is opened, is reported, and does not abort the tree.
    assert "private.key" not in opened_names
    assert [entry.relative_path for entry in entries] == ["note.md"]
    assert "deny-class source path skipped: private.key" in caplog.messages


def test_scan_closes_file_descriptors_as_it_walks_a_wide_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a source tree wider than one descriptor budget should require.
    root = tmp_path / "source"
    root.mkdir()
    for index in range(64):
        (root / f"note-{index:03}.md").write_bytes(b"body")
    client = _client(root)
    original_open = os.open
    original_close = os.close
    opened: set[int] = set()
    peak_open = 0

    def recording_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        nonlocal peak_open
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        opened.add(descriptor)
        peak_open = max(peak_open, len(opened))
        return descriptor

    def recording_close(descriptor: int) -> None:
        opened.discard(descriptor)
        original_close(descriptor)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(os, "close", recording_close)

    # When: every file is scanned.
    entries = client.scan(root)

    # Then: descriptors are bounded by traversal depth, not the file count.
    assert len(entries) == 64
    assert peak_open <= 3
    assert opened == set()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "special"])
def test_link_and_special_file_classes_are_refused(tmp_path: Path, kind: ProhibitedKind) -> None:
    # Given: one prohibited inode class under an approved root.
    root = tmp_path / "source"
    root.mkdir()
    candidate = root / "entry.md"
    match kind:
        case "symlink":
            target = tmp_path / "target.md"
            target.write_bytes(b"outside")
            candidate.symlink_to(target)
        case "hardlink":
            target = tmp_path / "target.md"
            target.write_bytes(b"linked")
            os.link(target, candidate)
        case "special":
            os.mkfifo(candidate)
        case unreachable:
            assert_never(unreachable)

    # When / Then: scanning rejects the inode without consuming its body.
    with pytest.raises(SafeSourceFilesystemError, match=kind):
        _client(root).scan(root)


def test_wrong_owner_and_unsafe_mode_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: an approved root with a safe file.
    root = tmp_path / "source"
    root.mkdir()
    note = root / "note.md"
    note.write_bytes(b"body")
    client = _client(root)

    # When / Then: a foreign-owner view is denied.
    monkeypatch.setattr(os, "getuid", lambda: root.stat().st_uid + 1)
    with pytest.raises(SafeSourceFilesystemError, match="owner"):
        client.scan(root)
    monkeypatch.undo()

    # Given / When / Then: group-writable source metadata is denied.
    note.chmod(0o620)
    with pytest.raises(SafeSourceFilesystemError, match="mode"):
        client.scan(root)


def test_entry_depth_file_and_aggregate_budgets_are_enforced(tmp_path: Path) -> None:
    # Given: a two-file nested source tree.
    root = tmp_path / "source"
    nested = root / "nested"
    nested.mkdir(parents=True)
    (root / "one.md").write_bytes(b"1234")
    (nested / "two.json").write_bytes(b"5678")

    # When / Then: every independent resource budget closes the scan.
    with pytest.raises(SafeSourceFilesystemError, match="entries"):
        _client(root, max_entries=1).scan(root)
    with pytest.raises(SafeSourceFilesystemError, match="depth"):
        _client(root, max_depth=0).scan(root)
    with pytest.raises(SafeSourceFilesystemError, match="file count"):
        _client(root, max_files=1).scan(root)
    with pytest.raises(SafeSourceFilesystemError, match="file bytes"):
        _client(root, max_file_bytes=3).scan(root)
    with pytest.raises(SafeSourceFilesystemError, match="aggregate"):
        _client(root, max_total_bytes=7).scan(root)


def test_file_swap_between_metadata_preview_and_open_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given: a deterministic barrier at the target openat call.
    root = tmp_path / "source"
    root.mkdir()
    target = root / "note.md"
    target.write_bytes(b"original")
    replacement = tmp_path / "replacement.md"
    replacement.write_bytes(b"replacement")
    reached_open = threading.Event()
    release_open = threading.Event()
    original_open = os.open

    def barrier_open(path: str | bytes | os.PathLike[str] | os.PathLike[bytes], flags: int, mode: int = 0o777, *, dir_fd: int | None = None) -> int:
        if path == "note.md" and dir_fd is not None:
            reached_open.set()
            assert release_open.wait(timeout=5)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(os, "open", barrier_open)
    errors: list[SafeSourceFilesystemError] = []

    def scan() -> None:
        try:
            _client(root).scan(root)
        except SafeSourceFilesystemError as exc:
            errors.append(exc)

    worker = threading.Thread(target=scan)
    worker.start()
    assert reached_open.wait(timeout=5)

    # When: the directory entry is atomically replaced before openat continues.
    os.replace(replacement, target)
    release_open.set()
    worker.join(timeout=5)

    # Then: preview/open identity mismatch closes the scan.
    assert not worker.is_alive()
    assert len(errors) == 1
    assert "mutation" in str(errors[0])


def test_open_descriptor_recheck_rejects_mutation_during_read(tmp_path: Path) -> None:
    # Given: an admitted source descriptor whose path is modified after admission.
    root = tmp_path / "source"
    root.mkdir()
    note = root / "note.md"
    note.write_bytes(b"before")
    client = _client(root)

    # When / Then: post-read metadata recheck rejects the mutation.
    with client.open_file(root, "note.md") as opened:
        note.write_bytes(b"after-content")
        with pytest.raises(SafeSourceFilesystemError, match="mutation"):
            client.read_file(opened)
