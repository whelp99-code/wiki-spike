from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Never

import pytest

from wiki_spike.applications.source_discovery_service import (
    SourceDiscoveryError,
    discover_source,
)
from wiki_spike.canonical import canonical_bytes
from wiki_spike.memory_core.errors import UnknownContractField
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
)

_SCRIPT = Path("scripts/second_brain_source_discovery.py")


def _request(root: Path, *, source_name: str = "me-wiki") -> SourceDiscoveryRequestV1:
    return SourceDiscoveryRequestV1.from_mapping(
        {
            "request_version": SOURCE_DISCOVERY_REQUEST_V1,
            "source_name": source_name,
            "source_root": str(root.absolute()),
        }
    )


def test_discovery_emits_canonical_metadata_without_body_reads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "source"
    notes = root / "notes"
    notes.mkdir(parents=True)
    first = notes / "alpha.md"
    second = root / "memory.sqlite"
    _ = first.write_text("body must remain unopened", encoding="utf-8")
    _ = second.write_bytes(b"sqlite body must remain unopened")
    before = {
        path: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in (first, second)
    }

    def forbid_body_read(_path: Path) -> bytes:
        raise AssertionError("source body was opened during metadata discovery")

    monkeypatch.setattr(Path, "read_bytes", forbid_body_read)
    def forbid_open(*_args: str, **_kwargs: str) -> Never:
        pytest.fail("source body was opened during metadata discovery")

    monkeypatch.setattr("builtins.open", forbid_open)
    manifest = discover_source(_request(root))

    assert manifest.source_name == "me-wiki"
    assert manifest.body_reads == "0"
    assert [entry.relative_path for entry in manifest.entries] == [
        "memory.sqlite",
        "notes/alpha.md",
    ]
    assert all(len(entry.path_digest) == 64 for entry in manifest.entries)
    assert before == {
        path: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in (first, second)
    }
    assert SourceDiscoveryManifestV1.from_mapping(
        manifest.to_mapping()
    ) == manifest


def test_discovery_excludes_git_metadata_without_reading_bodies(tmp_path: Path) -> None:
    root = tmp_path / "source"
    git_dir = root / ".git"
    git_dir.mkdir(parents=True)
    note = root / "note.md"
    edit_message = git_dir / "COMMIT_EDITMSG"
    _ = note.write_text("approved body", encoding="utf-8")
    _ = edit_message.write_text("private VCS metadata", encoding="utf-8")
    before = {
        path: (path.stat().st_size, path.stat().st_mtime_ns)
        for path in (note, git_dir, edit_message)
    }

    manifest = discover_source(_request(root))

    assert [entry.relative_path for entry in manifest.entries] == ["note.md"]
    assert before == {
        path: (path.stat().st_size, path.stat().st_mtime_ns)
        for path in before
    }


@pytest.mark.parametrize(
    "relative_path",
    [
        "private.pem",
        "id_rsa",
        "login.keychain-db",
        "session.token",
        "Cookies",
        "hidden-reasoning.json",
    ],
)
def test_discovery_rejects_deny_class_paths_without_opening_bodies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    denied = root / relative_path
    _ = denied.write_text("fake denied-class body", encoding="utf-8")

    def forbid_body_read(_path: Path) -> bytes:
        raise AssertionError("denied body was opened")

    monkeypatch.setattr(Path, "read_bytes", forbid_body_read)
    def forbid_open(*_args: str, **_kwargs: str) -> Never:
        pytest.fail("denied body was opened")

    monkeypatch.setattr("builtins.open", forbid_open)
    with pytest.raises(SourceDiscoveryError, match="deny-class"):
        _ = discover_source(_request(root))


def test_discovery_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    outside = tmp_path / "outside.md"
    _ = outside.write_text("outside", encoding="utf-8")
    (root / "escape.md").symlink_to(outside)

    with pytest.raises(SourceDiscoveryError, match="symlink"):
        _ = discover_source(_request(root))


def test_discovery_rejects_root_symlink(tmp_path: Path) -> None:
    root = tmp_path / "source"
    target = tmp_path / "target"
    target.mkdir()
    root.symlink_to(target, target_is_directory=True)

    with pytest.raises(SourceDiscoveryError, match="root symlink"):
        _ = discover_source(_request(root))


def test_discovery_rejects_nested_directory_symlink(tmp_path: Path) -> None:
    root = tmp_path / "source"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    (root / "nested").symlink_to(target, target_is_directory=True)

    with pytest.raises(SourceDiscoveryError, match="symlink"):
        _ = discover_source(_request(root))


def test_discovery_rejects_unsupported_suffix(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    _ = (root / "notes.txt").write_text("not approved", encoding="utf-8")

    with pytest.raises(SourceDiscoveryError, match="unsupported"):
        _ = discover_source(_request(root))


def test_discovery_rejects_special_file(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    os.mkfifo(root / "events.jsonl")

    with pytest.raises(SourceDiscoveryError, match="special"):
        _ = discover_source(_request(root))


def test_discovery_rejects_missing_root_and_unknown_source(
    tmp_path: Path,
) -> None:
    with pytest.raises(SourceDiscoveryError, match="root"):
        _ = discover_source(_request(tmp_path / "missing"))
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(ValueError, match="source_name"):
        _ = _request(root, source_name="unknown-source")


def test_discovery_request_rejects_extra_fields(tmp_path: Path) -> None:
    root = tmp_path / "source"
    root.mkdir()
    with pytest.raises(UnknownContractField):
        _ = SourceDiscoveryRequestV1.from_mapping(
            {
                "request_version": SOURCE_DISCOVERY_REQUEST_V1,
                "source_name": "me-wiki",
                "source_root": str(root.resolve()),
                "unexpected": "field",
            }
        )


def test_discovery_cli_writes_canonical_manifest_and_refuses_denied_input(
    tmp_path: Path,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    allowed = root / "memory.jsonl"
    _ = allowed.write_text("{}\n", encoding="utf-8")
    request_path = tmp_path / "request.json"
    output_path = tmp_path / "manifest.json"
    _ = request_path.write_bytes(
        canonical_bytes(_request(root).to_mapping()) + b"\n"
    )

    completed = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--request",
            str(request_path),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    expected = discover_source(_request(root))
    assert output_path.read_bytes() == canonical_bytes(expected.to_mapping()) + b"\n"
    assert expected.body_reads == "0"

    _ = (root / "private.key").write_text("fake private key", encoding="utf-8")
    output_path.unlink()
    refused = subprocess.run(
        [
            sys.executable,
            str(_SCRIPT),
            "--request",
            str(request_path),
            "--output",
            str(output_path),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert refused.returncode != 0
    assert "deny-class" in refused.stderr
    assert not output_path.exists()
