"""No-follow package-root allowlist and payload admission."""
from __future__ import annotations

import os

from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    open_directory,
    open_root,
    read_regular,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

ROOT_FILES = frozenset(
    {
        "bounded-snapshot.json",
        "payload-manifest.json",
        "opening-proof.json",
        "closing-proof.json",
        "evidence.json",
        "receipt.json",
    }
)


def open_package_root(package_root: str) -> int:
    return open_root(package_root)


def read_root_file(root_fd: int, name: str, budget: int) -> tuple[bytes, int]:
    if name not in ROOT_FILES:
        raise UnifiedDbExportError("unlisted package root file")
    return read_regular(root_fd, name, 0o400, budget)


def assert_root_allowlist(root_fd: int) -> None:
    names = set(os.listdir(root_fd))
    extra = names - ROOT_FILES - {"payload"}
    if extra:
        raise UnifiedDbExportError("unlisted package root path")
    missing = ROOT_FILES - names
    if missing or "payload" not in names:
        raise UnifiedDbExportError("package root allowlist is incomplete")
    payload_fd = open_directory(root_fd, "payload", 0o500)
    os.close(payload_fd)


def read_payload_tree_at(root_fd: int, budget: int) -> tuple[dict[str, bytes], int]:
    payload_fd = open_directory(root_fd, "payload", 0o500)
    try:
        found: dict[str, bytes] = {}
        remaining = budget
        for name in sorted(os.listdir(payload_fd)):
            data, remaining = read_regular(payload_fd, name, 0o400, remaining)
            found[name] = data
        return found, remaining
    finally:
        os.close(payload_fd)


def read_payload_tree(package_root: str) -> dict[str, bytes]:
    root_fd = open_package_root(package_root)
    try:
        assert_root_allowlist(root_fd)
        found, _remaining = read_payload_tree_at(root_fd, HARD_CAP)
        return found
    finally:
        os.close(root_fd)
