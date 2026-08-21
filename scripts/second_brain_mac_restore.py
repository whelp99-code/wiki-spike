#!/usr/bin/env python3
"""Fail-closed Mac production restore of backed-up lifecycle sqlite and CAS.

Copies sqlite + CAS from a backup dest into an empty target v1 dir only after
SERVING_READY inspect. Never mutates the backup, never follows symlinks, never
copies Keychain secrets, and refuses without creating dest when sqlite, CAS,
or SERVING_READY is missing.
"""
from __future__ import annotations

import argparse
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.infrastructure.lifecycle_db import LifecycleDbError
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)
from wiki_spike.infrastructure.mac_backup_receipt import (
    MacBackupReceiptError,
    verify_backup_receipt,
    verify_restore_receipt,
    write_restore_receipt,
)

_READ = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_WRITE = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)
_CHUNK = 1024 * 1024


class RestoreError(Exception):
    """Operator-facing restore refusal."""


def _require_real_dir(path: Path, label: str) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    metadata: os.stat_result | None = None
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise RestoreError(f"{label} is missing") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RestoreError(f"{label} would follow a symlink")
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        raise RestoreError(f"{label} is not a directory")


def _require_absent_dest(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    parts = absolute.parts[1:]
    for index, component in enumerate(parts):
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if index == len(parts) - 1:
                return
            raise RestoreError("destination path is missing") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise RestoreError("destination would follow a symlink")
        if index == len(parts) - 1:
            raise RestoreError("destination already exists")


def _assert_tree_copyable(root: Path) -> None:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            child = Path(dirpath) / name
            try:
                metadata = os.lstat(child)
            except OSError as exc:
                raise RestoreError("CAS path is missing") from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise RestoreError("CAS would follow a symlink")
            if not stat.S_ISDIR(metadata.st_mode) and not stat.S_ISREG(metadata.st_mode):
                raise RestoreError("CAS contains a special file")


def _mkdir_private(path: Path, mode: int) -> None:
    try:
        os.mkdir(path, 0o700)
    except FileExistsError as exc:
        raise RestoreError("destination already exists") from exc
    os.chmod(path, mode)


def _copy_regular(src: Path, dest: Path) -> None:
    infd = os.open(src, _READ)
    try:
        info = os.fstat(infd)
        if not stat.S_ISREG(info.st_mode):
            raise RestoreError("source is not a regular file")
        try:
            outfd = os.open(dest, _WRITE, stat.S_IMODE(info.st_mode))
        except FileExistsError as exc:
            raise RestoreError("destination already exists") from exc
        try:
            os.fchmod(outfd, stat.S_IMODE(info.st_mode))
            while True:
                chunk = os.read(infd, _CHUNK)
                if not chunk:
                    break
                written = 0
                while written < len(chunk):
                    written += os.write(outfd, chunk[written:])
            os.fsync(outfd)
        except OSError as exc:
            os.close(outfd)
            try:
                os.unlink(dest)
            except OSError:
                pass
            raise RestoreError("copy failed") from exc
        os.close(outfd)
    finally:
        os.close(infd)


def _copy_tree(src: Path, dest: Path) -> None:
    src_meta = os.lstat(src)
    if stat.S_ISLNK(src_meta.st_mode) or not stat.S_ISDIR(src_meta.st_mode):
        raise RestoreError("CAS is not a directory")
    _mkdir_private(dest, stat.S_IMODE(src_meta.st_mode))
    with os.scandir(src) as entries:
        children = list(entries)
    for entry in children:
        src_child = Path(entry.path)
        dest_child = dest / entry.name
        metadata = entry.stat(follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            raise RestoreError("CAS would follow a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            _copy_tree(src_child, dest_child)
        elif stat.S_ISREG(metadata.st_mode):
            _copy_regular(src_child, dest_child)
        else:
            raise RestoreError("CAS contains a special file")


def _inspect(sqlite: Path, workspace_ref: str) -> None:
    database = open_existing_lifecycle_database(sqlite)
    try:
        _ = inspect_existing_serving_ready(database, workspace_ref)
    finally:
        database.close()


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Copy backed-up Mac lifecycle sqlite and CAS after SERVING_READY."
    )
    parser.add_argument("--backup", required=True, type=Path)
    parser.add_argument("--workspace-ref", required=True)
    parser.add_argument("--dest", required=True, type=Path)
    return parser.parse_args(argv)


def _restore(args: argparse.Namespace) -> None:
    backup = Path(args.backup)
    sqlite = backup / "lifecycle.sqlite3"
    cas = backup / "cas"
    dest = Path(args.dest)
    _inspect(sqlite, str(args.workspace_ref))
    _require_real_dir(cas, "CAS")
    _assert_tree_copyable(cas)
    backup_digest = verify_backup_receipt(backup, str(args.workspace_ref))
    _require_absent_dest(dest)
    _mkdir_private(dest, 0o700)
    copied_sqlite = dest / "lifecycle.sqlite3"
    copied_cas = dest / "cas"
    _copy_regular(sqlite, copied_sqlite)
    _copy_tree(cas, copied_cas)
    write_restore_receipt(
        dest,
        str(args.workspace_ref),
        copied_sqlite,
        copied_cas,
        backup_digest,
    )
    verify_restore_receipt(dest, str(args.workspace_ref))


def main(argv: list[str] | None = None) -> int:
    try:
        _restore(_parse(argv))
    except (RestoreError, LifecycleDbError, MacBackupReceiptError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
