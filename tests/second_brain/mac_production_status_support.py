"""Helpers for unauthorized Mac production status tests."""
from __future__ import annotations

import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class PasswdRecord:
    pw_dir: str


def passwd_lookup(home: Path) -> Callable[[int], PasswdRecord]:
    """Return a getpwuid stand-in whose pw_dir is ``home``."""

    def lookup(uid: int) -> PasswdRecord:
        _ = uid
        return PasswdRecord(pw_dir=str(home))

    return lookup


def tree_snapshot(root: Path) -> dict[str, tuple[str, int, bytes | None]]:
    """Capture relative paths with type, mode, and file bytes or link targets."""
    snapshot: dict[str, tuple[str, int, bytes | None]] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        relative_dir = directory.relative_to(root).as_posix()
        if relative_dir != ".":
            meta = os.lstat(directory)
            snapshot[relative_dir] = ("dir", stat.S_IMODE(meta.st_mode), None)
        for name in sorted(dirnames + filenames):
            path = directory / name
            relative = path.relative_to(root).as_posix()
            if relative in snapshot:
                continue
            meta = os.lstat(path)
            mode = stat.S_IMODE(meta.st_mode)
            if stat.S_ISLNK(meta.st_mode):
                snapshot[relative] = ("lnk", mode, os.readlink(path).encode())
            elif stat.S_ISDIR(meta.st_mode):
                snapshot[relative] = ("dir", mode, None)
            elif stat.S_ISREG(meta.st_mode):
                snapshot[relative] = ("reg", mode, path.read_bytes())
            else:
                snapshot[relative] = ("other", mode, None)
    return snapshot
