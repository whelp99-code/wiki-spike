"""Bounded, descriptor-relative, O_NOFOLLOW read-only Mac artifact reader.

Reads exactly the three closed Mac production artifacts from an existing
``second-brain-v1`` directory without creating, following, or modifying
anything. The reader opens the directory and every leaf descriptor-relative
under ``O_NOFOLLOW``, verifies regular-file identity via ``fstat``, caps sizes,
and returns immutable bytes only. Parsing and product composition are the
caller's job.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path

ARTIFACT_NAMES: tuple[str, str, str] = (
    "signed-authority.json",
    "persistence-profile.json",
    "persistence-receipt.json",
)

_AUTHORITY_LIMIT = 1024 * 1024
_PROFILE_LIMIT = 16 * 1024
_RECEIPT_LIMIT = 16 * 1024

_ARTIFACT_LIMITS: dict[str, int] = {
    "signed-authority.json": _AUTHORITY_LIMIT,
    "persistence-profile.json": _PROFILE_LIMIT,
    "persistence-receipt.json": _RECEIPT_LIMIT,
}

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


@dataclass(frozen=True, slots=True)
class MacArtifactBundle:
    """Immutable bytes of the three closed Mac production artifacts."""

    authority: bytes
    profile: bytes
    receipt: bytes


class MacArtifactReadError(Exception):
    """Typed refusal raised when any artifact cannot be read safely."""

    code: str
    target: str | None

    def __init__(self, code: str, target: str | None = None) -> None:
        self.code = code
        self.target = target
        label = f" for {target!r}" if target is not None else ""
        super().__init__(f"{code}{label}")


def _read_leaf(dir_fd: int, name: str) -> bytes:
    limit = _ARTIFACT_LIMITS[name]
    try:
        fd = os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        code = (
            "artifact_missing" if exc.errno == errno.ENOENT else "artifact_open_refused"
        )
        raise MacArtifactReadError(code, name) from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise MacArtifactReadError("artifact_not_regular", name)
        if before.st_size > limit:
            raise MacArtifactReadError("artifact_oversize", name)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if (
            after.st_dev != before.st_dev
            or after.st_ino != before.st_ino
            or after.st_mode != before.st_mode
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or after.st_size != len(data)
        ):
            raise MacArtifactReadError("artifact_unstable", name)
    finally:
        os.close(fd)
    return data


def read_mac_artifact_bundle(v1_dir: Path) -> MacArtifactBundle:
    """Read the three closed artifacts from an existing ``second-brain-v1`` dir.

    The caller supplies the existing ``second-brain-v1`` directory. The reader
    never creates directories, never writes, and never follows a symlink in the
    directory itself or any leaf.
    """
    try:
        dir_fd = os.open(v1_dir, _DIR_FLAGS)
    except OSError as exc:
        code = "directory_missing" if exc.errno == errno.ENOENT else "directory_invalid"
        raise MacArtifactReadError(code) from exc
    try:
        authority = _read_leaf(dir_fd, ARTIFACT_NAMES[0])
        profile = _read_leaf(dir_fd, ARTIFACT_NAMES[1])
        receipt = _read_leaf(dir_fd, ARTIFACT_NAMES[2])
    finally:
        os.close(dir_fd)
    return MacArtifactBundle(authority=authority, profile=profile, receipt=receipt)
