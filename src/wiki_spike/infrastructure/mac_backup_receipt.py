"""Create-only Mac lifecycle backup receipt."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)

_CHUNK = 1024 * 1024
_KIND = "mac-lifecycle-backup-receipt-v1"
_READ = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_WRITE = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class MacBackupReceiptError(Exception):
    """Fail-closed backup receipt error."""


def _digest_file(path: Path) -> str:
    hasher = hashlib.sha256()
    fd = os.open(path, _READ)
    try:
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            hasher.update(chunk)
    finally:
        os.close(fd)
    return hasher.hexdigest()


def _cas_rows(root: Path) -> list[str]:
    rows: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        filenames.sort()
        base = Path(dirpath)
        for name in filenames:
            child = base / name
            meta = os.lstat(child)
            if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
                raise MacBackupReceiptError("CAS would follow a symlink")
            rel = child.relative_to(root).as_posix()
            rows.append(f"{rel} {_digest_file(child)}")
    rows.sort()
    return rows


def write_backup_receipt(
    dest: Path, workspace_ref: str, sqlite: Path, cas: Path
) -> None:
    """Write dest/backup-receipt.json create-only with string-only fields."""
    rows = _cas_rows(cas)
    body = {
        "cas_file_count": str(len(rows)),
        "cas_manifest_digest": hashlib.sha256(
            "\n".join(rows).encode("utf-8")
        ).hexdigest(),
        "receipt_kind": _KIND,
        "serving_ready": "true",
        "sqlite_sha256": _digest_file(sqlite),
        "workspace_ref": workspace_ref,
    }
    body["receipt_digest"] = canonical_ledger_digest(_KIND, body)
    payload = canonical_bytes(body) + b"\n"
    fd = os.open(dest / "backup-receipt.json", _WRITE, 0o444)
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
