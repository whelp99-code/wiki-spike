"""Create-only Mac lifecycle backup receipt."""
from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)

_CHUNK = 1024 * 1024
_KIND = "mac-lifecycle-backup-receipt-v1"
_RESTORE_KIND = "mac-lifecycle-restore-receipt-v1"
_FIELDS = frozenset(
    {
        "cas_file_count",
        "cas_manifest_digest",
        "receipt_digest",
        "receipt_kind",
        "serving_ready",
        "sqlite_sha256",
        "workspace_ref",
    }
)
_RESTORE_FIELDS = _FIELDS | {"backup_receipt_digest"}
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


def _expected_body(workspace_ref: str, sqlite: Path, cas: Path) -> dict[str, str]:
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
    return body


def write_backup_receipt(
    dest: Path, workspace_ref: str, sqlite: Path, cas: Path
) -> None:
    """Write dest/backup-receipt.json create-only with string-only fields."""
    payload = canonical_bytes(_expected_body(workspace_ref, sqlite, cas)) + b"\n"
    fd = os.open(dest / "backup-receipt.json", _WRITE, 0o444)
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _reject_number(value: str) -> int:
    raise MacBackupReceiptError("raw numbers are forbidden")


def _expected_restore_body(
    workspace_ref: str,
    sqlite: Path,
    cas: Path,
    backup_receipt_digest: str,
) -> dict[str, str]:
    rows = _cas_rows(cas)
    body = {
        "backup_receipt_digest": backup_receipt_digest,
        "cas_file_count": str(len(rows)),
        "cas_manifest_digest": hashlib.sha256(
            "\n".join(rows).encode("utf-8")
        ).hexdigest(),
        "receipt_kind": _RESTORE_KIND,
        "serving_ready": "true",
        "sqlite_sha256": _digest_file(sqlite),
        "workspace_ref": workspace_ref,
    }
    body["receipt_digest"] = canonical_ledger_digest(_RESTORE_KIND, body)
    return body


def write_restore_receipt(
    dest: Path,
    workspace_ref: str,
    sqlite: Path,
    cas: Path,
    backup_receipt_digest: str,
) -> None:
    """Write dest/restore-receipt.json create-only with string-only fields."""
    payload = canonical_bytes(
        _expected_restore_body(
            workspace_ref, sqlite, cas, backup_receipt_digest
        )
    ) + b"\n"
    fd = os.open(dest / "restore-receipt.json", _WRITE, 0o444)
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_backup_receipt(backup: Path, workspace_ref: str) -> str:
    """Refuse a missing, extra-field, or digest-mismatched backup receipt."""
    receipt_path = backup / "backup-receipt.json"
    try:
        meta = os.lstat(receipt_path)
    except OSError as exc:
        raise MacBackupReceiptError("backup receipt is absent") from exc
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise MacBackupReceiptError("backup receipt is not a regular file")
    fd = os.open(receipt_path, _READ)
    try:
        raw = b""
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    payload: object = json.loads(
        raw.decode("utf-8"),
        parse_int=_reject_number,
        parse_float=_reject_number,
    )
    if not isinstance(payload, dict):
        raise MacBackupReceiptError("backup receipt must be an object")
    unknown = set(payload) - _FIELDS
    missing = _FIELDS - set(payload)
    if unknown or missing:
        raise MacBackupReceiptError("backup receipt fields are invalid")
    observed = {key: payload[key] for key in _FIELDS}
    if any(not isinstance(value, str) or not value for value in observed.values()):
        raise MacBackupReceiptError("backup receipt fields are invalid")
    expected = _expected_body(
        workspace_ref, backup / "lifecycle.sqlite3", backup / "cas"
    )
    if observed != expected:
        raise MacBackupReceiptError("backup receipt does not match sqlite and CAS")
    return observed["receipt_digest"]


def verify_restore_receipt(dest: Path, workspace_ref: str) -> str:
    """Refuse a missing, extra-field, or digest-mismatched restore receipt."""
    receipt_path = dest / "restore-receipt.json"
    try:
        meta = os.lstat(receipt_path)
    except OSError as exc:
        raise MacBackupReceiptError("restore receipt is absent") from exc
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise MacBackupReceiptError("restore receipt is not a regular file")
    fd = os.open(receipt_path, _READ)
    try:
        raw = b""
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    payload: object = json.loads(
        raw.decode("utf-8"),
        parse_int=_reject_number,
        parse_float=_reject_number,
    )
    if not isinstance(payload, dict):
        raise MacBackupReceiptError("restore receipt must be an object")
    unknown = set(payload) - _RESTORE_FIELDS
    missing = _RESTORE_FIELDS - set(payload)
    if unknown or missing:
        raise MacBackupReceiptError("restore receipt fields are invalid")
    observed = {key: payload[key] for key in _RESTORE_FIELDS}
    if any(not isinstance(value, str) or not value for value in observed.values()):
        raise MacBackupReceiptError("restore receipt fields are invalid")
    expected = _expected_restore_body(
        workspace_ref,
        dest / "lifecycle.sqlite3",
        dest / "cas",
        observed["backup_receipt_digest"],
    )
    if observed != expected:
        raise MacBackupReceiptError("restore receipt does not match sqlite and CAS")
    return observed["receipt_digest"]
