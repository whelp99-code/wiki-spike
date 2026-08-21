#!/usr/bin/env python3
"""Issue a create-only non-destructive retention certificate."""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)

_KIND = "second-brain-retention-certificate-v1"
_RETENTION_HOURS = "2160"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_WRITE = (
    os.O_WRONLY
    | os.O_CREAT
    | os.O_EXCL
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class RetentionCertificateError(Exception):
    """Fail-closed retention certificate error."""


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", required=True)
    parser.add_argument(
        "--destructive-action-authorized",
        default="false",
    )
    parser.add_argument("--source-deletion-authorized", default="false")
    parser.add_argument("--retention-hours", default=_RETENTION_HOURS)
    parser.add_argument("--conservation-digest", default="")
    parser.add_argument("--restore-digest", default="")
    return parser.parse_args(argv)


def _write(dest: Path, payload: bytes) -> None:
    try:
        meta = os.lstat(dest)
    except OSError:
        meta = None
    if meta is not None:
        raise RetentionCertificateError("destination already exists")
    parent = dest.parent
    try:
        parent_meta = os.lstat(parent)
    except OSError as exc:
        raise RetentionCertificateError("destination parent is absent") from exc
    if stat.S_ISLNK(parent_meta.st_mode) or not stat.S_ISDIR(parent_meta.st_mode):
        raise RetentionCertificateError("destination parent is not a directory")
    fd = os.open(dest, _WRITE, 0o444)
    try:
        written = 0
        while written < len(payload):
            written += os.write(fd, payload[written:])
        os.fsync(fd)
    finally:
        os.close(fd)


def _hex64(value: object, field: str) -> str:
    text = str(value)
    if not _HEX64.fullmatch(text):
        raise RetentionCertificateError(f"{field} is required")
    return text


def _issue(args: argparse.Namespace) -> None:
    if str(args.destructive_action_authorized) != "false":
        raise RetentionCertificateError("destructive action is not authorized")
    if str(args.source_deletion_authorized) != "false":
        raise RetentionCertificateError("source deletion is not authorized")
    if str(args.retention_hours) != _RETENTION_HOURS:
        raise RetentionCertificateError("early expiry is not authorized")
    conservation_digest = _hex64(args.conservation_digest, "conservation_digest")
    restore_digest = _hex64(args.restore_digest, "restore_digest")
    if conservation_digest == restore_digest:
        raise RetentionCertificateError(
            "conservation and restore evidence must differ"
        )
    dest = Path(str(args.dest))
    body = {
        "certificate_kind": _KIND,
        "conservation_digest": conservation_digest,
        "destructive_action_authorized": "false",
        "key_deletion_authorized": "false",
        "restore_digest": restore_digest,
        "retention_hours": _RETENTION_HOURS,
        "source_deletion_authorized": "false",
    }
    body["certificate_digest"] = canonical_ledger_digest(_KIND, body)
    _write(dest, canonical_bytes(body) + b"\n")


def main(argv: list[str] | None = None) -> int:
    try:
        _issue(_parse(argv))
    except RetentionCertificateError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
