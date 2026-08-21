#!/usr/bin/env python3
"""Refuse snapshot import unless resolver_outcome is RESOLVED. Never writes dest."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

_READ = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
_CHUNK = 1024 * 1024
_FIELDS = frozenset(
    {
        "live_operation_authorized",
        "resolver_outcome",
        "stage0_contract_usable",
    }
)


class AuthorizedImportError(Exception):
    """Fail-closed authorized import error."""


def _reject_number(value: str) -> int:
    raise AuthorizedImportError("raw numbers are forbidden")


def _require_regular(path: Path, label: str) -> None:
    try:
        meta = os.lstat(path)
    except OSError as exc:
        raise AuthorizedImportError(f"{label} is absent") from exc
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        raise AuthorizedImportError(f"{label} is not a regular file")


def _require_dir(path: Path, label: str) -> None:
    try:
        meta = os.lstat(path)
    except OSError as exc:
        raise AuthorizedImportError(f"{label} is absent") from exc
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        raise AuthorizedImportError(f"{label} is not a directory")


def _require_absent(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise AuthorizedImportError("destination already exists")


def _refuse_dest_inside(source: Path, dest: Path) -> None:
    source_abs = Path(os.path.abspath(source))
    dest_abs = Path(os.path.abspath(dest))
    try:
        dest_abs.relative_to(source_abs)
    except ValueError:
        return
    raise AuthorizedImportError("destination is inside the source tree")


def _read_bytes(path: Path) -> bytes:
    fd = os.open(path, _READ)
    try:
        raw = b""
        while True:
            chunk = os.read(fd, _CHUNK)
            if not chunk:
                break
            raw += chunk
    finally:
        os.close(fd)
    return raw


def _load_receipt(path: Path) -> dict[str, str]:
    _require_regular(path, "resolution receipt")
    payload: object = json.loads(
        _read_bytes(path).decode("utf-8"),
        parse_int=_reject_number,
        parse_float=_reject_number,
    )
    if not isinstance(payload, dict):
        raise AuthorizedImportError("resolution receipt must be an object")
    unknown = set(payload) - _FIELDS
    missing = _FIELDS - set(payload)
    if unknown or missing:
        raise AuthorizedImportError("resolution receipt fields are invalid")
    observed = {key: payload[key] for key in _FIELDS}
    if any(not isinstance(value, str) or not value for value in observed.values()):
        raise AuthorizedImportError("resolution receipt fields are invalid")
    return observed


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resolution-receipt", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--dest", required=True)
    return parser.parse_args(argv)


def _import(args: argparse.Namespace) -> None:
    receipt = Path(str(args.resolution_receipt))
    source = Path(str(args.source_root))
    dest = Path(str(args.dest))
    observed = _load_receipt(receipt)
    _require_dir(source, "source root")
    _refuse_dest_inside(source, dest)
    _require_absent(dest)
    if observed["resolver_outcome"] != "RESOLVED":
        raise AuthorizedImportError("authorized import is refused")
    raise AuthorizedImportError("authorized import is not enabled")


def main(argv: list[str] | None = None) -> int:
    try:
        _import(_parse(argv))
    except AuthorizedImportError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
