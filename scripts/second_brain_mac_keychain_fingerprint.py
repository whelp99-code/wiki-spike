#!/usr/bin/env python3
"""Public-only create-only Mac Keychain fingerprint receipt CLI.

Never reads Keychain secrets, never calls security add/delete, never follows
symlinks, and never writes product-release receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.infrastructure.macos_keychain import (
    KeychainBackend,
    ProductionCustodyError,
)
from wiki_spike.infrastructure.macos_keychain_existing import (
    MAC_KEYCHAIN_SERVICE,
    SERVING_ARK_HANDLE,
    open_existing_macos_keychain_store,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)

RECEIPT_KIND = "mac-keychain-fingerprint-v1"
_INDEX_LIMIT = 4096
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
)


class FingerprintReceiptError(Exception):
    """Operator-facing failure."""


class _PublicBackend:
    def add(self, *, service: str, account: str, secret: str) -> bool:
        raise FingerprintReceiptError("fingerprint CLI never writes Keychain secrets")

    def read(self, *, service: str, account: str) -> str | None:
        raise FingerprintReceiptError("fingerprint CLI never reads Keychain secrets")

    def delete(self, *, service: str, account: str) -> bool:
        raise FingerprintReceiptError("fingerprint CLI never deletes Keychain items")


def _refuse_unsafe_dest(path: Path) -> None:
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
            raise FingerprintReceiptError("output path is missing") from None
        if stat.S_ISLNK(metadata.st_mode):
            raise FingerprintReceiptError("output would follow a symlink")
        if index == len(parts) - 1:
            raise FingerprintReceiptError("output already exists")


def _read_nofollow(path: Path) -> bytes:
    try:
        descriptor = os.open(path, _READ_FLAGS)
    except OSError as exc:
        raise FingerprintReceiptError("index record is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise FingerprintReceiptError("index record is not regular")
        if metadata.st_size > _INDEX_LIMIT:
            raise FingerprintReceiptError("index record exceeds 4096 bytes")
        data = os.read(descriptor, metadata.st_size)
        if len(data) != metadata.st_size:
            raise FingerprintReceiptError("index record read is unstable")
        return data
    finally:
        os.close(descriptor)


def _write_create_only(path: Path, content: bytes) -> None:
    try:
        descriptor = os.open(path, _WRITE_FLAGS, 0o600)
    except FileExistsError as exc:
        raise FingerprintReceiptError("output already exists") from exc
    except OSError as exc:
        raise FingerprintReceiptError("output cannot be created") from exc
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            offset += os.write(descriptor, content[offset:])
        os.fsync(descriptor)
    except OSError as exc:
        os.close(descriptor)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise FingerprintReceiptError("output write failed") from exc
    os.close(descriptor)


def _receipt(raw: bytes, *, service: str, namespace: str, ark_handle: str) -> dict[str, str]:
    try:
        mapping = json.loads(raw)
    except ValueError as exc:
        raise FingerprintReceiptError("index record is malformed") from exc
    if not isinstance(mapping, dict):
        raise FingerprintReceiptError("index record is malformed")
    metadata = mapping.get("metadata_digest")
    if not isinstance(metadata, str):
        raise FingerprintReceiptError("index metadata digest is invalid")
    index_sha256 = hashlib.sha256(raw).hexdigest()
    fingerprint = hashlib.sha256(
        f"{index_sha256}\0{metadata}".encode("ascii")
    ).hexdigest()
    body = {
        "ark_handle": ark_handle,
        "fingerprint": fingerprint,
        "index_sha256": index_sha256,
        "metadata_digest": metadata,
        "namespace": namespace,
        "receipt_kind": RECEIPT_KIND,
        "service": service,
    }
    return body | {"receipt_digest": canonical_ledger_digest(RECEIPT_KIND, body)}


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write a public-only create-only Mac Keychain fingerprint receipt."
    )
    parser.add_argument("--index-dir", required=True, type=Path)
    parser.add_argument("--keychain-directory", required=True, type=Path)
    parser.add_argument("--workspace-ref", required=True)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--service", default=MAC_KEYCHAIN_SERVICE)
    parser.add_argument("--ark-handle", default=SERVING_ARK_HANDLE)
    return parser.parse_args(argv)


def _emit(
    args: argparse.Namespace, *, backend: KeychainBackend | None
) -> dict[str, str]:
    dest = Path(args.out)
    _refuse_unsafe_dest(dest)
    selected = backend if backend is not None else _PublicBackend()
    _ = open_existing_macos_keychain_store(
        index_dir=Path(args.index_dir),
        service=str(args.service),
        namespace=str(args.workspace_ref),
        ark_handle=str(args.ark_handle),
        backend=selected,
        keychain_directory=Path(args.keychain_directory),
    )
    account = hashlib.sha256(
        f"{args.workspace_ref}\0{args.ark_handle}".encode()
    ).hexdigest()
    raw = _read_nofollow(Path(args.index_dir) / f"{account}.json")
    receipt = _receipt(
        raw,
        service=str(args.service),
        namespace=str(args.workspace_ref),
        ark_handle=str(args.ark_handle),
    )
    _write_create_only(dest, canonical_bytes(receipt) + b"\n")
    return receipt


def main(
    argv: list[str] | None = None, *, backend: KeychainBackend | None = None
) -> int:
    try:
        receipt = _emit(_parse(argv), backend=backend)
    except FingerprintReceiptError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except ProductionCustodyError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {"receipt_digest": receipt["receipt_digest"]},
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
