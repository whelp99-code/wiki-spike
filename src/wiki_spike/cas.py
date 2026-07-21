"""Content-Addressed Store with write-once enforcement (v3.3 §4-1).

cas_enforcement:
  reject_overwrite:        path == content_hash, so different content cannot land
                           on the same path; existing objects are never rewritten.
  verify_hash_after_write: re-read and re-hash before commit.
  write_once_permission:   committed blobs are chmod 0o444 (read-only).
  delete_via_tombstone_only: no hard-delete API; tombstone() marks without removing.
  integrity_scan:          scan() re-hashes every object.
"""
from __future__ import annotations

import os
from pathlib import Path

from .hashing import sha256_hex


class CASError(RuntimeError):
    pass


class ContentAddressedStore:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.tombstones = self.root / "tombstones"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.tombstones.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        return self.objects / digest

    def put(self, data: bytes) -> str:
        digest = sha256_hex(data)
        path = self._path(digest)
        if path.exists():
            if sha256_hex(path.read_bytes()) != digest:
                raise CASError(f"integrity violation on existing object {digest}")
            return digest
        # Concurrency-safe: each writer uses its OWN temp file (mkstemp), fsyncs,
        # then does an atomic create-only link. A lost race (FileExistsError) is a
        # no-op because the content is identical by construction (idempotent).
        import tempfile

        fd, tmp_name = tempfile.mkstemp(dir=str(self.objects), prefix=digest + ".", suffix=".tmp")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if sha256_hex(tmp.read_bytes()) != digest:
                raise CASError("verify-after-write failed")
            os.chmod(tmp, 0o444)
            try:
                os.link(tmp, path)  # atomic create-only; fails if another writer won
            except FileExistsError:
                pass  # idempotent: identical content already committed
        finally:
            tmp.unlink(missing_ok=True)
        return digest

    def exists(self, digest: str) -> bool:
        return self._path(digest).exists()

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        if not path.exists():
            raise CASError(f"object not found: {digest}")
        data = path.read_bytes()
        if sha256_hex(data) != digest:
            raise CASError(f"integrity violation reading {digest}")
        return data

    def is_tombstoned(self, digest: str) -> bool:
        return (self.tombstones / digest).exists()

    def tombstone(self, digest: str, reason: str) -> None:
        # Delete via tombstone only: the blob is retained, a marker is written.
        (self.tombstones / digest).write_text(reason, encoding="utf-8")

    def scan(self) -> list[str]:
        """Integrity scan: return digests whose bytes no longer match their name."""
        bad = []
        for p in self.objects.iterdir():
            if p.name.endswith(".tmp"):
                continue
            if sha256_hex(p.read_bytes()) != p.name:
                bad.append(p.name)
        return bad
