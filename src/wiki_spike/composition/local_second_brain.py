"""Local product façade over the existing encrypted lifecycle authority.

This is deliberately *not* another memory engine. Durable memory truth stays in
LifecycleDatabase + EncryptedContentStore + dual per-artifact key custody. The
facade only translates the small desktop workflow into the existing REMEMBER,
CORRECT, activation, checked-recall, and FORGET contracts.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import getpass
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

import fcntl
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from wiki_spike.applications.encrypted_lifecycle_pipeline import (
    EncryptedLifecyclePipeline,
    PipelineError,
    RememberResult,
)
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.changeset import build_state_delta
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.encrypted_serving import (
    EncryptedArtifactReader,
    EncryptedServingError,
)
from wiki_spike.infrastructure.keystore import PlatformKeyStore, RecoveryKeyStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.contracts import canonical_bytes

NOTE_SCHEMA: Final = "wiki-memory-note-v1"
BACKUP_SCHEMA: Final = "wiki-memory-core-backup-v1"
BACKUP_AAD: Final = b"wiki-memory.core-backup.v1"
MAX_SOURCE_BYTES: Final = 900_000
MAX_BACKUP_BYTES: Final = 2 * 1024 * 1024 * 1024
MAX_QUERY_CHARS: Final = 4096
ROOT_MODE: Final = 0o700
PRIVATE_FILE_MODE: Final = 0o600
READ_ONLY_BLOB_MODE: Final = 0o444
_TOKEN_RE: Final = re.compile(r"[^\W_]+", re.UNICODE)
_HEX64_RE: Final = re.compile(r"^[0-9a-f]{64}$")
_KEY_FILES: Final = ("identity.key", "fallback-dek.key", "signing.key")
_REQUIRED_ROOTS: Final = (
    "lifecycle.sqlite3",
    "cas",
    "keys",
)


class LocalMemoryError(RuntimeError):
    """Operator-facing failure from the local Second Brain façade."""


@dataclass(frozen=True, slots=True)
class SourceDocument:
    name: str
    source_name: str
    source_kind: str
    payload: bytes
    digest: str


@dataclass(frozen=True, slots=True)
class MemoryHit:
    memory_id: str
    source_name: str
    source_sha256: str
    content_sha256: str
    content: str
    created_at: str
    updated_at: str
    score: str
    artifact_id: str = ""
    revision_id: str = ""
    blob_id: str = ""

    def to_mapping(self) -> dict[str, str]:
        return {
            "memory_id": self.memory_id,
            "source_name": self.source_name,
            "source_sha256": self.source_sha256,
            "content_sha256": self.content_sha256,
            "content": self.content,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "score": self.score,
            "artifact_id": self.artifact_id,
            "revision_id": self.revision_id,
            "blob_id": self.blob_id,
        }


@dataclass(frozen=True, slots=True)
class _ActiveRef:
    logical_object_id: str
    artifact_id: str
    revision_id: str
    revision_number: str
    blob_id: str
    created_at: str

    @property
    def memory_id(self) -> str:
        return f"mem_{self.logical_object_id}"


def utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _b64(payload: bytes) -> str:
    return base64.b64encode(payload).decode("ascii")


def _unb64(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise LocalMemoryError(f"{label} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise LocalMemoryError(f"{label} is not strict base64") from exc


def _mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def _assert_not_symlink(path: Path, label: str) -> None:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise LocalMemoryError(f"cannot inspect {label}: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise LocalMemoryError(f"{label} must not be a symlink: {path}")


def _assert_no_symlink_ancestor(path: Path) -> None:
    absolute = Path(os.path.abspath(path.expanduser()))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise LocalMemoryError(f"cannot inspect path component: {current}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise LocalMemoryError(f"symlinked path component is not allowed: {current}")


@contextlib.contextmanager
def _private_umask() -> Iterator[None]:
    previous = os.umask(0o077)
    try:
        yield
    finally:
        os.umask(previous)


def _atomic_write(path: Path, payload: bytes, *, overwrite: bool) -> None:
    _assert_no_symlink_ancestor(path.parent)
    _assert_not_symlink(path, "output file")
    path.parent.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
    if path.exists() and not overwrite:
        raise LocalMemoryError(f"destination already exists: {path}")
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(temporary, flags, PRIVATE_FILE_MODE)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, PRIVATE_FILE_MODE)
        if path.exists() and overwrite:
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise LocalMemoryError(f"destination already exists: {path}") from exc
            temporary.unlink(missing_ok=True)
    finally:
        temporary.unlink(missing_ok=True)


def _clean_title(value: str) -> str:
    title = " ".join(value.strip().split()) if isinstance(value, str) else ""
    if not title or len(title) > 255 or "\x00" in title:
        raise LocalMemoryError("memory title must be 1..255 characters")
    return title


def _text_document(text: str, *, title: str, kind: str) -> SourceDocument:
    if not isinstance(text, str):
        raise LocalMemoryError("memory text must be a string")
    normalized = unicodedata.normalize(
        "NFC",
        text.replace("\r\n", "\n").replace("\r", "\n"),
    )
    payload = normalized.encode("utf-8")
    if not payload:
        raise LocalMemoryError("memory text is empty")
    if len(payload) > MAX_SOURCE_BYTES:
        raise LocalMemoryError(f"memory text exceeds {MAX_SOURCE_BYTES} bytes")
    cleaned = _clean_title(title)
    return SourceDocument(
        name=cleaned,
        source_name=cleaned,
        source_kind=kind,
        payload=payload,
        digest=sha256_bytes(payload),
    )


def _read_source(path: str | Path, *, label: str | None = None) -> SourceDocument:
    requested = Path(path).expanduser()
    _assert_not_symlink(requested, "source file")
    source = requested.resolve()
    _assert_no_symlink_ancestor(source.parent)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise LocalMemoryError(f"cannot open source file: {source}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise LocalMemoryError("source must be a regular file")
        if metadata.st_size > MAX_SOURCE_BYTES:
            raise LocalMemoryError(f"source file exceeds {MAX_SOURCE_BYTES} bytes")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(MAX_SOURCE_BYTES + 1)
    finally:
        os.close(descriptor)
    if not payload:
        raise LocalMemoryError("source file is empty")
    if len(payload) > MAX_SOURCE_BYTES:
        raise LocalMemoryError(f"source file exceeds {MAX_SOURCE_BYTES} bytes")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LocalMemoryError("source must be UTF-8 text or Markdown") from exc
    normalized = unicodedata.normalize(
        "NFC",
        text.replace("\r\n", "\n").replace("\r", "\n"),
    ).encode("utf-8")
    title = _clean_title(label if label is not None else (source.stem or source.name))
    suffix = source.suffix.casefold()
    kind = "MARKDOWN_FILE" if suffix in {".md", ".markdown"} else "TEXT_FILE"
    return SourceDocument(
        name=title,
        source_name=source.name,
        source_kind=kind,
        payload=normalized,
        digest=sha256_bytes(normalized),
    )


def _tokens(text: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFC", text).casefold()
    return tuple(sorted(set(_TOKEN_RE.findall(normalized))))


def _require_passphrase(value: str) -> bytes:
    if not isinstance(value, str) or len(value) < 12:
        raise LocalMemoryError("backup passphrase must contain at least 12 characters")
    return value.encode("utf-8")


def read_passphrase(path: str | Path | None, *, confirm: bool = False) -> str:
    if path is not None:
        source = Path(path).expanduser()
        _assert_not_symlink(source, "passphrase file")
        if not source.is_file():
            raise LocalMemoryError(f"passphrase file does not exist: {source}")
        if _mode(source) & 0o077:
            raise LocalMemoryError("passphrase file permissions must be 0600 or stricter")
        value = source.read_text("utf-8").rstrip("\r\n")
    else:
        value = getpass.getpass("Backup passphrase: ")
        if confirm:
            repeated = getpass.getpass("Repeat backup passphrase: ")
            if value != repeated:
                raise LocalMemoryError("backup passphrases do not match")
    _require_passphrase(value)
    return value


def _derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(
        _require_passphrase(passphrase)
    )


def _note_payload(
    document: SourceDocument,
    *,
    created_at: str,
    updated_at: str,
    origin: dict[str, str] | None = None,
) -> bytes:
    current_source = {
        "kind": document.source_kind,
        "name": document.source_name,
        "sha256": document.digest,
        "locator_kind": "WHOLE_SOURCE",
    }
    payload = {
        "schema": NOTE_SCHEMA,
        "title": document.name,
        "body": document.payload.decode("utf-8"),
        "origin": dict(origin or current_source),
        "revision_source": current_source,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    return canonical_bytes(payload)


def _parse_note(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LocalMemoryError("encrypted memory payload is not valid JSON") from exc
    required = {
        "schema",
        "title",
        "body",
        "origin",
        "revision_source",
        "created_at",
        "updated_at",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise LocalMemoryError("encrypted memory payload has an unsupported shape")
    if value.get("schema") != NOTE_SCHEMA:
        raise LocalMemoryError("encrypted memory payload has an unsupported schema")
    for field in ("title", "body", "created_at", "updated_at"):
        if not isinstance(value.get(field), str):
            raise LocalMemoryError(f"encrypted memory payload field {field} is invalid")
    for field in ("origin", "revision_source"):
        item = value.get(field)
        if not isinstance(item, dict) or set(item) != {
            "kind",
            "name",
            "sha256",
            "locator_kind",
        }:
            raise LocalMemoryError(f"encrypted memory payload field {field} is invalid")
        if not all(isinstance(item[key], str) for key in item):
            raise LocalMemoryError(f"encrypted memory payload field {field} is invalid")
        if not _HEX64_RE.fullmatch(item["sha256"]):
            raise LocalMemoryError(f"encrypted memory payload field {field} digest is invalid")
    return value


class LocalMemoryStore:
    """Small GUI-facing façade over the existing encrypted lifecycle core."""

    def __init__(self, root: str | Path) -> None:
        requested_root = Path(root).expanduser()
        _assert_not_symlink(requested_root, "workspace root")
        self.root = requested_root.resolve()
        self._closed = False
        self._validate_existing_layout()
        self.identity_key = self._read_key("identity.key")
        self.fallback_dek = self._read_key("fallback-dek.key")
        self.signing_seed = self._read_key("signing.key")
        self.workspace_id = "local-" + sha256_bytes(self.identity_key)[:32]
        self.derived_keys = crypto.derive_identity_keys(self.identity_key)

        self.db = LifecycleDatabase(self.root / "lifecycle.sqlite3")
        self.db.initialize()
        self.cas = EncryptedContentStore.open_existing(self.root / "cas")
        self.platform_keystore = PlatformKeyStore(self.root / "keys" / "platform")
        self.recovery_keystore = RecoveryKeyStore(self.root / "keys" / "recovery")
        self.pipeline = EncryptedLifecyclePipeline(
            workspace_id=self.workspace_id,
            derived_keys=self.derived_keys,
            db=self.db,
            cas=self.cas,
            dek=self.fallback_dek,
            platform_keystore=self.platform_keystore,
            recovery_keystore=self.recovery_keystore,
        )
        self.pipeline.bootstrap_workspace()
        self.reader = EncryptedArtifactReader(
            workspace_id=self.workspace_id,
            db=self.db,
            cas=self.cas,
            fallback_dek=self.fallback_dek,
            platform_keystore=self.platform_keystore,
        )
        self.signing_key = Ed25519PrivateKey.from_private_bytes(self.signing_seed)
        self._harden_permissions()

    @classmethod
    def is_initialized(cls, root: str | Path) -> bool:
        requested = Path(root).expanduser()
        try:
            if requested.is_symlink():
                return False
        except OSError:
            return False
        target = requested.resolve()
        return (
            target.is_dir()
            and (target / "lifecycle.sqlite3").is_file()
            and (target / "cas" / "objects").is_dir()
            and (target / "cas" / "tombstones").is_dir()
            and all((target / "keys" / name).is_file() for name in _KEY_FILES)
            and (target / "keys" / "platform").is_dir()
            and (target / "keys" / "recovery").is_dir()
        )

    @classmethod
    def initialize(cls, root: str | Path) -> "LocalMemoryStore":
        requested = Path(root).expanduser()
        _assert_not_symlink(requested, "workspace root")
        target = requested.resolve()
        _assert_no_symlink_ancestor(target.parent)
        _assert_not_symlink(target, "workspace root")
        if target.exists():
            if cls.is_initialized(target):
                return cls(target)
            if any(target.iterdir()):
                raise LocalMemoryError("workspace root must be empty before initialization")
        with _private_umask():
            target.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            os.chmod(target, ROOT_MODE)
            keys = target / "keys"
            (keys / "platform").mkdir(parents=True, mode=ROOT_MODE)
            (keys / "recovery").mkdir(parents=True, mode=ROOT_MODE)
            _atomic_write(keys / "identity.key", os.urandom(32), overwrite=False)
            _atomic_write(keys / "fallback-dek.key", os.urandom(32), overwrite=False)
            _atomic_write(keys / "signing.key", os.urandom(32), overwrite=False)
            cas = EncryptedContentStore(target / "cas")
            del cas
            database = LifecycleDatabase(target / "lifecycle.sqlite3")
            database.initialize()
            database.close()
            lock_path = target / ".lock"
            _atomic_write(lock_path, b"", overwrite=False)
        return cls(target)

    def __enter__(self) -> "LocalMemoryStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        if self._closed:
            return
        self.db.close()
        self._closed = True

    def _validate_existing_layout(self) -> None:
        _assert_no_symlink_ancestor(self.root.parent)
        _assert_not_symlink(self.root, "workspace root")
        if not self.is_initialized(self.root):
            raise LocalMemoryError("memory workspace is not initialized or is incomplete")
        if _mode(self.root) & 0o077:
            raise LocalMemoryError("workspace root permissions must be 0700 or stricter")

    def _read_key(self, name: str) -> bytes:
        path = self.root / "keys" / name
        _assert_not_symlink(path, name)
        if _mode(path) & 0o077:
            raise LocalMemoryError(f"{name} permissions must be 0600 or stricter")
        payload = path.read_bytes()
        if len(payload) != 32:
            raise LocalMemoryError(f"{name} must contain exactly 32 bytes")
        return payload

    def _harden_permissions(self) -> None:
        os.chmod(self.root, ROOT_MODE)
        for directory in (
            self.root / "cas",
            self.root / "cas" / "objects",
            self.root / "cas" / "tombstones",
            self.root / "keys",
            self.root / "keys" / "platform",
            self.root / "keys" / "recovery",
        ):
            if directory.exists():
                os.chmod(directory, ROOT_MODE)
        for path in (
            self.root / "lifecycle.sqlite3",
            self.root / "lifecycle.sqlite3-wal",
            self.root / "lifecycle.sqlite3-shm",
            self.root / ".lock",
            *(self.root / "keys" / name for name in _KEY_FILES),
        ):
            try:
                if path.exists() and not path.is_symlink():
                    os.chmod(path, PRIVATE_FILE_MODE)
            except FileNotFoundError:
                # SQLite sidecars and create-only temp files may disappear
                # between discovery and chmod while another process commits.
                continue
        for custody in ("platform", "recovery"):
            for path in (self.root / "keys" / custody).glob("*.json"):
                try:
                    os.chmod(path, PRIVATE_FILE_MODE)
                except FileNotFoundError:
                    continue
        for path in (self.root / "cas" / "objects").iterdir():
            try:
                if path.is_file() and not path.is_symlink():
                    os.chmod(path, READ_ONLY_BLOB_MODE)
            except FileNotFoundError:
                continue
        for path in (self.root / "cas" / "tombstones").iterdir():
            try:
                if path.is_file() and not path.is_symlink():
                    os.chmod(path, PRIVATE_FILE_MODE)
            except FileNotFoundError:
                continue

    @contextlib.contextmanager
    def _locked(self, *, exclusive: bool) -> Iterator[None]:
        lock_path = self.root / ".lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, PRIVATE_FILE_MODE)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _sign_generation(self, changeset_id: str) -> None:
        self.pipeline.create_generation(
            changeset_id=changeset_id,
            signing_key=self.signing_key,
            signer_key_id="local-owner-v1",
        )

    def _activate_remembered(self, remembered: RememberResult) -> None:
        self.pipeline.review_candidate(
            artifact_id=remembered.artifact_semantic_digest,
            reviewer_handle="local-owner",
            review_state="APPROVED",
        )
        delta = build_state_delta(
            operation="ADD",
            object_kind="MEMORY_REVISION",
            object_id=remembered.artifact_semantic_digest,
            revision_id=remembered.revision_id,
            expected_active_revision_id=remembered.revision_id,
            envelope_ref=remembered.blob_id,
        )
        changeset = self.pipeline.build_changeset(
            command_ids=[remembered.command_id],
            deltas=[delta],
        )
        self.pipeline.persist_changeset(changeset)
        self._sign_generation(changeset["changeset_id"])
        self.pipeline.activate_artifact(
            artifact_id=remembered.artifact_semantic_digest,
            blob_id=remembered.blob_id,
        )

    def remember(self, source: str | Path, *, label: str | None = None) -> dict[str, str]:
        return self._remember_document(_read_source(source, label=label))

    def remember_text(self, text: str, *, title: str = "새 메모") -> dict[str, str]:
        return self._remember_document(
            _text_document(text, title=title, kind="DIRECT_NOTE")
        )

    def _remember_document(self, document: SourceDocument) -> dict[str, str]:
        now = utc_now()
        body = _note_payload(document, created_at=now, updated_at=now)
        with self._locked(exclusive=True), _private_umask():
            try:
                remembered = self.pipeline.remember(
                    raw_body=body,
                    project_id="wiki-memory",
                    source_kind=document.source_kind,
                    input_format=(
                        "MARKDOWN" if document.source_kind == "MARKDOWN_FILE" else "PLAIN_TEXT"
                    ),
                    source_instance_id="local-" + secrets.token_hex(16),
                    subject_ordinal="0",
                    sensitivity="INTERNAL",
                    consent_epoch="1",
                    extractor_profile="LOCAL_RULES_V1",
                )
                self._activate_remembered(remembered)
            except (PipelineError, ValueError, OSError) as exc:
                raise LocalMemoryError(f"encrypted remember failed: {exc}") from exc
            finally:
                self._harden_permissions()
        return {
            "state": "ACTIVE",
            "memory_id": f"mem_{remembered.logical_object_id}",
            "artifact_id": remembered.artifact_semantic_digest,
            "revision_id": remembered.revision_id,
            "blob_id": remembered.blob_id,
            "source_name": document.name,
            "source_sha256": document.digest,
            "content_sha256": sha256_bytes(document.payload),
        }

    @staticmethod
    def _logical_id(memory_id: str) -> str:
        value = memory_id[4:] if memory_id.startswith("mem_") else memory_id
        if not _HEX64_RE.fullmatch(value):
            raise LocalMemoryError("memory id is invalid")
        return value

    def _blob_for_artifact(self, artifact_id: str, revision_id: str) -> str:
        assert self.db.con is not None
        row = self.db.con.execute(
            "SELECT envelope_ref_id FROM state_delta "
            "WHERE object_id=? AND operation_kind='ADD' AND envelope_ref_id IS NOT NULL "
            "ORDER BY rowid DESC LIMIT 1",
            (artifact_id,),
        ).fetchone()
        if row is not None and isinstance(row[0], str) and _HEX64_RE.fullmatch(row[0]):
            if self.cas.exists(row[0]):
                return row[0]
        expected_aad = sha256_bytes(
            crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(artifact_id)
        )
        for path in sorted(self.cas.objects.iterdir()):
            if not path.is_file() or not _HEX64_RE.fullmatch(path.name):
                continue
            try:
                envelope = json.loads(path.read_text("utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                isinstance(envelope, dict)
                and envelope.get("workspace_id") == self.workspace_id
                and envelope.get("revision_id") == revision_id
                and envelope.get("aad_digest") == expected_aad
            ):
                return path.name
        raise LocalMemoryError(f"encrypted blob locator is missing for artifact {artifact_id}")

    def _active_refs(self) -> tuple[_ActiveRef, ...]:
        assert self.db.con is not None
        self.db.con.row_factory = sqlite3.Row
        rows = self.db.con.execute(
            "SELECT b.logical_object_id, b.artifact_id, b.revision_id, "
            "b.revision_number, a.created_at "
            "FROM object_binding b "
            "JOIN canonical_artifact a ON a.artifact_id=b.artifact_id "
            "JOIN key_state k ON k.artifact_id=b.artifact_id "
            "WHERE b.workspace_id=? AND b.object_kind='MEMORY' "
            "AND k.custody_state='ACTIVE' "
            "AND NOT EXISTS (SELECT 1 FROM deletion_state d WHERE d.artifact_id=b.artifact_id) "
            "ORDER BY a.created_at DESC, CAST(b.revision_number AS INTEGER) DESC",
            (self.workspace_id,),
        ).fetchall()
        references: list[_ActiveRef] = []
        seen: set[str] = set()
        for row in rows:
            logical = row["logical_object_id"]
            if logical in seen:
                continue
            seen.add(logical)
            references.append(
                _ActiveRef(
                    logical_object_id=logical,
                    artifact_id=row["artifact_id"],
                    revision_id=row["revision_id"],
                    revision_number=row["revision_number"],
                    blob_id=self._blob_for_artifact(row["artifact_id"], row["revision_id"]),
                    created_at=row["created_at"],
                )
            )
        return tuple(references)

    def _resolve_current(self, memory_id: str) -> _ActiveRef:
        logical = self._logical_id(memory_id)
        for reference in self._active_refs():
            if reference.logical_object_id == logical or reference.artifact_id == logical:
                return reference
        raise LocalMemoryError(f"active memory not found: {memory_id}")

    def _read_ref(self, reference: _ActiveRef, *, score: int = 0) -> tuple[MemoryHit, dict[str, Any]]:
        try:
            decrypted = self.reader.read(
                artifact_id=reference.artifact_id,
                blob_id=reference.blob_id,
            )
        except EncryptedServingError as exc:
            raise LocalMemoryError(f"{exc.code}: {exc}") from exc
        note = _parse_note(decrypted.content)
        body = note["body"]
        revision_source = note["revision_source"]
        hit = MemoryHit(
            memory_id=reference.memory_id,
            source_name=note["title"],
            source_sha256=revision_source["sha256"],
            content_sha256=sha256_bytes(body.encode("utf-8")),
            content=body,
            created_at=note["created_at"],
            updated_at=note["updated_at"],
            score=str(score),
            artifact_id=reference.artifact_id,
            revision_id=reference.revision_id,
            blob_id=reference.blob_id,
        )
        return hit, note

    def get(self, memory_id: str) -> MemoryHit:
        with self._locked(exclusive=False):
            hit, _ = self._read_ref(self._resolve_current(memory_id))
            return hit

    def recent(self, *, limit: int = 100) -> tuple[MemoryHit, ...]:
        if limit < 1 or limit > 1000:
            raise LocalMemoryError("recent limit must be 1..1000")
        with self._locked(exclusive=False):
            return tuple(self._read_ref(ref)[0] for ref in self._active_refs()[:limit])

    def recall(self, query: str, *, limit: int = 10) -> tuple[MemoryHit, ...]:
        if not isinstance(query, str) or not query.strip():
            raise LocalMemoryError("recall query is empty")
        if len(query) > MAX_QUERY_CHARS:
            raise LocalMemoryError(f"recall query exceeds {MAX_QUERY_CHARS} characters")
        if limit < 1 or limit > 100:
            raise LocalMemoryError("recall limit must be 1..100")
        normalized_query = unicodedata.normalize("NFC", query).casefold().strip()
        query_tokens = _tokens(normalized_query)
        matches: list[MemoryHit] = []
        with self._locked(exclusive=False):
            for reference in self._active_refs():
                hit, note = self._read_ref(reference)
                title = unicodedata.normalize("NFC", note["title"]).casefold()
                body = unicodedata.normalize("NFC", note["body"]).casefold()
                source = unicodedata.normalize(
                    "NFC",
                    str(note["origin"]["name"]),
                ).casefold()
                searchable = f"{title}\n{body}\n{source}"
                if normalized_query not in searchable and not all(
                    token in searchable for token in query_tokens
                ):
                    continue
                score = 0
                if normalized_query in title:
                    score += 20
                if normalized_query in body:
                    score += 10
                if normalized_query in source:
                    score += 5
                score += sum(searchable.count(token) for token in query_tokens)
                matches.append(
                    MemoryHit(
                        **{
                            **hit.to_mapping(),
                            "score": str(score),
                        }
                    )
                )
        matches.sort(key=lambda item: (int(item.score), item.updated_at), reverse=True)
        return tuple(matches[:limit])

    def citation(self, memory_id: str) -> dict[str, str]:
        with self._locked(exclusive=False):
            reference = self._resolve_current(memory_id)
            hit, note = self._read_ref(reference)
            assert self.db.con is not None
            prior = self.db.con.execute(
                "SELECT COUNT(*) FROM object_binding "
                "WHERE workspace_id=? AND logical_object_id=? AND artifact_id<>?",
                (self.workspace_id, reference.logical_object_id, reference.artifact_id),
            ).fetchone()[0]
            origin = note["origin"]
            revision_source = note["revision_source"]
            return {
                "memory_id": hit.memory_id,
                "source_name": hit.source_name,
                "source_sha256": hit.source_sha256,
                "content_sha256": hit.content_sha256,
                "created_at": hit.created_at,
                "updated_at": hit.updated_at,
                "prior_versions": str(prior),
                "origin_kind": origin["kind"],
                "origin_name": origin["name"],
                "origin_sha256": origin["sha256"],
                "origin_locator_kind": origin["locator_kind"],
                "revision_source_kind": revision_source["kind"],
                "revision_source_name": revision_source["name"],
                "artifact_id": reference.artifact_id,
                "revision_id": reference.revision_id,
                "logical_object_id": reference.logical_object_id,
                "blob_id": reference.blob_id,
                "authority": "ENCRYPTED_LIFECYCLE_CORE",
            }

    def correct(
        self,
        memory_id: str,
        source: str | Path,
        *,
        label: str | None = None,
    ) -> dict[str, str]:
        return self._correct_document(memory_id, _read_source(source, label=label))

    def correct_text(self, memory_id: str, text: str, *, title: str) -> dict[str, str]:
        return self._correct_document(
            memory_id,
            _text_document(text, title=title, kind="DIRECT_EDIT"),
        )

    def _correct_document(
        self,
        memory_id: str,
        document: SourceDocument,
    ) -> dict[str, str]:
        with self._locked(exclusive=True), _private_umask():
            current = self._resolve_current(memory_id)
            _, current_note = self._read_ref(current)
            now = utc_now()
            payload = _note_payload(
                document,
                created_at=current_note["created_at"],
                updated_at=now,
                origin=current_note["origin"],
            )
            try:
                corrected = self.pipeline.correct(
                    artifact_id=current.artifact_id,
                    reviewer_handle="local-owner",
                    corrected_raw_body=payload,
                    note="local-owner-edit",
                    expected_active_revision_id=current.revision_id,
                )
                self.pipeline.review_candidate(
                    artifact_id=corrected["artifact_semantic_digest"],
                    reviewer_handle="local-owner",
                    review_state="APPROVED",
                )
                self._sign_generation(corrected["changeset_id"])
                self.pipeline.activate_artifact(
                    artifact_id=corrected["artifact_semantic_digest"],
                    blob_id=corrected["blob_id"],
                )
            except (PipelineError, ValueError, OSError) as exc:
                raise LocalMemoryError(f"encrypted correction failed: {exc}") from exc
            finally:
                self._harden_permissions()
        return {
            "state": "ACTIVE",
            "memory_id": f"mem_{current.logical_object_id}",
            "artifact_id": corrected["artifact_semantic_digest"],
            "revision_id": corrected["revision_id"],
            "blob_id": corrected["blob_id"],
            "source_name": document.name,
            "source_sha256": document.digest,
            "content_sha256": sha256_bytes(document.payload),
        }

    def _all_revision_refs(self, logical_object_id: str) -> tuple[_ActiveRef, ...]:
        assert self.db.con is not None
        self.db.con.row_factory = sqlite3.Row
        rows = self.db.con.execute(
            "SELECT b.logical_object_id, b.artifact_id, b.revision_id, "
            "b.revision_number, a.created_at "
            "FROM object_binding b JOIN canonical_artifact a ON a.artifact_id=b.artifact_id "
            "WHERE b.workspace_id=? AND b.logical_object_id=? "
            "ORDER BY CAST(b.revision_number AS INTEGER) DESC",
            (self.workspace_id, logical_object_id),
        ).fetchall()
        return tuple(
            _ActiveRef(
                logical_object_id=row["logical_object_id"],
                artifact_id=row["artifact_id"],
                revision_id=row["revision_id"],
                revision_number=row["revision_number"],
                blob_id=self._blob_for_artifact(row["artifact_id"], row["revision_id"]),
                created_at=row["created_at"],
            )
            for row in rows
        )

    def forget(self, memory_id: str) -> dict[str, str]:
        logical = self._logical_id(memory_id)
        with self._locked(exclusive=True), _private_umask():
            revisions = self._all_revision_refs(logical)
            if not revisions or not any(
                ref.logical_object_id == logical for ref in self._active_refs()
            ):
                raise LocalMemoryError(f"active memory not found: {memory_id}")
            deleted = 0
            last_checkpoint = ""
            for reference in revisions:
                assert self.db.con is not None
                exists = self.db.con.execute(
                    "SELECT 1 FROM deletion_state WHERE artifact_id=? LIMIT 1",
                    (reference.artifact_id,),
                ).fetchone()
                if exists is not None:
                    continue
                try:
                    result = self.pipeline.forget(
                        artifact_id=reference.artifact_id,
                        blob_id=reference.blob_id,
                        selector_kind="LOGICAL_MEMORY",
                        selector_value=logical,
                        revision_id=reference.revision_id,
                        reason_code="local_owner_forget",
                    )
                except (PipelineError, ValueError, OSError) as exc:
                    raise LocalMemoryError(f"encrypted forget failed: {exc}") from exc
                deleted += 1
                last_checkpoint = result["deletion_checkpoint_id"]
            self._harden_permissions()
        return {
            "state": "FORGOTTEN",
            "memory_id": f"mem_{logical}",
            "deleted_revisions": str(deleted),
            "deletion_checkpoint_id": last_checkpoint,
        }

    def events(self, *, limit: int = 20) -> tuple[dict[str, str], ...]:
        if limit < 1 or limit > 1000:
            raise LocalMemoryError("event limit must be 1..1000")
        rows = self.db.event_log_rows()[-limit:]
        return tuple(
            {
                "sequence": str(row["event_id"]),
                "occurred_at": row["created_at"],
                "kind": row["event_kind"],
                "ref_digest": row["ref_digest"],
                "event_digest": row["event_digest"],
            }
            for row in reversed(rows)
        )

    def status(self) -> dict[str, Any]:
        issues: list[str] = []
        try:
            integrity = self.db.con.execute("PRAGMA integrity_check").fetchone()[0]  # type: ignore[union-attr]
        except sqlite3.DatabaseError as exc:
            integrity = f"ERROR: {exc}"
        if integrity != "ok":
            issues.append(f"database integrity: {integrity}")
        bad_blobs = self.cas.scan()
        if bad_blobs:
            issues.append(f"CAS integrity failures: {len(bad_blobs)}")
        if _mode(self.root) & 0o077:
            issues.append("workspace root permissions must be 0700")
        key_modes: list[str] = []
        for name in _KEY_FILES:
            path = self.root / "keys" / name
            mode = _mode(path)
            key_modes.append(oct(mode))
            if mode & 0o077:
                issues.append(f"{name} permissions must be 0600")
        active = len(self._active_refs())
        assert self.db.con is not None
        forgotten = self.db.con.execute(
            "SELECT COUNT(DISTINCT b.logical_object_id) "
            "FROM object_binding b JOIN deletion_state d ON d.artifact_id=b.artifact_id "
            "WHERE b.workspace_id=?",
            (self.workspace_id,),
        ).fetchone()[0]
        parallel_tables = {
            row[0]
            for row in self.db.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            if row[0] in {"memory", "memory_token", "memory_version", "metadata"}
        }
        if parallel_tables:
            issues.append(f"parallel memory tables present: {sorted(parallel_tables)}")
        ready = not issues
        return {
            "profile": "LOCAL_SECOND_BRAIN",
            "authority": "ENCRYPTED_LIFECYCLE_CORE",
            "state": "READY" if ready else "BLOCKED",
            "operational_ready": ready,
            "workspace_id": self.workspace_id,
            "active_memories": str(active),
            "forgotten_memories": str(forgotten),
            "database_integrity": str(integrity),
            "cas_integrity_failures": str(len(bad_blobs)),
            "root_mode": oct(_mode(self.root)),
            "key_mode": ",".join(key_modes),
            "parallel_memory_database": False,
            "network_enabled": False,
            "external_models_enabled": False,
            "automatic_capture_enabled": False,
            "external_export_enabled": False,
            "issues": issues,
        }

    def _snapshot_files(self, destination: Path) -> None:
        destination.mkdir(parents=True, mode=ROOT_MODE)
        database_path = destination / "lifecycle.sqlite3"
        target = sqlite3.connect(database_path)
        try:
            assert self.db.con is not None
            self.db.con.backup(target)
        finally:
            target.close()
        os.chmod(database_path, PRIVATE_FILE_MODE)
        for name in _KEY_FILES:
            target_key = destination / "keys" / name
            target_key.parent.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            shutil.copyfile(self.root / "keys" / name, target_key)
            os.chmod(target_key, PRIVATE_FILE_MODE)
        for relative in (
            Path("keys/platform"),
            Path("keys/recovery"),
            Path("cas/objects"),
            Path("cas/tombstones"),
        ):
            source = self.root / relative
            target_dir = destination / relative
            target_dir.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            for path in source.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise LocalMemoryError(f"unsupported backup entry: {path}")
                copied = target_dir / path.name
                shutil.copyfile(path, copied)
                os.chmod(
                    copied,
                    READ_ONLY_BLOB_MODE if relative == Path("cas/objects") else PRIVATE_FILE_MODE,
                )

    @staticmethod
    def _archive(snapshot: Path, workspace_id: str) -> bytes:
        entries: list[dict[str, str]] = []
        files = [path for path in sorted(snapshot.rglob("*")) if path.is_file()]
        for path in files:
            relative = path.relative_to(snapshot).as_posix()
            payload = path.read_bytes()
            entries.append(
                {
                    "path": relative,
                    "sha256": sha256_bytes(payload),
                    "mode": oct(_mode(path)),
                }
            )
        manifest = canonical_bytes(
            {
                "schema": BACKUP_SCHEMA,
                "workspace_id": workspace_id,
                "created_at": utc_now(),
                "files": entries,
            }
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", manifest)
            for path in files:
                archive.write(path, path.relative_to(snapshot).as_posix())
        payload = buffer.getvalue()
        if len(payload) > MAX_BACKUP_BYTES:
            raise LocalMemoryError(f"backup exceeds {MAX_BACKUP_BYTES} bytes")
        return payload

    def backup(
        self,
        destination: str | Path,
        *,
        passphrase: str,
        overwrite: bool = False,
    ) -> dict[str, str]:
        requested_target = Path(destination).expanduser()
        _assert_not_symlink(requested_target, "backup destination")
        target = requested_target.resolve()
        with self._locked(exclusive=True), tempfile.TemporaryDirectory(
            prefix="wiki-memory-core-backup-"
        ) as temporary:
            snapshot = Path(temporary) / "workspace"
            self._snapshot_files(snapshot)
            archive = self._archive(snapshot, self.workspace_id)
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = _derive_backup_key(passphrase, salt)
        ciphertext = AESGCM(key).encrypt(nonce, archive, BACKUP_AAD)
        container = json.dumps(
            {
                "schema": BACKUP_SCHEMA,
                "kdf": "scrypt-n32768-r8-p1",
                "salt": _b64(salt),
                "nonce": _b64(nonce),
                "ciphertext": _b64(ciphertext),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_write(target, container, overwrite=overwrite)
        return {
            "state": "WRITTEN",
            "backup": str(target),
            "backup_sha256": sha256_bytes(container),
            "workspace_id": self.workspace_id,
        }

    @staticmethod
    def _allowed_restore_path(relative: str) -> bool:
        if relative in {
            "lifecycle.sqlite3",
            "keys/identity.key",
            "keys/fallback-dek.key",
            "keys/signing.key",
        }:
            return True
        return any(
            relative.startswith(prefix)
            for prefix in (
                "keys/platform/",
                "keys/recovery/",
                "cas/objects/",
                "cas/tombstones/",
            )
        )

    @classmethod
    def _extract_archive(cls, archive_bytes: bytes, destination: Path) -> None:
        try:
            archive = zipfile.ZipFile(io.BytesIO(archive_bytes), "r")
        except zipfile.BadZipFile as exc:
            raise LocalMemoryError("backup archive is invalid") from exc
        with archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or "manifest.json" not in names:
                raise LocalMemoryError("backup archive manifest is missing or duplicated")
            if any(
                name.startswith("/")
                or ".." in Path(name).parts
                or "\\" in name
                for name in names
            ):
                raise LocalMemoryError("backup archive contains an unsafe path")
            try:
                manifest = json.loads(archive.read("manifest.json"))
            except (KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LocalMemoryError("backup manifest is invalid") from exc
            if not isinstance(manifest, dict) or manifest.get("schema") != BACKUP_SCHEMA:
                raise LocalMemoryError("backup manifest schema is unsupported")
            entries = manifest.get("files")
            if not isinstance(entries, list):
                raise LocalMemoryError("backup manifest file list is invalid")
            expected = {"manifest.json"}
            total = 0
            destination.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "mode"}:
                    raise LocalMemoryError("backup manifest file entry is invalid")
                relative = entry["path"]
                if not isinstance(relative, str) or not cls._allowed_restore_path(relative):
                    raise LocalMemoryError(f"backup contains unsupported path: {relative!r}")
                expected.add(relative)
                payload = archive.read(relative)
                total += len(payload)
                if total > MAX_BACKUP_BYTES:
                    raise LocalMemoryError("backup expands beyond the allowed size")
                if sha256_bytes(payload) != entry["sha256"]:
                    raise LocalMemoryError(f"backup digest mismatch: {relative}")
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
                _atomic_write(target, payload, overwrite=False)
                requested_mode = int(str(entry["mode"]), 8)
                is_cas_object = relative.startswith("cas/objects/")
                safe_mode = READ_ONLY_BLOB_MODE if is_cas_object else PRIVATE_FILE_MODE
                if is_cas_object:
                    if requested_mode != READ_ONLY_BLOB_MODE:
                        raise LocalMemoryError(
                            f"backup CAS object permissions are invalid: {relative}"
                        )
                elif requested_mode & 0o077:
                    raise LocalMemoryError(f"backup contains unsafe permissions: {relative}")
                os.chmod(target, safe_mode)
            if set(names) != expected:
                raise LocalMemoryError("backup archive contains unmanifested files")
        for directory in (
            destination,
            destination / "keys",
            destination / "keys/platform",
            destination / "keys/recovery",
            destination / "cas",
            destination / "cas/objects",
            destination / "cas/tombstones",
        ):
            directory.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            os.chmod(directory, ROOT_MODE)
        _atomic_write(destination / ".lock", b"", overwrite=False)

    @classmethod
    def restore(
        cls,
        backup: str | Path,
        root: str | Path,
        *,
        passphrase: str,
        replace: bool = False,
    ) -> dict[str, str]:
        requested_source = Path(backup).expanduser()
        _assert_not_symlink(requested_source, "backup file")
        source = requested_source.resolve()
        requested_target = Path(root).expanduser()
        _assert_not_symlink(requested_target, "restore target")
        target = requested_target.resolve()
        _assert_no_symlink_ancestor(target.parent)
        if not source.is_file():
            raise LocalMemoryError(f"backup does not exist: {source}")
        if source.stat().st_size > MAX_BACKUP_BYTES:
            raise LocalMemoryError("backup file is too large")
        try:
            container = json.loads(source.read_text("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LocalMemoryError("backup container is invalid") from exc
        if not isinstance(container, dict) or container.get("schema") != BACKUP_SCHEMA:
            raise LocalMemoryError("backup container schema is unsupported")
        try:
            salt = _unb64(container.get("salt"), "salt")
            nonce = _unb64(container.get("nonce"), "nonce")
            ciphertext = _unb64(container.get("ciphertext"), "ciphertext")
            archive_bytes = AESGCM(_derive_backup_key(passphrase, salt)).decrypt(
                nonce,
                ciphertext,
                BACKUP_AAD,
            )
        except InvalidTag as exc:
            raise LocalMemoryError("backup authentication failed") from exc
        if len(archive_bytes) > MAX_BACKUP_BYTES:
            raise LocalMemoryError("decrypted backup is too large")

        target.parent.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
        stage = Path(
            tempfile.mkdtemp(
                prefix=f".{target.name}.restore-",
                dir=target.parent,
            )
        )
        replaced: Path | None = None
        try:
            cls._extract_archive(archive_bytes, stage)
            checked = cls(stage)
            try:
                status = checked.status()
                workspace_id = checked.workspace_id
            finally:
                checked.close()
            if not status["operational_ready"]:
                raise LocalMemoryError(f"restored workspace is not ready: {status['issues']}")
            if target.exists() and any(target.iterdir()):
                if not replace:
                    raise LocalMemoryError("restore target is not empty; use replace explicitly")
                replaced = target.with_name(
                    f"{target.name}.pre-restore-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}"
                )
                os.replace(target, replaced)
            elif target.exists():
                target.rmdir()
            os.replace(stage, target)
        except BaseException:
            shutil.rmtree(stage, ignore_errors=True)
            if replaced is not None and not target.exists() and replaced.exists():
                os.replace(replaced, target)
            raise
        return {
            "state": "RESTORED",
            "workspace": str(target),
            "workspace_id": workspace_id,
            "replaced_workspace": str(replaced) if replaced is not None else "",
        }


def diagnose(root: str | Path) -> dict[str, Any]:
    target = Path(root).expanduser().resolve()
    if not LocalMemoryStore.is_initialized(target):
        return {
            "profile": "LOCAL_SECOND_BRAIN",
            "authority": "ENCRYPTED_LIFECYCLE_CORE",
            "state": "NOT_READY",
            "operational_ready": False,
            "root": str(target),
            "issues": ["memory workspace is not initialized"],
            "parallel_memory_database": False,
            "network_enabled": False,
            "external_models_enabled": False,
        }
    with LocalMemoryStore(target) as store:
        return store.status()
