"""Keyed commitments and AEAD framing for snapshot import payloads."""
from __future__ import annotations

import hmac
import json
import re
import secrets
from dataclasses import dataclass
from hashlib import sha256

from cryptography.exceptions import InvalidTag

from wiki_spike.infrastructure.crypto import aes_gcm_open, aes_gcm_seal, hkdf_sha256
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.snapshot_import_result import ImportedRecordPayloadV1

_TOMBSTONE = "TOMBSTONE"
_LIVE = "LIVE"
_SALT = b"wiki-spike.snapshot-import.v1"
_IDENTITY_INFO = b"snapshot-import-identity-v1"
_AEAD_INFO = b"snapshot-import-aead-v1"
_HEADER_FIELDS = frozenset(
    {
        "native_id",
        "revision",
        "watermark",
        "tombstone_state",
        "relative_path",
        "content_digest",
        "content_length",
    }
)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class SnapshotSealError(ValueError):
    """Sealed snapshot payload could not be authenticated or parsed."""


@dataclass(frozen=True, slots=True)
class ImportKeys:
    identity: bytes
    aead: bytes


@dataclass(frozen=True, slots=True)
class SealedRecord:
    ordinal: str
    object_digest: str
    revision_digest: str
    watermark_digest: str
    tombstone_state: str
    payload_digest: str
    envelope: bytes


@dataclass(frozen=True, slots=True)
class OpenedRecord:
    native_id: str
    revision: str
    watermark: str
    tombstone: bool
    relative_path: str
    content: bytes | None


def derive_import_keys(master: bytes) -> ImportKeys:
    """Derive domain-separated identity and AEAD subkeys from the 32-byte master."""
    return ImportKeys(
        hkdf_sha256(master, _SALT, _IDENTITY_INFO, 32),
        hkdf_sha256(master, _SALT, _AEAD_INFO, 32),
    )


def tombstone_state(tombstone: bool) -> str:
    return _TOMBSTONE if tombstone else _LIVE


def keyed_commit(keys: ImportKeys, domain: str, value: bytes) -> str:
    """HMAC-SHA-256 commitment over a domain-separated identity or payload."""
    return hmac.new(keys.identity, domain.encode() + b"\0" + value, sha256).hexdigest()


def payload_bytes(record: ImportedRecordPayloadV1) -> bytes:
    header = canonical_bytes(
        {
            "native_id": record.native_id,
            "revision": record.revision,
            "watermark": record.watermark,
            "tombstone_state": tombstone_state(record.tombstone),
            "relative_path": record.relative_path or "",
            "content_digest": record.content_digest or ("0" * 64),
            "content_length": str(0 if record.content is None else len(record.content)),
        }
    )
    return header + b"\n" + (b"" if record.content is None else record.content)


def record_set_digest(keys: ImportKeys, sealed: tuple[SealedRecord, ...]) -> str:
    body: dict[str, JsonValue] = {
        "records": [
            {
                "ordinal": item.ordinal,
                "object_digest": item.object_digest,
                "revision_digest": item.revision_digest,
                "watermark_digest": item.watermark_digest,
                "tombstone_state": item.tombstone_state,
                "payload_digest": item.payload_digest,
            }
            for item in sealed
        ]
    }
    return keyed_commit(keys, "record-set-v1", canonical_bytes(body))


def aad_bytes(
    cohort_id: str,
    snapshot_digest: str,
    discovery_digest: str,
    namespace_id: str,
    sealed: SealedRecord,
) -> bytes:
    return canonical_bytes(
        {
            "cohort_id": cohort_id,
            "snapshot_digest": snapshot_digest,
            "discovery_digest": discovery_digest,
            "namespace_id": namespace_id,
            "object_digest": sealed.object_digest,
            "revision_digest": sealed.revision_digest,
            "tombstone_state": sealed.tombstone_state,
            "ordinal": sealed.ordinal,
        }
    )


def seal_record(
    keys: ImportKeys,
    record: ImportedRecordPayloadV1,
    ordinal: str,
    cohort_id: str,
    snapshot_digest: str,
    discovery_digest: str,
    namespace_id: str,
) -> SealedRecord:
    payload = payload_bytes(record)
    state = tombstone_state(record.tombstone)
    unsigned = SealedRecord(
        ordinal,
        keyed_commit(keys, "native-id-v1", record.native_id.encode()),
        keyed_commit(keys, "revision-v1", record.revision.encode()),
        keyed_commit(keys, "watermark-v1", record.watermark.encode()),
        state,
        keyed_commit(keys, "payload-v1", payload),
        b"",
    )
    nonce = secrets.token_bytes(12).hex()
    ciphertext, tag = aes_gcm_seal(
        keys.aead,
        nonce,
        payload,
        aad_bytes(cohort_id, snapshot_digest, discovery_digest, namespace_id, unsigned),
    )
    return SealedRecord(
        unsigned.ordinal,
        unsigned.object_digest,
        unsigned.revision_digest,
        unsigned.watermark_digest,
        unsigned.tombstone_state,
        unsigned.payload_digest,
        bytes.fromhex(nonce + ciphertext + tag),
    )


def _header(raw: bytes) -> dict[str, str]:
    header, separator, _body = raw.partition(b"\n")
    if separator != b"\n":
        raise SnapshotSealError("restore mismatch: payload framing")
    try:
        parsed = json.loads(header.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SnapshotSealError("restore mismatch: payload framing") from exc
    if not isinstance(parsed, dict):
        raise SnapshotSealError("restore mismatch: payload framing")
    unknown = set(parsed) - _HEADER_FIELDS
    missing = _HEADER_FIELDS - set(parsed)
    if unknown or missing:
        raise SnapshotSealError("restore mismatch: payload framing")
    values: dict[str, str] = {}
    for field in _HEADER_FIELDS:
        value = parsed[field]
        if not isinstance(value, str):
            raise SnapshotSealError("restore mismatch: payload framing")
        values[field] = value
    return values


def open_record(
    keys: ImportKeys,
    envelope: bytes,
    sealed: SealedRecord,
    cohort_id: str,
    snapshot_digest: str,
    discovery_digest: str,
    namespace_id: str,
) -> OpenedRecord:
    if len(envelope) < 28:
        raise SnapshotSealError("restore mismatch: corrupt object")
    try:
        payload = aes_gcm_open(
            keys.aead,
            envelope[:12].hex(),
            envelope[12:-16].hex(),
            envelope[-16:].hex(),
            aad_bytes(cohort_id, snapshot_digest, discovery_digest, namespace_id, sealed),
        )
    except (InvalidTag, ValueError) as exc:
        raise SnapshotSealError("restore mismatch: authentication failed") from exc
    if keyed_commit(keys, "payload-v1", payload) != sealed.payload_digest:
        raise SnapshotSealError("restore mismatch: payload digest")
    header = _header(payload)
    body = payload.partition(b"\n")[2]
    tombstone = header["tombstone_state"] == _TOMBSTONE
    if tombstone:
        if header["relative_path"] != "" or header["content_length"] != "0" or body:
            raise SnapshotSealError("restore mismatch: tombstone framing")
        content = None
    else:
        if header["content_length"] != str(len(body)) or not _DIGEST.fullmatch(
            header["content_digest"]
        ):
            raise SnapshotSealError("restore mismatch: content length")
        if sha256(body).hexdigest() != header["content_digest"]:
            raise SnapshotSealError("restore mismatch: content digest")
        content = body
    if keyed_commit(keys, "native-id-v1", header["native_id"].encode()) != sealed.object_digest:
        raise SnapshotSealError("restore mismatch: swapped object")
    if keyed_commit(keys, "revision-v1", header["revision"].encode()) != sealed.revision_digest:
        raise SnapshotSealError("restore mismatch: swapped revision")
    if keyed_commit(keys, "watermark-v1", header["watermark"].encode()) != sealed.watermark_digest:
        raise SnapshotSealError("restore mismatch: swapped watermark")
    if tombstone_state(tombstone) != sealed.tombstone_state:
        raise SnapshotSealError("restore mismatch: tombstone state")
    return OpenedRecord(
        header["native_id"],
        header["revision"],
        header["watermark"],
        tombstone,
        header["relative_path"],
        content,
    )
