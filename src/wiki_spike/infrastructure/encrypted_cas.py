"""Opaque encrypted content-addressed store (Gate 2, stage-08).

encrypted_cas_enforcement:
  reject_overwrite:        blob_id == sha256(envelope_bytes), so different
                            content cannot land on the same id; existing
                            objects are never rewritten.
  verify_hash_after_write: re-read and re-hash before returning blob_id.
  write_once_permission:   committed blobs are chmod 0o444 (read-only).
  delete_via_tombstone_only: no hard-delete API; tombstone() marks without
                            removing bytes. Confidentiality after tombstone
                            is achieved elsewhere via crypto-shred (key
                            destruction), not by erasing these bytes.
  integrity_scan:          scan() re-hashes every object.
  no_plaintext_ever:       put() rejects bytes that decode as a JSON object
                            carrying an obvious plaintext-bearing field
                            (see assert_opaque). Only opaque non-JSON
                            ciphertext bytes, or JSON objects that validate
                            against schemas/encrypted-lifecycle/envelope-v1
                            .schema.json, may be stored.

This mirrors the write-once / verify-after-write / tombstone-only pattern
in ``wiki_spike.cas.ContentAddressedStore`` (NOT imported here: modules
under ``infrastructure`` must not depend on legacy storage modules).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

try:
    import jsonschema  # type: ignore

    _HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover - exercised only when jsonschema absent
    jsonschema = None  # type: ignore
    _HAVE_JSONSCHEMA = False

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "schemas"
    / "encrypted-lifecycle"
    / "envelope-v1.schema.json"
)
_ENVELOPE_SCHEMA: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

# Obvious plaintext-bearing field names. Any top-level JSON object carrying
# one of these is rejected outright: this store persists ciphertext only.
_PLAINTEXT_MARKER_FIELDS: tuple[str, ...] = ("plaintext", "body", "locator_text")


class EncryptedCASError(RuntimeError):
    """Base error for the encrypted content-addressed store."""


class IntegrityError(EncryptedCASError):
    """Stored/read bytes do not hash to the expected blob_id."""


class NotFound(EncryptedCASError):
    """No blob is stored under the requested blob_id."""


class Tombstoned(EncryptedCASError):
    """The blob has been tombstoned; bytes are retained but not servable."""


class OpaqueViolation(EncryptedCASError):
    """Rejected: bytes are not opaque ciphertext or a valid envelope-v1 object."""


def _try_parse_json_object(data: bytes) -> Any | None:
    """Return the parsed JSON value if ``data`` decodes as UTF-8 JSON, else None."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def assert_opaque(data: bytes) -> None:
    """Reject bytes that decode to a JSON object carrying an obvious
    plaintext-bearing field (``plaintext``, ``body``, ``locator_text``).

    Non-JSON bytes and JSON objects free of these markers pass through
    unchanged; this is a targeted guard against accidental plaintext
    ingestion, not a full envelope validator (see ``_validate_storable``).
    """
    obj = _try_parse_json_object(data)
    if isinstance(obj, dict):
        leaked = sorted(f for f in _PLAINTEXT_MARKER_FIELDS if f in obj)
        if leaked:
            raise OpaqueViolation(
                f"rejected plaintext-bearing field(s) {leaked} in stored bytes"
            )


def _resolve_schema_node(node: dict[str, Any], definitions: dict[str, Any]) -> dict[str, Any]:
    """Resolve a single-level local ``$ref`` against ``definitions``."""
    if "$ref" in node:
        name = node["$ref"].rsplit("/", 1)[-1]
        return definitions[name]
    return node


def _manual_validate_node(
    value: Any, node: dict[str, Any], definitions: dict[str, Any], path: str
) -> None:
    """Enforce the subset of JSON Schema draft-07 used by envelope-v1.schema.json:
    $ref, const, type:"string"(+pattern/minLength), type:"object"
    (+required/properties/additionalProperties:false). Used as the fail-closed
    manual fallback when the ``jsonschema`` dev dependency is not installed;
    kept in lockstep with the schema by reading _ENVELOPE_SCHEMA directly
    rather than hardcoding a parallel copy of its rules.
    """
    node = _resolve_schema_node(node, definitions)

    if "const" in node:
        if value != node["const"]:
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: expected {node['const']!r}, got {value!r}"
            )
        return

    node_type = node.get("type")
    if node_type == "string":
        if not isinstance(value, str):
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: expected string, got {type(value).__name__}"
            )
        pattern = node.get("pattern")
        if pattern is not None and re.fullmatch(pattern, value) is None:
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: value does not match required pattern"
            )
        min_length = node.get("minLength")
        if min_length is not None and len(value) < min_length:
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: shorter than minLength {min_length}"
            )
        return

    if node_type == "object":
        if not isinstance(value, dict):
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: expected object, got {type(value).__name__}"
            )
        required = node.get("required", [])
        missing = [k for k in required if k not in value]
        if missing:
            raise OpaqueViolation(
                f"not a valid envelope-v1 object: {path}: missing required field(s) {missing}"
            )
        properties = node.get("properties", {})
        if node.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            if extra:
                raise OpaqueViolation(
                    f"not a valid envelope-v1 object: {path}: unexpected field(s) {extra}"
                )
        for key, subnode in properties.items():
            if key in value:
                _manual_validate_node(value[key], subnode, definitions, f"{path}.{key}")
        return

    raise OpaqueViolation(
        f"not a valid envelope-v1 object: {path}: unsupported schema node for manual validation"
    )


def _validate_envelope_schema_manual(obj: dict[str, Any]) -> None:
    """Strict fail-closed structural validation used when ``jsonschema`` is
    unavailable. Enforces the same required shape, additionalProperties:false,
    const, and pattern constraints as envelope-v1.schema.json -- it must
    reject exactly what the jsonschema path rejects, never less."""
    definitions = _ENVELOPE_SCHEMA.get("definitions", {})
    _manual_validate_node(obj, _ENVELOPE_SCHEMA, definitions, "envelope")


def _validate_envelope_schema(obj: dict[str, Any]) -> None:
    if _HAVE_JSONSCHEMA:
        try:
            jsonschema.validate(obj, _ENVELOPE_SCHEMA)
        except jsonschema.ValidationError as exc:  # type: ignore[union-attr]
            raise OpaqueViolation(f"not a valid envelope-v1 object: {exc.message}") from exc
    else:
        # jsonschema is an optional dev dependency; when absent this MUST
        # fail closed (reject anything schema-invalid), never silently
        # skip validation. See _validate_envelope_schema_manual.
        _validate_envelope_schema_manual(obj)


def _validate_storable(data: bytes) -> None:
    """Only opaque ciphertext bytes or schema-valid envelope-v1 JSON objects
    may enter the store. No plaintext ever."""
    assert_opaque(data)
    obj = _try_parse_json_object(data)
    if obj is None:
        return  # not JSON text at all: opaque ciphertext bytes, accepted
    if not isinstance(obj, dict):
        raise OpaqueViolation(
            "JSON array/scalar payloads are neither opaque ciphertext nor envelope-v1"
        )
    _validate_envelope_schema(obj)


class EncryptedContentStore:
    """Content-addressed store for ENCRYPTED envelope bytes only.

    ``blob_id = sha256(envelope_bytes)`` (ADR-0026 envelope identity). All
    files live under a caller-provided root directory; behavior is
    deterministic given identical inputs.
    """

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.objects = self.root / "objects"
        self.tombstones = self.root / "tombstones"
        self.objects.mkdir(parents=True, exist_ok=True)
        self.tombstones.mkdir(parents=True, exist_ok=True)

    def _path(self, blob_id: str) -> Path:
        return self.objects / blob_id

    def put(self, envelope_bytes: bytes) -> str:
        """Store opaque envelope bytes; return blob_id = sha256(bytes).

        Write-once: a second put under the same id with different content
        (e.g. a corrupted/tampered existing object) raises IntegrityError.
        An identical second put is a no-op (idempotent).
        """
        _validate_storable(envelope_bytes)
        blob_id = hashlib.sha256(envelope_bytes).hexdigest()
        path = self._path(blob_id)
        if path.exists():
            existing = path.read_bytes()
            if hashlib.sha256(existing).hexdigest() != blob_id:
                raise IntegrityError(f"integrity violation on existing blob {blob_id}")
            if existing != envelope_bytes:
                raise IntegrityError(
                    f"rejected: colliding blob_id {blob_id} for different content"
                )
            return blob_id

        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.objects), prefix=blob_id + ".", suffix=".tmp"
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(envelope_bytes)
                f.flush()
                os.fsync(f.fileno())
            if hashlib.sha256(tmp.read_bytes()).hexdigest() != blob_id:
                raise IntegrityError("verify-after-write failed")
            os.chmod(tmp, 0o444)
            try:
                os.link(tmp, path)  # atomic create-only; fails if another writer won
            except FileExistsError:
                pass  # idempotent: identical content already committed
        finally:
            tmp.unlink(missing_ok=True)
        return blob_id

    def exists(self, blob_id: str) -> bool:
        return self._path(blob_id).exists()

    def is_tombstoned(self, blob_id: str) -> bool:
        return (self.tombstones / blob_id).exists()

    def get(self, blob_id: str) -> bytes:
        """Return the exact stored ciphertext bytes for ``blob_id``.

        Raises Tombstoned if the blob has been logically removed, NotFound
        if no such blob exists, or IntegrityError if the stored bytes no
        longer hash to ``blob_id`` (corruption).
        """
        if self.is_tombstoned(blob_id):
            raise Tombstoned(f"blob {blob_id} has been tombstoned")
        path = self._path(blob_id)
        if not path.exists():
            raise NotFound(f"blob not found: {blob_id}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != blob_id:
            raise IntegrityError(f"integrity violation reading {blob_id}")
        return data

    def tombstone(self, blob_id: str, reason: str = "") -> None:
        """Mark ``blob_id`` as logically removed WITHOUT deleting bytes."""
        (self.tombstones / blob_id).write_text(reason, encoding="utf-8")

    def scan(self) -> list[str]:
        """Integrity scan: return blob_ids whose bytes no longer match their name."""
        bad = []
        for p in self.objects.iterdir():
            if p.name.endswith(".tmp"):
                continue
            if hashlib.sha256(p.read_bytes()).hexdigest() != p.name:
                bad.append(p.name)
        return bad
