"""Retained, fail-closed deployment authority for native shadow measurements.

This module deliberately does not import the Application layer.  It is a
structural implementation of that layer's ``MonotonicAppendAuthority``
Protocol: composition supplies the snapshot value factory, preserving the
Core/Application -> Infrastructure boundary.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from secrets import token_hex
from typing import Any, Callable, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

_DATETIME = datetime


AUTHORITY_DOMAIN = "second-brain-native-shadow-authority-v1"
STATE_SCHEMA = "second-brain-deployment-monotonic-authority-state-v1"
RECEIPT_SCHEMA = "second-brain-deployment-live-operation-receipt-v1"
EVIDENCE_SCHEMA = "second-brain-deployment-authority-evidence-v1"


class DeploymentAuthorityError(RuntimeError):
    """Configuration, retained-state, or durable-write validation failed."""


@dataclass(frozen=True, slots=True)
class DeploymentAuthorityEvidence:
    """Contractual pins supplied by a deployment, never inferred from an endpoint."""

    identity: str
    endpoint: str
    policy_id: str
    measurement_binding: str
    public_key_fingerprint: str

    def __post_init__(self) -> None:
        if (not all(isinstance(value, str) and value for value in (
            self.identity, self.endpoint, self.policy_id, self.measurement_binding,
        )) or not self.endpoint.startswith("retention-authority://")
                or not _digest(self.public_key_fingerprint)):
            raise DeploymentAuthorityError("deployment authority evidence is invalid")


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _receipt_root(events: list[dict[str, Any]]) -> str:
    return sha256(canonical_ledger_bytes(AUTHORITY_DOMAIN, {"events": events})).hexdigest()


def _state_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonical JSON for retained events, which legitimately include integers."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DeploymentAuthorityError("retained authority state is not canonicalizable") from exc


def _stamp(value: datetime) -> str:
    if not isinstance(value, _DATETIME) or value.tzinfo is None:
        raise DeploymentAuthorityError("authority clock is invalid")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class DeploymentMonotonicAppendAuthority:
    """A lock-serialized retained authority with signed, nonce-bound snapshots.

    The state path is the single authority namespace.  It is intentionally not
    a cache: malformed, missing-after-initialization, rolled-back, or aliased
    state fails closed instead of being repaired or reconstructed.
    """

    def __init__(self, *, state_path: str | Path, evidence: DeploymentAuthorityEvidence,
                 signing_key: Ed25519PrivateKey,
                 snapshot_factory: Callable[..., Any], trusted_clock: Callable[[], datetime],
                 max_age_seconds: int = 60) -> None:
        if (not isinstance(signing_key, Ed25519PrivateKey) or not callable(snapshot_factory)
                or not callable(trusted_clock)):
            raise DeploymentAuthorityError("deployment authority signer, snapshot factory, or trusted clock is invalid")
        if type(max_age_seconds) is not int or not 0 < max_age_seconds <= 300:
            raise DeploymentAuthorityError("deployment authority receipt lifetime is invalid")
        actual = sha256(signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
        if actual != evidence.public_key_fingerprint:
            raise DeploymentAuthorityError("deployment authority signing key does not match evidence")
        original_state_path = Path(state_path)
        if not original_state_path.is_absolute() or original_state_path.name in {"", ".", ".."}:
            raise DeploymentAuthorityError("retained authority state path must be absolute and concrete")
        self._reject_path_alias(original_state_path, "retained authority state")
        self._state_path = original_state_path.resolve(strict=False)
        self._evidence, self._key = evidence, signing_key
        self._snapshot_factory, self._trusted_clock, self._max_age = snapshot_factory, trusted_clock, max_age_seconds
        self._last_revision = -1
        self._anchor: tuple[int, str] | None = None

    @staticmethod
    def _reject_path_alias(path: Path, label: str) -> None:
        """Inspect the caller spelling before resolve can erase a symlink hop."""
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise DeploymentAuthorityError(f"{label} alias is forbidden")

    @property
    def identity(self) -> str: return self._evidence.identity

    @property
    def endpoint(self) -> str: return self._evidence.endpoint

    @property
    def policy_id(self) -> str: return self._evidence.policy_id

    @property
    def public_key(self) -> Ed25519PublicKey: return self._key.public_key()

    @property
    def _lock_path(self) -> Path:
        return self._state_path.with_suffix(self._state_path.suffix + ".lock")

    @staticmethod
    def _instant(value: Any) -> datetime:
        if not isinstance(value, str): raise DeploymentAuthorityError("evidence timestamp is invalid")
        try: instant = _DATETIME.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc: raise DeploymentAuthorityError("evidence timestamp is invalid") from exc
        if instant.tzinfo is None: raise DeploymentAuthorityError("evidence timestamp is invalid")
        return instant.astimezone(timezone.utc)

    def _trusted_now(self) -> datetime:
        """Read only the deployment-provided authority clock, never host time."""
        try:
            value = self._trusted_clock()
        except Exception as exc:
            raise DeploymentAuthorityError("trusted authority clock is unavailable") from exc
        if (not isinstance(value, _DATETIME) or value.tzinfo is not timezone.utc
                or value.utcoffset() != timedelta(0)):
            raise DeploymentAuthorityError("trusted authority clock must return canonical UTC")
        return value

    def verify_deployment_evidence(self, evidence: Mapping[str, Any], *, measurement_binding: str) -> None:
        """Verify the closed deployment attestation before any local mutation."""
        required = {"evidence_version", "identity", "endpoint", "policy_id", "public_key_fingerprint", "measurement_binding", "authority_revision", "authority_root", "issued_at", "expires_at", "signature"}
        if not isinstance(evidence, Mapping) or set(evidence) != required or evidence.get("evidence_version") != EVIDENCE_SCHEMA:
            raise DeploymentAuthorityError("deployment authority evidence schema is invalid")
        if (evidence.get("identity"), evidence.get("endpoint"), evidence.get("policy_id"), evidence.get("public_key_fingerprint"), evidence.get("measurement_binding")) != (
                self.identity, self.endpoint, self.policy_id, self._evidence.public_key_fingerprint, measurement_binding) or measurement_binding != self._evidence.measurement_binding:
            raise DeploymentAuthorityError("deployment authority evidence pins or binding are invalid")
        if type(evidence.get("authority_revision")) is not int or evidence["authority_revision"] < 0 or not _digest(evidence.get("authority_root")):
            raise DeploymentAuthorityError("deployment authority evidence head is invalid")
        now = self._trusted_now()
        issued, expires = self._instant(evidence["issued_at"]), self._instant(evidence["expires_at"])
        if expires <= issued or now < issued or now >= expires or expires - issued > timedelta(minutes=5):
            raise DeploymentAuthorityError("deployment authority evidence is stale")
        try:
            signature = bytes.fromhex(evidence["signature"])
            self.public_key.verify(signature, canonical_ledger_bytes(EVIDENCE_SCHEMA, {key: evidence[key] for key in required - {"signature"}}))
        except Exception as exc:
            # InvalidSignature intentionally shares the fail-closed public error.
            if isinstance(exc, DeploymentAuthorityError): raise
            raise DeploymentAuthorityError("deployment authority evidence signature is invalid") from exc
        expected = (evidence["authority_revision"], evidence["authority_root"])
        try:
            events = self._read(create=False)
        except DeploymentAuthorityError as exc:
            if "missing" not in str(exc) or expected != (0, _receipt_root([])):
                raise
            events = []
        actual = (len(events), _receipt_root(events))
        if actual != expected:
            raise DeploymentAuthorityError("deployment authority evidence head does not match retained state")
        self._anchor = expected

    def _locked(self):
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (self._state_path.parent, *self._state_path.parent.parents):
            if parent.exists() and parent.is_symlink():
                raise DeploymentAuthorityError("retained authority parent alias is forbidden")
        try:
            descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DeploymentAuthorityError("retained authority lock is not a private regular file")
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "r+")
        except OSError as exc:
            raise DeploymentAuthorityError("retained authority lock alias is forbidden") from exc
        class _Lock:
            def __enter__(_self): fcntl.flock(handle.fileno(), fcntl.LOCK_EX); return _self
            def __exit__(_self, *unused): fcntl.flock(handle.fileno(), fcntl.LOCK_UN); handle.close()
        return _Lock()

    def _state_body(self, events: list[dict[str, Any]]) -> dict[str, Any]:
        return {"schema": STATE_SCHEMA, "measurement_binding": self._evidence.measurement_binding,
                "revision": len(events), "root": _receipt_root(events),
                "signer_fingerprint": self._evidence.public_key_fingerprint, "events": events}

    def _read(self, *, create: bool) -> list[dict[str, Any]]:
        try:
            descriptor = os.open(self._state_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if not create:
                raise DeploymentAuthorityError("retained authority state is missing")
            self._write([])
            return []
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise DeploymentAuthorityError("retained authority state is not a private regular file")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 65536):
                chunks.append(chunk)
            raw = b"".join(chunks)
            value = json.loads(raw)
            if _state_bytes(value) != raw:
                raise DeploymentAuthorityError("retained authority state is noncanonical")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DeploymentAuthorityError("retained authority state is unreadable") from exc
        finally:
            os.close(descriptor)
        expected = {"schema", "measurement_binding", "revision", "root", "signer_fingerprint", "events", "signature"}
        if not isinstance(value, dict) or set(value) != expected or value.get("schema") != STATE_SCHEMA:
            raise DeploymentAuthorityError("retained authority state schema is invalid")
        if (value.get("measurement_binding") != self._evidence.measurement_binding
                or value.get("signer_fingerprint") != self._evidence.public_key_fingerprint
                or not isinstance(value["events"], list) or type(value.get("revision")) is not int
                or value["revision"] != len(value["events"]) or value.get("root") != _receipt_root(value["events"])):
            raise DeploymentAuthorityError("retained authority state binding is invalid")
        events = value["events"]
        if not all(isinstance(event, dict) for event in events):
            raise DeploymentAuthorityError("retained authority events are invalid")
        try:
            self.public_key.verify(bytes.fromhex(value["signature"]), canonical_ledger_bytes(STATE_SCHEMA, self._state_body(events)))
        except (InvalidSignature, ValueError, TypeError) as exc:
            raise DeploymentAuthorityError("retained authority state signature is invalid") from exc
        if len(events) < self._last_revision:
            raise DeploymentAuthorityError("retained authority rollback detected")
        self._last_revision = len(events)
        return events

    def _write(self, events: list[dict[str, Any]]) -> None:
        body = self._state_body(events)
        body["signature"] = self._key.sign(canonical_ledger_bytes(STATE_SCHEMA, body)).hex()
        payload = _state_bytes(body)
        descriptor, temporary = tempfile.mkstemp(prefix=self._state_path.name + ".", dir=self._state_path.parent)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0: raise OSError("short retained authority write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor); descriptor = -1
            if self._state_path.exists() and self._state_path.is_symlink():
                raise DeploymentAuthorityError("retained authority state alias is forbidden")
            os.replace(temporary, self._state_path)
            directory = os.open(self._state_path.parent, os.O_RDONLY)
            try: os.fsync(directory)
            finally: os.close(directory)
        except OSError as exc:
            raise DeploymentAuthorityError("retained authority state cannot be committed") from exc
        finally:
            if descriptor >= 0: os.close(descriptor)
            try: os.unlink(temporary)
            except FileNotFoundError: pass

    def _signed_snapshot(self, *, events: list[dict[str, Any]], request_nonce: str,
                         issued_at: datetime) -> Any:
        if not isinstance(request_nonce, str) or len(request_nonce) < 32:
            raise DeploymentAuthorityError("authority request nonce is invalid")
        payload = {
            "identity": self.identity, "endpoint": self.endpoint, "policy_id": self.policy_id,
            "public_key_fingerprint": self._evidence.public_key_fingerprint,
            "revision": len(events), "root": _receipt_root(events), "request_nonce": request_nonce,
            "issued_at": _stamp(issued_at),
            "expires_at": _stamp(issued_at + timedelta(seconds=self._max_age)),
            "events": tuple(events),
        }
        signature = self._key.sign(canonical_ledger_bytes(AUTHORITY_DOMAIN, payload)).hex()
        try:
            snapshot = self._snapshot_factory(**payload, signature=signature)
            expected_payload = payload | {"events": [dict(event) for event in events]}
            if snapshot.payload() != expected_payload or snapshot.signature != signature:
                raise ValueError("factory receipt does not preserve the signed payload")
        except Exception as exc:
            raise DeploymentAuthorityError("deployment authority snapshot factory is invalid") from exc
        return snapshot

    def _read_at_anchor(self) -> tuple[list[dict[str, Any]], bool]:
        """Read the pinned head without creating a state file as a side effect."""
        try:
            return self._read(create=False), False
        except DeploymentAuthorityError as exc:
            if "missing" not in str(exc) or self._anchor != (0, _receipt_root([])):
                raise
            return [], True

    def snapshot(self, *, request_nonce: str) -> Any:
        with self._locked():
            if self._anchor is None: raise DeploymentAuthorityError("verified deployment evidence is required")
            events, missing = self._read_at_anchor()
            if (len(events), _receipt_root(events)) != self._anchor: raise DeploymentAuthorityError("retained authority head changed after evidence verification")
            snapshot = self._signed_snapshot(events=events, request_nonce=request_nonce,
                                             issued_at=self._trusted_now())
            if missing:
                self._write([])
            return snapshot

    def compare_and_advance(self, *, expected_revision: int, event: Mapping[str, Any], request_nonce: str) -> Any:
        if type(expected_revision) is not int or expected_revision < 0 or not isinstance(event, Mapping):
            raise DeploymentAuthorityError("authority advance request is invalid")
        with self._locked():
            if self._anchor is None: raise DeploymentAuthorityError("verified deployment evidence is required")
            events, _ = self._read_at_anchor()
            if (len(events), _receipt_root(events)) != self._anchor: raise DeploymentAuthorityError("retained authority head changed after evidence verification")
            if expected_revision != len(events):
                raise DeploymentAuthorityError("authority revision conflict")
            if "recorded_at" in event:
                raise DeploymentAuthorityError("authority event timestamp is reserved")
            issued_at = self._trusted_now()
            next_events = [*events, dict(event) | {"recorded_at": _stamp(issued_at)}]
            snapshot = self._signed_snapshot(events=next_events, request_nonce=request_nonce,
                                             issued_at=issued_at)
            self._write(next_events)
            self._last_revision = len(next_events)
            self._anchor = (len(next_events), _receipt_root(next_events))
            return snapshot


def write_live_operation_denial_receipt(*, path: str | Path,
                                        authority: DeploymentMonotonicAppendAuthority,
                                        operation: str) -> dict[str, Any]:
    """Persist a closed, hash-bound receipt without raw event data or secrets."""
    if operation not in {"init", "status", "append", "verify"}:
        raise DeploymentAuthorityError("receipt operation is invalid")
    snapshot = authority.snapshot(request_nonce=token_hex(32))
    receipt = {
        "receipt_version": RECEIPT_SCHEMA, "identity": authority.identity,
        "endpoint": authority.endpoint, "policy_id": authority.policy_id,
        "public_key_fingerprint": authority._evidence.public_key_fingerprint,
        "measurement_binding": authority._evidence.measurement_binding,
        "authority_revision": str(snapshot.revision), "authority_root": snapshot.root,
        "operation": operation, "live_operation_authorized": False,
    }
    receipt["receipt_digest"] = sha256(canonical_ledger_bytes(RECEIPT_SCHEMA, receipt)).hexdigest()
    payload = _state_bytes(receipt)
    original_receipt_path = Path(path)
    if not original_receipt_path.is_absolute():
        raise DeploymentAuthorityError("receipt path must be absolute")
    DeploymentMonotonicAppendAuthority._reject_path_alias(original_receipt_path, "receipt")
    receipt_path = original_receipt_path.resolve(strict=False)
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=receipt_path.name + ".", dir=receipt_path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0: raise OSError("short receipt write")
            offset += written
        os.fsync(descriptor); os.close(descriptor); descriptor = -1
        os.link(temporary, receipt_path)  # atomic create-only; collision never overwrites a receipt
        directory = os.open(receipt_path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except OSError as exc:
        raise DeploymentAuthorityError("authorization receipt cannot be committed") from exc
    finally:
        if descriptor >= 0: os.close(descriptor)
        try: os.unlink(temporary)
        except FileNotFoundError: pass
    return receipt


__all__ = ["DeploymentAuthorityError", "DeploymentAuthorityEvidence", "DeploymentMonotonicAppendAuthority", "EVIDENCE_SCHEMA", "write_live_operation_denial_receipt"]
