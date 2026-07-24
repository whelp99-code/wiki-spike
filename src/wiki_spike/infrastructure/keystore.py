"""Dual create-only key custody for the Encrypted Single-Memory Lifecycle
(Gate 2 slice).

Implements ADR-0027 §2 (dual create-only custody) and §3 (binding-aware
reconciliation partition) at the storage layer: two independent create-only
key stores (``PlatformKeyStore`` / ``RecoveryKeyStore``) that never overwrite
an existing entry, an authenticated-readback "prove usability without
leaking the key" challenge, forward-only destroy with a signed absence
receipt, an ``ArkKeyIntentState`` enum + forward-only transition helper
mirroring ``schemas/encrypted-lifecycle/ark-key-intent-v1.schema.json``, and
a binding-aware reconciliation classifier that never destroys an
ACTIVE-bound or metadata-mismatched key.

Architecture-boundary contract: this module (part of the ``infrastructure``
layer) may import ``wiki_spike.memory_core`` and
``wiki_spike.infrastructure.crypto`` only; it must never import
``wiki_spike.memory_runtime``, ``wiki_spike.applications``,
``wiki_spike.connectors``, ``wiki_spike.ui``, or the legacy storage modules.

Production Keychain binding is a later concern. For this Gate 2 slice both
custodians persist to a caller-provided directory as opaque files keyed by
an opaque ``(namespace, ark_handle)`` pair; the create-only / readback /
inventory / destroy CONTRACT implemented here is what later slices bind to
a real platform Keychain and a real separate recovery keystore.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Protocol

from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class KeyStoreError(Exception):
    """Base class for all keystore errors."""


class KeyAlreadyExists(KeyStoreError):
    """Raised when ``create_only`` targets a handle whose stored metadata
    digest matches the requesting intent but whose wrapped key material
    differs — an attempted in-place overwrite of already-claimed key
    material, which create-only custody never permits."""


class KeyCollision(KeyStoreError):
    """Raised when ``create_only`` targets a handle already claimed by a
    different intent (stored metadata digest does not bind the requesting
    intent)."""


class KeyNotFound(KeyStoreError):
    """Raised when an operation targets a handle that was never created."""


class KeyDestroyed(KeyStoreError):
    """Raised when a readback challenge is attempted against a handle whose
    key material has already been destroyed."""


class KeyAlreadyDestroyed(KeyStoreError):
    """Raised when ``create_only`` targets a handle that has already been
    forward-only destroyed. A destroyed key is never recreated."""


class InvalidStateTransition(KeyStoreError):
    """Raised when an ``ArkKeyIntentState`` transition is not forward-only
    per the schema-defined lifecycle."""


class KeyStoreCorrupt(KeyStoreError):
    """Raised when a stored custody entry file cannot be parsed as the
    expected JSON object (torn/truncated write, corrupted bytes, or a
    parsed object missing required custody keys). Fail-closed: a custody
    authority never treats an unreadable entry as absent or as
    best-effort ignorable."""


# ---------------------------------------------------------------------------
# ARK key-intent lifecycle states (schemas/encrypted-lifecycle/
# ark-key-intent-v1.schema.json) + forward-only transition helper.
# ---------------------------------------------------------------------------


class ArkKeyIntentState(str, Enum):
    KEY_INTENT_PREPARED = "KEY_INTENT_PREPARED"
    PLATFORM_KEY_VERIFIED = "PLATFORM_KEY_VERIFIED"
    RECOVERY_KEY_VERIFIED = "RECOVERY_KEY_VERIFIED"
    CAS_MATERIALIZED = "CAS_MATERIALIZED"
    ACTIVE = "ACTIVE"
    ORPHAN_PENDING_DESTROY = "ORPHAN_PENDING_DESTROY"
    ORPHAN_DESTROYED = "ORPHAN_DESTROYED"
    QUARANTINED = "QUARANTINED"


# Linear happy-path sequence (ADR-0027 §2):
#   PREPARED -> platform create/readback -> recovery create/readback
#   -> CAS materialization -> final SQLite ACTIVE election
# plus the forward-only destroy tail, and QUARANTINED reachable from any
# non-terminal state (fail-closed reconciliation never optimistically
# completes). ORPHAN_DESTROYED and QUARANTINED are terminal.
_HAPPY_PATH_ORDER: tuple[ArkKeyIntentState, ...] = (
    ArkKeyIntentState.KEY_INTENT_PREPARED,
    ArkKeyIntentState.PLATFORM_KEY_VERIFIED,
    ArkKeyIntentState.RECOVERY_KEY_VERIFIED,
    ArkKeyIntentState.CAS_MATERIALIZED,
    ArkKeyIntentState.ACTIVE,
    ArkKeyIntentState.ORPHAN_PENDING_DESTROY,
    ArkKeyIntentState.ORPHAN_DESTROYED,
)

ALLOWED_TRANSITIONS: dict[ArkKeyIntentState, frozenset[ArkKeyIntentState]] = {}
for _idx, _state in enumerate(_HAPPY_PATH_ORDER):
    _next = set(_HAPPY_PATH_ORDER[_idx + 1 : _idx + 2])
    if _state not in (ArkKeyIntentState.ORPHAN_DESTROYED,):
        _next.add(ArkKeyIntentState.QUARANTINED)
    ALLOWED_TRANSITIONS[_state] = frozenset(_next)
ALLOWED_TRANSITIONS[ArkKeyIntentState.ORPHAN_DESTROYED] = frozenset()
ALLOWED_TRANSITIONS[ArkKeyIntentState.QUARANTINED] = frozenset()


def transition(current: ArkKeyIntentState, target: ArkKeyIntentState) -> ArkKeyIntentState:
    """Validate and return ``target`` if it is a forward-only successor of
    ``current``; raise ``InvalidStateTransition`` otherwise. Terminal states
    (``ORPHAN_DESTROYED``, ``QUARANTINED``) have no successors — the
    forward-only guarantee that a destroyed key is never recreated and a
    quarantined intent is never optimistically resumed."""
    allowed = ALLOWED_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidStateTransition(
            f"cannot transition ARK key intent from {current.value} to {target.value}"
        )
    return target


# ---------------------------------------------------------------------------
# Readback / absence receipts.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReadbackReceipt:
    """Proof that a custodian's stored key material is usable, obtained by
    sealing and immediately unsealing a synthetic in-memory challenge. Never
    carries the key, the wrapped key material, or the challenge plaintext."""

    namespace: str
    ark_handle: str
    metadata_digest: str
    receipt_digest: str
    verified: bool

    def to_mapping(self) -> dict:
        return {
            "namespace": self.namespace,
            "ark_handle": self.ark_handle,
            "metadata_digest": self.metadata_digest,
            "receipt_digest": self.receipt_digest,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class AbsenceReceipt:
    """Append-only proof that a handle's key material has been destroyed."""

    namespace: str
    ark_handle: str
    prior_metadata_digest: str
    destroyed_at: str
    receipt_digest: str

    def to_mapping(self) -> dict:
        return {
            "namespace": self.namespace,
            "ark_handle": self.ark_handle,
            "prior_metadata_digest": self.prior_metadata_digest,
            "destroyed_at": self.destroyed_at,
            "receipt_digest": self.receipt_digest,
        }


@dataclass(frozen=True)
class InventoryEntry:
    namespace: str
    ark_handle: str
    metadata_digest: str
    destroyed: bool


@dataclass(frozen=True)
class CreateOnlyResult:
    created: bool
    already_exists: bool


# ---------------------------------------------------------------------------
# KeyStore protocol.
# ---------------------------------------------------------------------------


class KeyStore(Protocol):
    def create_only(
        self, namespace: str, ark_handle: str, wrapped_dek_hex: str, metadata_digest: str
    ) -> CreateOnlyResult: ...

    def readback_challenge(self, namespace: str, ark_handle: str) -> ReadbackReceipt: ...

    def inventory(self, namespace: str) -> list[InventoryEntry]: ...

    def destroy(self, namespace: str, ark_handle: str) -> AbsenceReceipt: ...


# ---------------------------------------------------------------------------
# File-backed create-only base implementation.
# ---------------------------------------------------------------------------

_SAFE_HANDLE_RE = re.compile(r"^[A-Za-z0-9._:-]{1,256}$")


def _validate_opaque(name: str, value: str) -> None:
    if not value or not _SAFE_HANDLE_RE.fullmatch(value):
        raise ValueError(f"invalid {name}: {value!r}")


def _entry_path(root: Path, namespace: str, ark_handle: str) -> Path:
    key = f"{namespace}\x00{ark_handle}".encode("utf-8")
    filename = hashlib.sha256(key).hexdigest() + ".json"
    return root / filename


class CreateOnlyKeyStore:
    """Shared create-only custody logic for a single custodian. Two
    independent instances (one per custodian) MUST use two independent
    directories so that neither custodian's storage is derived from or
    shared with the other (ADR-0027 §2: "never derived from one custodian
    by the other")."""

    def __init__(self, root_dir: str | Path, custodian_label: str) -> None:
        self.root_dir = Path(root_dir)
        self.custodian_label = custodian_label
        self.root_dir.mkdir(parents=True, exist_ok=True)

    # -- persistence -------------------------------------------------

    _REQUIRED_RECORD_KEYS = (
        "namespace",
        "ark_handle",
        "wrapped_dek_hex",
        "metadata_digest",
        "destroyed",
    )

    @classmethod
    def _parse_record(cls, path: Path, raw: str) -> dict:
        try:
            record = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise KeyStoreCorrupt(
                f"custody entry {path} is not valid JSON (torn or corrupted write): {exc}"
            ) from exc
        if not isinstance(record, dict) or not all(
            key in record for key in cls._REQUIRED_RECORD_KEYS
        ):
            raise KeyStoreCorrupt(
                f"custody entry {path} is missing required custody keys "
                f"{cls._REQUIRED_RECORD_KEYS}"
            )
        return record

    def _load(self, namespace: str, ark_handle: str) -> Optional[dict]:
        path = _entry_path(self.root_dir, namespace, ark_handle)
        if not path.exists():
            return None
        return self._parse_record(path, path.read_text(encoding="utf-8"))

    def _save(self, namespace: str, ark_handle: str, record: dict) -> None:
        path = _entry_path(self.root_dir, namespace, ark_handle)
        payload = json.dumps(record, sort_keys=True)
        tmp_path = path.with_name(f"{path.name}.tmp-{uuid.uuid4().hex}")
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, path)
        except BaseException:
            tmp_path.unlink(missing_ok=True)
            raise

    # -- KeyStore protocol --------------------------------------------

    def create_only(
        self, namespace: str, ark_handle: str, wrapped_dek_hex: str, metadata_digest: str
    ) -> CreateOnlyResult:
        _validate_opaque("namespace", namespace)
        _validate_opaque("ark_handle", ark_handle)
        existing = self._load(namespace, ark_handle)
        if existing is None:
            record = {
                "namespace": namespace,
                "ark_handle": ark_handle,
                "custodian": self.custodian_label,
                "wrapped_dek_hex": wrapped_dek_hex,
                "metadata_digest": metadata_digest,
                "destroyed": False,
                "created_at": _now_ts(),
            }
            self._save(namespace, ark_handle, record)
            return CreateOnlyResult(created=True, already_exists=False)

        if existing["destroyed"]:
            raise KeyAlreadyDestroyed(
                f"handle {ark_handle!r} in namespace {namespace!r} was already destroyed; "
                "forward-only custody never recreates a destroyed key"
            )

        if existing["metadata_digest"] != metadata_digest:
            raise KeyCollision(
                f"handle {ark_handle!r} in namespace {namespace!r} is already claimed by a "
                "different key intent (metadata digest mismatch)"
            )

        if existing["wrapped_dek_hex"] != wrapped_dek_hex:
            raise KeyAlreadyExists(
                f"handle {ark_handle!r} in namespace {namespace!r} already exists; "
                "create-only custody never overwrites key material in place"
            )

        # Exact re-create of an identical intent: idempotent accept.
        return CreateOnlyResult(created=False, already_exists=True)

    def readback_challenge(self, namespace: str, ark_handle: str) -> ReadbackReceipt:
        record = self._load(namespace, ark_handle)
        if record is None:
            raise KeyNotFound(f"no key at namespace={namespace!r} ark_handle={ark_handle!r}")
        if record["destroyed"]:
            raise KeyDestroyed(
                f"handle {ark_handle!r} in namespace {namespace!r} was destroyed; "
                "unwrap is expected to fail"
            )

        dek = bytes.fromhex(record["wrapped_dek_hex"])
        aad = record["metadata_digest"].encode("ascii")
        nonce_hex = os.urandom(12).hex()
        challenge_plaintext = os.urandom(32)
        ciphertext_hex, tag_hex = crypto.aes_gcm_seal(dek, nonce_hex, challenge_plaintext, aad=aad)
        recovered = crypto.aes_gcm_open(dek, nonce_hex, ciphertext_hex, tag_hex, aad=aad)
        verified = recovered == challenge_plaintext

        receipt_digest = hashlib.sha256(
            canonical_bytes(
                {
                    "namespace": namespace,
                    "ark_handle": ark_handle,
                    "metadata_digest": record["metadata_digest"],
                    "nonce_hex": nonce_hex,
                    "ciphertext_hex": ciphertext_hex,
                    "tag_hex": tag_hex,
                    "verified": verified,
                }
            )
        ).hexdigest()
        return ReadbackReceipt(
            namespace=namespace,
            ark_handle=ark_handle,
            metadata_digest=record["metadata_digest"],
            receipt_digest=receipt_digest,
            verified=verified,
        )

    def inventory(self, namespace: str) -> list[InventoryEntry]:
        entries: list[InventoryEntry] = []
        for path in sorted(self.root_dir.glob("*.json")):
            record = self._parse_record(path, path.read_text(encoding="utf-8"))
            if record["namespace"] != namespace:
                continue
            entries.append(
                InventoryEntry(
                    namespace=record["namespace"],
                    ark_handle=record["ark_handle"],
                    metadata_digest=record["metadata_digest"],
                    destroyed=record["destroyed"],
                )
            )
        return entries

    def destroy(self, namespace: str, ark_handle: str) -> AbsenceReceipt:
        record = self._load(namespace, ark_handle)
        if record is None:
            raise KeyNotFound(f"no key at namespace={namespace!r} ark_handle={ark_handle!r}")

        if record["destroyed"]:
            # Idempotent forward-only cleanup: return the same absence
            # receipt again rather than performing (or claiming) another
            # destroy operation.
            return AbsenceReceipt(
                namespace=record["namespace"],
                ark_handle=record["ark_handle"],
                prior_metadata_digest=record["metadata_digest"],
                destroyed_at=record["destroyed_at"],
                receipt_digest=record["absence_receipt_digest"],
            )

        destroyed_at = _now_ts()
        prior_metadata_digest = record["metadata_digest"]
        receipt_digest = hashlib.sha256(
            canonical_bytes(
                {
                    "namespace": namespace,
                    "ark_handle": ark_handle,
                    "prior_metadata_digest": prior_metadata_digest,
                    "destroyed_at": destroyed_at,
                }
            )
        ).hexdigest()

        record["destroyed"] = True
        record["wrapped_dek_hex"] = ""
        record["destroyed_at"] = destroyed_at
        record["absence_receipt_digest"] = receipt_digest
        self._save(namespace, ark_handle, record)

        return AbsenceReceipt(
            namespace=namespace,
            ark_handle=ark_handle,
            prior_metadata_digest=prior_metadata_digest,
            destroyed_at=destroyed_at,
            receipt_digest=receipt_digest,
        )


def _now_ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class PlatformKeyStore(CreateOnlyKeyStore):
    """Platform Keychain-analog custodian (Gate 2: file-backed opaque
    store). Production Keychain binding is a later concern."""

    def __init__(self, root_dir: str | Path) -> None:
        super().__init__(root_dir, custodian_label="platform")


class RecoveryKeyStore(CreateOnlyKeyStore):
    """Independent recovery custodian (Gate 2: file-backed opaque store),
    physically separate from the platform custodian's directory."""

    def __init__(self, root_dir: str | Path) -> None:
        super().__init__(root_dir, custodian_label="recovery")


# ---------------------------------------------------------------------------
# Binding-aware reconciliation partition (ADR-0027 §3, simplified to the
# three outcomes this Gate 2 slice's callers act on).
# ---------------------------------------------------------------------------


class BindingStatus(str, Enum):
    ACTIVE = "ACTIVE"
    PREPARED = "PREPARED"
    UNBOUND = "UNBOUND"
    LOSER = "LOSER"
    EXPIRED = "EXPIRED"


@dataclass(frozen=True)
class BindingRecord:
    """A DB-known binding for an external key handle."""

    status: BindingStatus
    metadata_digest: str


@dataclass(frozen=True)
class ExternalKeyRecord:
    """An externally observed key custody entry (e.g. keystore inventory
    row) being reconciled against DB-known bindings."""

    metadata_digest: Optional[str]
    corrupt: bool = False


class ReconciliationOutcome(str, Enum):
    DESTROY_UNBOUND = "DESTROY_UNBOUND"
    RESUME_EXACT = "RESUME_EXACT"
    QUARANTINE_UNKNOWN = "QUARANTINE_UNKNOWN"


_DESTROYABLE_STATUSES = frozenset(
    {BindingStatus.UNBOUND, BindingStatus.LOSER, BindingStatus.EXPIRED}
)


def classify_for_reconciliation(
    binding: Optional[BindingRecord],
    external: Optional[ExternalKeyRecord],
    *,
    non_membership_verified: bool = False,
) -> ReconciliationOutcome:
    """Classify a single external key handle for reconciliation.

    The invariant (ADR-0027 §3) is unconditional: only unbound, losing, or
    expired artifacts are ever destroyed; anything currently ACTIVE-bound,
    anything whose metadata disagrees with the DB-known binding, and
    anything missing or corrupt is never destroyed — it is quarantined
    instead. Fail-closed: any ambiguity resolves to ``QUARANTINE_UNKNOWN``,
    never to a destroy or resume decision.

    When ``binding is None`` (no DB-known binding), ``non_membership_verified``
    must be ``True`` — backed by a signed binding-registry non-membership
    proof — before ``DESTROY_UNBOUND`` is emitted; otherwise the absence
    may reflect a stale/corrupt DB cache and the key is quarantined.
    """
    if external is None or external.corrupt or external.metadata_digest is None:
        return ReconciliationOutcome.QUARANTINE_UNKNOWN

    if binding is None:
        if non_membership_verified:
            return ReconciliationOutcome.DESTROY_UNBOUND
        return ReconciliationOutcome.QUARANTINE_UNKNOWN

    if binding.status in _DESTROYABLE_STATUSES:
        return ReconciliationOutcome.DESTROY_UNBOUND

    # binding.status is ACTIVE or PREPARED from here on: never destroyable.
    if external.metadata_digest == binding.metadata_digest:
        return ReconciliationOutcome.RESUME_EXACT

    # Metadata mismatch against an ACTIVE/PREPARED binding: fail closed.
    return ReconciliationOutcome.QUARANTINE_UNKNOWN


def reconcile(
    bindings: Mapping[str, BindingRecord],
    external: Mapping[str, ExternalKeyRecord],
    *,
    non_membership_verified_handles: frozenset[str] | None = None,
) -> dict[str, ReconciliationOutcome]:
    """Classify every handle appearing in either ``bindings`` or
    ``external`` (their union), never destroying an ACTIVE-bound or
    mismatched key.  ``non_membership_verified_handles`` lists handles
    whose binding-registry non-membership was confirmed by a signed
    proof; handles absent from ``bindings`` but not in this set are
    quarantined rather than destroyed."""
    verified = non_membership_verified_handles or frozenset()
    all_handles = set(bindings) | set(external)
    return {
        handle: classify_for_reconciliation(
            bindings.get(handle), external.get(handle),
            non_membership_verified=handle in verified,
        )
        for handle in sorted(all_handles)
    }
