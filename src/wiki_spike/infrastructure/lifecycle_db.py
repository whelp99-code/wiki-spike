"""Encrypted-lifecycle SQLite unit-of-work (ADR-0026 / ADR-0027, Gate 2).

``LifecycleDatabase`` is a NEW, standalone SQLite database — distinct from the
legacy ``wiki_spike.controlplane.ControlPlane`` — that acts as the mutable
*cache* authority for the Encrypted Single-Memory Lifecycle (ADR-0026 §1,
"Fact authority matrix"). It is never a destroy or restore authority on its
own; the binding registry (out of scope for this module) is the sole
authority for destroy/restore classification. This module only persists the
control-plane row shapes SQLite is trusted to cache: command/candidate/object/
revision rows, ARK custody pointers, deletion phase, floor state, and a
body-free hash-chained event log.

Contract PRAGMAs (mirrored, not imported, from ``wiki_spike.controlplane``):
``journal_mode=WAL``, ``synchronous=FULL``, ``foreign_keys=ON``,
``busy_timeout=5000``, and every write transaction uses ``BEGIN IMMEDIATE``.

No plaintext columns exist anywhere in this schema. Every column is one of
exactly seven kinds, enforced by a name-suffix convention so the shape is
mechanically auditable (see ``COLUMN_KIND_ALLOWLIST`` and
:func:`assert_no_plaintext_columns`):

- **id**       — ``*_id`` / ``workspace_id`` / ``artifact_id`` / ... — opaque identifiers.
- **digest**   — ``*_digest`` / ``*_sha256`` — content digests (never bodies).
- **ref**      — ``*_ref`` — closed opaque references.
- **handle**   — ``*_handle`` — opaque external-provider handles.
- **state**    — ``*_state`` / ``*_kind`` / ``*_role`` / ``ordinal`` — closed
  enum/selector/ordinal values, never free text.
- **wrapped**  — ``*_hex`` — opaque wrapped-key/ciphertext/nonce bytes as hex.
- **ts**       — ``*_at`` — ISO-8601 timestamps.
- Two narrow numeric extensions of **id/digest** used verbatim by ADR-0027
  §5 (floor generation/checkpoint sequencing): ``*_generation``,
  ``*_sequence`` — always persisted as canonical decimal strings, never as
  JSON/SQLite numeric literals with locale or precision drift.

All numerics that are business data (generation counters, sequence numbers,
ordinals) are stored as TEXT canonical decimal strings, never INTEGER,
per the constraint that all numerics in the encrypted-lifecycle system are
canonical decimal strings (ADR-0026 context, memory_core.contracts.canonical_bytes
rejects raw JSON numeric tokens). The only INTEGER columns are SQLite
``AUTOINCREMENT`` surrogate rowids for the two append-only logs
(``event_log``, ``outbox``), mirroring the existing
``wiki_spike.controlplane.ControlPlane`` outbox pattern; those integers are
never business identity, only local monotonic ordering.

WAL checked-snapshot read linearization (ADR-0027 §9 / R9-3 / UF-3):
:meth:`LifecycleDatabase.checked_snapshot_read` is the *only* linearization
point for reads in this module. Under WAL, a deferred ``BEGIN`` transaction
captures a consistent point-in-time view atomically at the moment the first
statement inside it actually reads (SQLite's "the first read establishes the
snapshot" WAL semantics) through the transaction's ``COMMIT``/``ROLLBACK``.
There is no writer-fence or transaction-completion linearization point: a
snapshot read that observes state, after which a concurrent writer commits a
FORGET/delete, is a legitimate *pre-linearized* response — it reflects state
as of its own atomic acquisition and is never retroactively invalid.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from wiki_spike.memory_core.second_brain_capture_ports import AtomicCapturePersistencePort
import json

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.recovery import (
    AppliedDeletionOverlayEvidence,
    AppliedDeletionOverlayToken,
    VerifiedDeletionOverlay,
    SignedDeletionOverlay,
)
from wiki_spike.memory_core.second_brain_capture_contracts import (
    CapturePersistenceAggregateV1, CaptureItemReceiptV1,
)
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.crypto import aes_gcm_seal

# --------------------------------------------------------------------------- #
# Column-kind allowlist (no plaintext columns anywhere in this schema).
# --------------------------------------------------------------------------- #

COLUMN_KIND_ALLOWLIST: tuple[str, ...] = (
    "_id",
    "_digest",
    "_sha256",
    "_ref",
    "_handle",
    "_state",
    "_kind",
    "_role",
    "_hex",
    "_at",
    "_generation",
    "_sequence",
)
# A small number of columns are exact-name matches rather than suffix matches.
# Each is a body-free closed value: ``ordinal`` is a manifest ordinal;
# ``consent_epoch``, ``retention_epoch`` and ``revision_number`` are canonical
# decimal-string counters; ``sensitivity`` is a closed enum
# (PUBLIC/INTERNAL/CONFIDENTIAL/RESTRICTED). None carries plaintext.
COLUMN_KIND_EXACT_ALLOWLIST: tuple[str, ...] = (
    "ordinal",
    "consent_epoch",
    "retention_epoch",
    "revision_number",
    "sensitivity",
)


def is_allowed_column_name(name: str) -> bool:
    if name in COLUMN_KIND_EXACT_ALLOWLIST:
        return True
    return any(name.endswith(suffix) for suffix in COLUMN_KIND_ALLOWLIST)


# --------------------------------------------------------------------------- #
# Schema-of-record.
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS command (
  command_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  command_kind TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  command_state TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS canonical_artifact (
  artifact_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  artifact_kind TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  artifact_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, artifact_kind, revision_id)
);
-- Body-free subject/object identity binding (G4-CORRECTION-CONTINUITY).
-- Persists the digest-only identity needed to keep a correction under the
-- SAME logical object as its parent (logical-object continuity) and to
-- verify same-subject new consent -- without ever storing plaintext.
CREATE TABLE IF NOT EXISTS object_binding (
  artifact_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  logical_object_id TEXT NOT NULL,
  revision_id TEXT NOT NULL,
  subject_key_digest TEXT NOT NULL,
  project_id TEXT NOT NULL,
  object_kind TEXT NOT NULL,
  consent_epoch TEXT NOT NULL,
  revision_number TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS source_consent_state (
  workspace_id TEXT NOT NULL,
  source_ref_id TEXT NOT NULL,
  project_ref_id TEXT NOT NULL,
  consent_epoch TEXT NOT NULL,
  consent_state TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  consent_digest TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, source_ref_id, project_ref_id)
);
CREATE TABLE IF NOT EXISTS retention_policy (
  workspace_id TEXT NOT NULL,
  source_ref_id TEXT NOT NULL,
  project_ref_id TEXT NOT NULL,
  retention_epoch TEXT NOT NULL,
  retention_state TEXT NOT NULL,
  sensitivity TEXT NOT NULL,
  retention_digest TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (workspace_id, source_ref_id, project_ref_id)
);
CREATE TABLE IF NOT EXISTS command_artifact (
  command_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  artifact_role TEXT NOT NULL,
  ordinal TEXT NOT NULL,
  PRIMARY KEY (command_id, artifact_id),
  UNIQUE (command_id, artifact_role, ordinal),
  FOREIGN KEY (command_id) REFERENCES command(command_id),
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS ark_key_intent (
  intent_id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  custodian_role TEXT NOT NULL,
  intent_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS wrapped_key (
  wrapped_key_id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  custodian_role TEXT NOT NULL,
  wrapped_key_hex TEXT NOT NULL,
  nonce_hex TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS key_state (
  artifact_id TEXT PRIMARY KEY,
  custody_state TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS candidate_review (
  review_id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  reviewer_handle TEXT NOT NULL,
  review_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS floor_state (
  workspace_id TEXT PRIMARY KEY,
  stable_floor_generation TEXT NOT NULL,
  stable_checkpoint_id TEXT NOT NULL,
  attempt_state TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS deletion_state (
  deletion_id TEXT PRIMARY KEY,
  artifact_id TEXT NOT NULL,
  phase_state TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS recovery_deletion_overlay (
  overlay_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  manifest_id TEXT NOT NULL,
  overlay_sequence TEXT NOT NULL,
  previous_overlay_id TEXT,
  mapping_digest TEXT,
  signer_key_id TEXT NOT NULL,
  signed_at TEXT NOT NULL,
  overlay_state TEXT NOT NULL,
  UNIQUE (workspace_id, manifest_id, overlay_sequence)
);
CREATE TABLE IF NOT EXISTS recovery_deletion_veto (
  overlay_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  veto_state TEXT NOT NULL,
  PRIMARY KEY (overlay_id, artifact_id),
  FOREIGN KEY (overlay_id) REFERENCES recovery_deletion_overlay(overlay_id)
);
CREATE TABLE IF NOT EXISTS recovery_deletion_overlay_token (
  token_digest TEXT PRIMARY KEY,
  overlay_id TEXT NOT NULL,
  token_state TEXT NOT NULL,
  FOREIGN KEY (overlay_id) REFERENCES recovery_deletion_overlay(overlay_id)
);
CREATE TABLE IF NOT EXISTS source_deletion_recovery_map (
  map_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_ref_id TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  deletion_ref_id TEXT NOT NULL,
  recovery_proof_ref_id TEXT NOT NULL,
  overlay_sequence TEXT NOT NULL,
  bundle_head_digest TEXT NOT NULL,
  floor_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (workspace_id, source_ref_id, artifact_id, deletion_ref_id),
  FOREIGN KEY (artifact_id) REFERENCES canonical_artifact(artifact_id)
);
CREATE TABLE IF NOT EXISTS binding_leaf (
  leaf_id TEXT PRIMARY KEY,
  namespace_id TEXT NOT NULL,
  provider_handle TEXT NOT NULL,
  leaf_state TEXT NOT NULL,
  leaf_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS binding_checkpoint (
  checkpoint_id TEXT PRIMARY KEY,
  checkpoint_sha256 TEXT NOT NULL,
  checkpoint_sequence TEXT NOT NULL,
  history_root_digest TEXT NOT NULL,
  current_map_root_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS event_log (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  prev_digest TEXT,
  event_kind TEXT NOT NULL,
  ref_digest TEXT NOT NULL,
  event_digest TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS outbox (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_kind TEXT NOT NULL,
  ref_digest TEXT NOT NULL,
  outbox_state TEXT NOT NULL DEFAULT 'PENDING'
);
CREATE TABLE IF NOT EXISTS accepted_changeset (
  changeset_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  parent_generation_id TEXT,
  changes_root_digest TEXT NOT NULL,
  changeset_state TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS state_delta (
  delta_id TEXT PRIMARY KEY,
  changeset_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  object_kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  revision_id TEXT,
  expected_active_revision_id TEXT,
  envelope_ref_id TEXT,
  assertion_id TEXT,
  evidence_edge_id TEXT,
  evidence_fragment_ref_id TEXT,
  deletion_command_id TEXT,
  scope_digest TEXT,
  reason_state TEXT,
  FOREIGN KEY (changeset_id) REFERENCES accepted_changeset(changeset_id)
);
CREATE TABLE IF NOT EXISTS generation (
  generation_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  changeset_id TEXT NOT NULL,
  generation_state TEXT NOT NULL,
  binding_checkpoint_id TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY (changeset_id) REFERENCES accepted_changeset(changeset_id)
);
CREATE TABLE IF NOT EXISTS floor_candidate (
  attempt_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  candidate_kind TEXT NOT NULL,
  expected_old_floor_digest TEXT NOT NULL,
  expected_keychain_generation TEXT NOT NULL,
  candidate_floor_hex TEXT NOT NULL,
  candidate_floor_digest TEXT NOT NULL,
  challenge_sequence TEXT NOT NULL,
  nonce_digest TEXT NOT NULL,
  disposition_state TEXT NOT NULL,
  reason_state TEXT,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS freshness_serve_gate (
  workspace_id TEXT PRIMARY KEY,
  gate_state TEXT NOT NULL,
  stable_floor_generation TEXT NOT NULL,
  stable_checkpoint_id TEXT NOT NULL,
  source_candidate_digest TEXT NOT NULL,
  reason_state TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
"""

CAPTURE_SCHEMA = """
CREATE TABLE IF NOT EXISTS capture_scope (
  scope_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  scope_state TEXT NOT NULL,
  scope_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_receipt (
  capture_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  capture_sequence TEXT NOT NULL,
  receipt_state TEXT NOT NULL,
  receipt_digest TEXT NOT NULL,
  encrypted_content_ref TEXT NOT NULL,
  encrypted_native_mapping_ref TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_manifest (
  manifest_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  manifest_sequence TEXT NOT NULL,
  manifest_state TEXT NOT NULL,
  manifest_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_reconciliation (
  reconciliation_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  reconciliation_sequence TEXT NOT NULL,
  reconciliation_state TEXT NOT NULL,
  reconciliation_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_checkpoint (
  scope_id TEXT PRIMARY KEY,
  checkpoint_id TEXT NOT NULL,
  checkpoint_sequence TEXT NOT NULL,
  checkpoint_state TEXT NOT NULL,
  checkpoint_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_registration (
  registration_id TEXT PRIMARY KEY,
  scope_id TEXT NOT NULL,
  registration_sequence TEXT NOT NULL,
  registration_state TEXT NOT NULL,
  registration_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capture_cohort (
  cohort_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  cohort_state TEXT NOT NULL,
  cohort_digest TEXT NOT NULL,
  aggregate_handle TEXT NOT NULL
);
"""

# Tables in declaration order, used for both DDL introspection and the
# plaintext-column allowlist assertion.
TABLE_NAMES: tuple[str, ...] = (
    "command",
    "canonical_artifact",
    "object_binding",
    "command_artifact",
    "source_consent_state",
    "retention_policy",
    "ark_key_intent",
    "wrapped_key",
    "key_state",
    "candidate_review",
    "floor_state",
    "deletion_state",
    "recovery_deletion_overlay",
    "recovery_deletion_veto",
    "recovery_deletion_overlay_token",
    "source_deletion_recovery_map",
    "binding_leaf",
    "binding_checkpoint",
    "event_log",
    "outbox",
    "accepted_changeset",
    "state_delta",
    "generation",
    "floor_candidate",
    "freshness_serve_gate",
    "capture_scope",
    "capture_receipt",
    "capture_manifest",
    "capture_reconciliation",
    "capture_checkpoint",
    "migration_registration",
    "capture_cohort",
)

EVENT_LOG_DOMAIN = "wiki-spike.lifecycle-db.event-log.v1"


class LifecycleDbError(RuntimeError):
    """Base error for lifecycle-db invariant violations."""


class EventChainError(LifecycleDbError):
    """Raised when ``append_event`` is called with a stale/incorrect prev_digest."""


@dataclass(frozen=True)
class SnapshotResult:
    """An atomic as-of read captured at a single WAL checked-snapshot point.

    See the module docstring ("WAL checked-snapshot read linearization") for
    the exact linearization semantics this snapshot provides.
    """

    artifact_id: str
    artifact_state: str | None
    custody_state: str | None
    event_chain_head_digest: str | None


@dataclass(frozen=True)
class ServeSnapshotResult:
    """An atomic as-of read of ALL serve-gating state for one artifact, captured
    at a single WAL checked-snapshot point (ADR-0027 §9). A serve path (e.g. MCP
    ``memory_recall``/``memory_source``) makes its entire visibility decision --
    artifact present, custody state, deletion veto, freshness serve gate -- from
    this one snapshot, so a concurrent writer (e.g. a FORGET committing a veto)
    that lands after this acquisition can never retroactively change the
    decision; the response is a legitimate pre-linearized one.
    """

    artifact_id: str
    artifact_state: str | None
    custody_state: str | None
    deletion_phase_state: str | None
    serve_gate_state: str | None
    serve_gate_reason: str | None
    event_chain_head_digest: str | None


class UnitOfWork:
    """Typed insert/read helpers bound to one open ``BEGIN IMMEDIATE`` transaction.

    Every method issues parameterized SQL only — no string-formatted SQL is
    ever constructed from caller-supplied values.
    """

    def __init__(self, con: sqlite3.Connection) -> None:
        self._con = con

    # -- command / canonical_artifact / command_artifact -------------------- #

    def insert_command(
        self,
        command_id: str,
        workspace_id: str,
        command_kind: str,
        input_digest: str,
        command_state: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO command "
            "(command_id, workspace_id, command_kind, input_digest, command_state, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (command_id, workspace_id, command_kind, input_digest, command_state, created_at),
        )

    def insert_canonical_artifact(
        self,
        artifact_id: str,
        workspace_id: str,
        artifact_kind: str,
        revision_id: str,
        artifact_state: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO canonical_artifact "
            "(artifact_id, workspace_id, artifact_kind, revision_id, artifact_state, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (artifact_id, workspace_id, artifact_kind, revision_id, artifact_state, created_at),
        )

    def insert_command_artifact(
        self, command_id: str, artifact_id: str, artifact_role: str, ordinal: str
    ) -> None:
        self._con.execute(
            "INSERT INTO command_artifact (command_id, artifact_id, artifact_role, ordinal) "
            "VALUES (?,?,?,?)",
            (command_id, artifact_id, artifact_role, ordinal),
        )

    def get_command(self, command_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM command WHERE command_id=?", (command_id,)
        ).fetchone()

    def get_canonical_artifact(self, artifact_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM canonical_artifact WHERE artifact_id=?", (artifact_id,)
        ).fetchone()

    def list_command_artifacts(self, command_id: str) -> list[sqlite3.Row]:
        self._con.row_factory = sqlite3.Row
        return list(
            self._con.execute(
                "SELECT * FROM command_artifact WHERE command_id=? ORDER BY ordinal",
                (command_id,),
            )
        )

    # -- body-free subject/object identity binding (continuity) ------------- #

    def insert_object_binding(
        self,
        artifact_id: str,
        workspace_id: str,
        logical_object_id: str,
        revision_id: str,
        subject_key_digest: str,
        project_id: str,
        object_kind: str,
        consent_epoch: str,
        revision_number: str,
        sensitivity: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO object_binding "
            "(artifact_id, workspace_id, logical_object_id, revision_id, subject_key_digest, "
            " project_id, object_kind, consent_epoch, revision_number, sensitivity, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (artifact_id, workspace_id, logical_object_id, revision_id, subject_key_digest,
             project_id, object_kind, consent_epoch, revision_number, sensitivity, created_at),
        )

    def get_object_binding(self, artifact_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM object_binding WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
    # -- body-free source consent / retention policy ------------------------ #

    def upsert_source_consent_state(
        self,
        workspace_id: str,
        source_ref_id: str,
        project_ref_id: str,
        consent_epoch: str,
        consent_state: str,
        sensitivity: str,
        consent_digest: str,
        expires_at: str,
        updated_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO source_consent_state "
            "(workspace_id, source_ref_id, project_ref_id, consent_epoch, consent_state, sensitivity, "
            " consent_digest, expires_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(workspace_id, source_ref_id, project_ref_id) DO UPDATE SET "
            "consent_epoch=excluded.consent_epoch, consent_state=excluded.consent_state, "
            "sensitivity=excluded.sensitivity, consent_digest=excluded.consent_digest, "
            "expires_at=excluded.expires_at, updated_at=excluded.updated_at",
            (workspace_id, source_ref_id, project_ref_id, consent_epoch, consent_state, sensitivity,
             consent_digest, expires_at, updated_at),
        )

    def get_source_consent_state(
        self, workspace_id: str, source_ref_id: str, project_ref_id: str
    ) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM source_consent_state "
            "WHERE workspace_id=? AND source_ref_id=? AND project_ref_id=?",
            (workspace_id, source_ref_id, project_ref_id),
        ).fetchone()

    def upsert_retention_policy(
        self,
        workspace_id: str,
        source_ref_id: str,
        project_ref_id: str,
        retention_epoch: str,
        retention_state: str,
        sensitivity: str,
        retention_digest: str,
        expires_at: str,
        updated_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO retention_policy "
            "(workspace_id, source_ref_id, project_ref_id, retention_epoch, retention_state, sensitivity, "
            " retention_digest, expires_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(workspace_id, source_ref_id, project_ref_id) DO UPDATE SET "
            "retention_epoch=excluded.retention_epoch, retention_state=excluded.retention_state, "
            "sensitivity=excluded.sensitivity, retention_digest=excluded.retention_digest, "
            "expires_at=excluded.expires_at, updated_at=excluded.updated_at",
            (workspace_id, source_ref_id, project_ref_id, retention_epoch, retention_state, sensitivity,
             retention_digest, expires_at, updated_at),
        )

    def get_retention_policy(
        self, workspace_id: str, source_ref_id: str, project_ref_id: str
    ) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM retention_policy "
            "WHERE workspace_id=? AND source_ref_id=? AND project_ref_id=?",
            (workspace_id, source_ref_id, project_ref_id),
        ).fetchone()

    # -- ARK custody: ark_key_intent / wrapped_key / key_state -------------- #

    def insert_ark_key_intent(
        self, intent_id: str, artifact_id: str, custodian_role: str, intent_state: str, created_at: str
    ) -> None:
        self._con.execute(
            "INSERT INTO ark_key_intent "
            "(intent_id, artifact_id, custodian_role, intent_state, created_at) VALUES (?,?,?,?,?)",
            (intent_id, artifact_id, custodian_role, intent_state, created_at),
        )

    def insert_wrapped_key(
        self,
        wrapped_key_id: str,
        artifact_id: str,
        custodian_role: str,
        wrapped_key_hex: str,
        nonce_hex: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO wrapped_key "
            "(wrapped_key_id, artifact_id, custodian_role, wrapped_key_hex, nonce_hex, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (wrapped_key_id, artifact_id, custodian_role, wrapped_key_hex, nonce_hex, created_at),
        )

    def upsert_key_state(self, artifact_id: str, custody_state: str, updated_at: str) -> None:
        self._con.execute(
            "INSERT INTO key_state (artifact_id, custody_state, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(artifact_id) DO UPDATE SET custody_state=excluded.custody_state, "
            "updated_at=excluded.updated_at",
            (artifact_id, custody_state, updated_at),
        )

    def get_key_state(self, artifact_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM key_state WHERE artifact_id=?", (artifact_id,)
        ).fetchone()

    # -- review / floor / deletion ------------------------------------------ #

    def insert_candidate_review(
        self, review_id: str, artifact_id: str, reviewer_handle: str, review_state: str, created_at: str
    ) -> None:
        self._con.execute(
            "INSERT INTO candidate_review "
            "(review_id, artifact_id, reviewer_handle, review_state, created_at) VALUES (?,?,?,?,?)",
            (review_id, artifact_id, reviewer_handle, review_state, created_at),
        )

    def upsert_floor_state(
        self,
        workspace_id: str,
        stable_floor_generation: str,
        stable_checkpoint_id: str,
        attempt_state: str,
        updated_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO floor_state "
            "(workspace_id, stable_floor_generation, stable_checkpoint_id, attempt_state, updated_at) "
            "VALUES (?,?,?,?,?) "
            "ON CONFLICT(workspace_id) DO UPDATE SET "
            "stable_floor_generation=excluded.stable_floor_generation, "
            "stable_checkpoint_id=excluded.stable_checkpoint_id, "
            "attempt_state=excluded.attempt_state, updated_at=excluded.updated_at",
            (workspace_id, stable_floor_generation, stable_checkpoint_id, attempt_state, updated_at),
        )

    def get_floor_state(self, workspace_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM floor_state WHERE workspace_id=?", (workspace_id,)
        ).fetchone()

    def insert_deletion_state(
        self, deletion_id: str, artifact_id: str, phase_state: str, updated_at: str
    ) -> None:
        self._con.execute(
            "INSERT INTO deletion_state (deletion_id, artifact_id, phase_state, updated_at) "
            "VALUES (?,?,?,?)",
            (deletion_id, artifact_id, phase_state, updated_at),
        )

    def update_deletion_phase(self, deletion_id: str, phase_state: str, updated_at: str) -> None:
        self._con.execute(
            "UPDATE deletion_state SET phase_state=?, updated_at=? WHERE deletion_id=?",
            (phase_state, updated_at, deletion_id),
        )

    def get_deletion_state_by_artifact(self, artifact_id: str) -> "sqlite3.Row | None":
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM deletion_state WHERE artifact_id=? "
            "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
            (artifact_id,),
        ).fetchone()

    def persist_verified_recovery_deletion_overlay(
        self, overlay: VerifiedDeletionOverlay
    ) -> AppliedDeletionOverlayEvidence:
        """Atomically persist verified overlay metadata and its complete veto set."""
        signed = overlay.overlay
        deleted_artifact_refs = tuple(sorted(overlay.deleted_artifact_refs))
        self._con.row_factory = sqlite3.Row
        existing = self._con.execute(
            "SELECT * FROM recovery_deletion_overlay WHERE overlay_id=?", (signed.overlay_id,)
        ).fetchone()
        if existing is not None:
            if (
                existing["workspace_id"] != signed.workspace_id
                or existing["manifest_id"] != signed.manifest_id
                or existing["overlay_sequence"] != signed.sequence
                or existing["previous_overlay_id"] != signed.previous_overlay_id
                or existing["mapping_digest"] != signed.mapping_digest
                or existing["signer_key_id"] != signed.signer_key_id
                or existing["signed_at"] != signed.signed_at
            ):
                raise LifecycleDbError("recovery deletion overlay id conflicts with persisted truth")
            persisted_refs = tuple(
                row[0]
                for row in self._con.execute(
                    "SELECT artifact_id FROM recovery_deletion_veto WHERE overlay_id=? ORDER BY artifact_id",
                    (signed.overlay_id,),
                )
            )
            if persisted_refs != deleted_artifact_refs:
                raise LifecycleDbError("recovery deletion overlay id conflicts with persisted veto set")
            return AppliedDeletionOverlayEvidence(
                signed.overlay_id,
                signed.workspace_id,
                signed.manifest_id,
                signed.sequence,
                signed.previous_overlay_id,
                overlay.deleted_artifact_refs,
            )
        head = self._con.execute(
            "SELECT overlay_id, overlay_sequence FROM recovery_deletion_overlay "
            "WHERE workspace_id=? AND manifest_id=? "
            "ORDER BY CAST(overlay_sequence AS INTEGER) DESC LIMIT 1",
            (signed.workspace_id, signed.manifest_id),
        ).fetchone()
        if head is None:
            if signed.sequence != "0" or signed.previous_overlay_id is not None:
                raise LifecycleDbError("recovery deletion overlay history is discontinuous")
        elif (
            signed.sequence != str(int(head["overlay_sequence"]) + 1)
            or signed.previous_overlay_id != head["overlay_id"]
        ):
            raise LifecycleDbError("recovery deletion overlay rollback or discontinuity")
        self._con.execute(
            "INSERT INTO recovery_deletion_overlay "
            "(overlay_id, workspace_id, manifest_id, overlay_sequence, previous_overlay_id, "
            " mapping_digest, signer_key_id, signed_at, overlay_state) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                signed.overlay_id,
                signed.workspace_id,
                signed.manifest_id,
                signed.sequence,
                signed.previous_overlay_id,
                signed.mapping_digest,
                signed.signer_key_id,
                signed.signed_at,
                "VERIFIED_APPLIED",
            ),
        )
        self._con.executemany(
            "INSERT INTO recovery_deletion_veto (overlay_id, artifact_id, veto_state) VALUES (?,?,?)",
            [(signed.overlay_id, artifact_id, "ACTIVE") for artifact_id in deleted_artifact_refs],
        )
        return AppliedDeletionOverlayEvidence(
            signed.overlay_id,
            signed.workspace_id,
            signed.manifest_id,
            signed.sequence,
            signed.previous_overlay_id,
            overlay.deleted_artifact_refs,
        )

    def recovery_deletion_vetoed(self, artifact_id: str) -> bool:
        return self._con.execute(
            "SELECT 1 FROM recovery_deletion_veto WHERE artifact_id=? AND veto_state='ACTIVE' LIMIT 1",
            (artifact_id,),
        ).fetchone() is not None

    def list_recovery_deletion_vetoes(self, overlay_id: str) -> list[sqlite3.Row]:
        self._con.row_factory = sqlite3.Row
        return list(self._con.execute(
            "SELECT * FROM recovery_deletion_veto WHERE overlay_id=? ORDER BY artifact_id", (overlay_id,)
        ))
    # -- source/deletion/recovery mapping (body-free) ----------------------- #

    def insert_source_deletion_recovery_map(
        self,
        map_id: str,
        workspace_id: str,
        source_ref_id: str,
        artifact_id: str,
        deletion_ref_id: str,
        recovery_proof_ref_id: str,
        overlay_sequence: str,
        bundle_head_digest: str,
        floor_digest: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO source_deletion_recovery_map "
            "(map_id, workspace_id, source_ref_id, artifact_id, deletion_ref_id, "
            " recovery_proof_ref_id, overlay_sequence, bundle_head_digest, floor_digest, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (map_id, workspace_id, source_ref_id, artifact_id, deletion_ref_id,
             recovery_proof_ref_id, overlay_sequence, bundle_head_digest, floor_digest, created_at),
        )

    def list_source_deletion_recovery_maps(
        self, workspace_id: str, source_ref_id: str, deletion_ref_id: str
    ) -> list[sqlite3.Row]:
        self._con.row_factory = sqlite3.Row
        return list(self._con.execute(
            "SELECT * FROM source_deletion_recovery_map "
            "WHERE workspace_id=? AND source_ref_id=? AND deletion_ref_id=? ORDER BY artifact_id",
            (workspace_id, source_ref_id, deletion_ref_id),
        ))

    # -- binding cache (SQLite is a cache only; see module docstring) ------- #

    def insert_binding_leaf(
        self,
        leaf_id: str,
        namespace_id: str,
        provider_handle: str,
        leaf_state: str,
        leaf_digest: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO binding_leaf "
            "(leaf_id, namespace_id, provider_handle, leaf_state, leaf_digest, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (leaf_id, namespace_id, provider_handle, leaf_state, leaf_digest, created_at),
        )

    def insert_binding_checkpoint(
        self,
        checkpoint_id: str,
        checkpoint_sha256: str,
        checkpoint_sequence: str,
        history_root_digest: str,
        current_map_root_digest: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO binding_checkpoint "
            "(checkpoint_id, checkpoint_sha256, checkpoint_sequence, history_root_digest, "
            " current_map_root_digest, created_at) VALUES (?,?,?,?,?,?)",
            (
                checkpoint_id,
                checkpoint_sha256,
                checkpoint_sequence,
                history_root_digest,
                current_map_root_digest,
                created_at,
            ),
        )

    # -- outbox --------------------------------------------------------------- #

    def insert_outbox(self, event_kind: str, ref_digest: str) -> None:
        self._con.execute(
            "INSERT INTO outbox (event_kind, ref_digest, outbox_state) VALUES (?,?,'PENDING')",
            (event_kind, ref_digest),
        )

    # -- Gate 3: accepted_changeset / state_delta / generation --------------- #

    def insert_accepted_changeset(
        self,
        changeset_id: str,
        workspace_id: str,
        parent_generation_id: str | None,
        changes_root_digest: str,
        changeset_state: str,
        created_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO accepted_changeset "
            "(changeset_id, workspace_id, parent_generation_id, changes_root_digest, "
            " changeset_state, created_at) VALUES (?,?,?,?,?,?)",
            (changeset_id, workspace_id, parent_generation_id, changes_root_digest,
             changeset_state, created_at),
        )

    def insert_state_delta(
        self,
        delta_id: str,
        changeset_id: str,
        operation_kind: str,
        object_kind: str,
        object_id: str,
        revision_id: str | None = None,
        expected_active_revision_id: str | None = None,
        envelope_ref_id: str | None = None,
        assertion_id: str | None = None,
        evidence_edge_id: str | None = None,
        evidence_fragment_ref_id: str | None = None,
        deletion_command_id: str | None = None,
        scope_digest: str | None = None,
        reason_state: str | None = None,
    ) -> None:
        self._con.execute(
            "INSERT INTO state_delta "
            "(delta_id, changeset_id, operation_kind, object_kind, object_id, revision_id, "
            " expected_active_revision_id, envelope_ref_id, assertion_id, evidence_edge_id, "
            " evidence_fragment_ref_id, deletion_command_id, scope_digest, reason_state) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (delta_id, changeset_id, operation_kind, object_kind, object_id, revision_id,
             expected_active_revision_id, envelope_ref_id, assertion_id, evidence_edge_id,
             evidence_fragment_ref_id, deletion_command_id, scope_digest, reason_state),
        )

    def insert_generation(
        self,
        generation_id: str,
        workspace_id: str,
        changeset_id: str,
        generation_state: str,
        binding_checkpoint_id: str | None = None,
        created_at: str = "",
    ) -> None:
        self._con.execute(
            "INSERT INTO generation "
            "(generation_id, workspace_id, changeset_id, generation_state, "
            " binding_checkpoint_id, created_at) VALUES (?,?,?,?,?,?)",
            (generation_id, workspace_id, changeset_id, generation_state,
             binding_checkpoint_id, created_at),
        )

    def get_accepted_changeset(self, changeset_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM accepted_changeset WHERE changeset_id=?", (changeset_id,)
        ).fetchone()

    def list_state_deltas(self, changeset_id: str) -> list[sqlite3.Row]:
        self._con.row_factory = sqlite3.Row
        return list(
            self._con.execute(
                "SELECT * FROM state_delta WHERE changeset_id=? ORDER BY delta_id",
                (changeset_id,),
            )
        )

    # -- Gate 3: floor_candidate / freshness_serve_gate ---------------------- #

    def insert_floor_candidate(
        self,
        attempt_id: str,
        workspace_id: str,
        candidate_kind: str,
        expected_old_floor_digest: str,
        expected_keychain_generation: str,
        candidate_floor_hex: str,
        candidate_floor_digest: str,
        challenge_sequence: str,
        nonce_digest: str,
        disposition_state: str,
        reason_state: str | None = None,
        created_at: str = "",
    ) -> None:
        self._con.execute(
            "INSERT INTO floor_candidate "
            "(attempt_id, workspace_id, candidate_kind, expected_old_floor_digest, "
            " expected_keychain_generation, candidate_floor_hex, candidate_floor_digest, "
            " challenge_sequence, nonce_digest, disposition_state, reason_state, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (attempt_id, workspace_id, candidate_kind, expected_old_floor_digest,
             expected_keychain_generation, candidate_floor_hex, candidate_floor_digest,
             challenge_sequence, nonce_digest, disposition_state, reason_state, created_at),
        )

    def get_floor_candidate(self, attempt_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM floor_candidate WHERE attempt_id=?", (attempt_id,)
        ).fetchone()

    def upsert_freshness_serve_gate(
        self,
        workspace_id: str,
        gate_state: str,
        stable_floor_generation: str,
        stable_checkpoint_id: str,
        source_candidate_digest: str,
        reason_state: str,
        updated_at: str,
    ) -> None:
        self._con.execute(
            "INSERT INTO freshness_serve_gate "
            "(workspace_id, gate_state, stable_floor_generation, stable_checkpoint_id, "
            " source_candidate_digest, reason_state, updated_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(workspace_id) DO UPDATE SET "
            "gate_state=excluded.gate_state, "
            "stable_floor_generation=excluded.stable_floor_generation, "
            "stable_checkpoint_id=excluded.stable_checkpoint_id, "
            "source_candidate_digest=excluded.source_candidate_digest, "
            "reason_state=excluded.reason_state, updated_at=excluded.updated_at",
            (workspace_id, gate_state, stable_floor_generation, stable_checkpoint_id,
             source_candidate_digest, reason_state, updated_at),
        )

    def get_freshness_serve_gate(self, workspace_id: str) -> sqlite3.Row | None:
        self._con.row_factory = sqlite3.Row
        return self._con.execute(
            "SELECT * FROM freshness_serve_gate WHERE workspace_id=?", (workspace_id,)
        ).fetchone()

    # -- body-free hash-chained event log (in-transaction; F5 atomicity) ----- #

    def event_chain_head(self) -> str | None:
        """Return the current event-chain head ``event_digest`` as seen WITHIN
        this unit of work's transaction (``None`` if the chain is empty)."""
        row = self._con.execute(
            "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def append_event(self, prev_digest: str | None, kind: str, ref_digest: str) -> str:
        """Append one body-free hash-chained event WITHIN this unit of work's
        transaction (F5), so the event commits atomically with the state change
        it records -- a crash can never leave state without its event or vice
        versa. ``prev_digest`` must equal the current chain head read inside this
        transaction; a mismatch raises :class:`EventChainError` without writing.
        The payload carries only refs/digests (never a body), so
        ``event_digest = SHA-256(domain-prefixed canonical_bytes({schema,
        prev_digest, event_kind, ref_digest}))``. Returns the new digest."""
        current_head = self._con.execute(
            "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        actual_prev = current_head[0] if current_head else None
        if actual_prev != prev_digest:
            raise EventChainError(
                f"stale prev_digest: expected {actual_prev!r}, got {prev_digest!r}"
            )
        payload = {
            "schema": "wiki-lifecycle-event-v1",
            "prev_digest": prev_digest or "",
            "event_kind": kind,
            "ref_digest": ref_digest,
        }
        message = EVENT_LOG_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(payload)
        event_digest = hashlib.sha256(message).hexdigest()
        created_at = "1970-01-01T00:00:00Z"
        self._con.execute(
            "INSERT INTO event_log (prev_digest, event_kind, ref_digest, event_digest, created_at) "
            "VALUES (?,?,?,?,?)",
            (prev_digest, kind, ref_digest, event_digest, created_at),
        )
        return event_digest


class LifecycleDatabase:
    """The encrypted-lifecycle SQLite unit-of-work database (schema-of-record)."""

    def __init__(self, db_path: Path, fixture_capture_mode: bool = False) -> None:
        self.db_path = db_path
        self.con: sqlite3.Connection | None = None
        # Retained as an ignored compatibility argument. A caller cannot grant
        # fixture capability by passing or mutating a public mode flag.
        self._fixture_capture_capability = False

    @property
    def fixture_capture_mode(self) -> bool:
        return self._fixture_capture_capability

    def initialize(self) -> None:
        """Open (creating if absent) ``db_path```, apply the contract PRAGMAs,
        and create ordinary production DDL."""
        self.con = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.execute("PRAGMA busy_timeout=5000")
        self.con.executescript(SCHEMA)
        if self._fixture_capture_capability:
            self.con.executescript(CAPTURE_SCHEMA)
        self.assert_contract_pragmas()
        assert_no_plaintext_columns(self.con)

    def assert_contract_pragmas(self) -> None:
        """Assert the four contract PRAGMAs are active on the open connection."""
        assert self.con is not None, "initialize() not called"
        journal_mode = self.con.execute("PRAGMA journal_mode").fetchone()[0]
        if str(journal_mode).lower() != "wal":
            raise LifecycleDbError(f"journal_mode must be WAL, got {journal_mode!r}")
        synchronous = self.con.execute("PRAGMA synchronous").fetchone()[0]
        if int(synchronous) != 2:  # FULL == 2
            raise LifecycleDbError(f"synchronous must be FULL(2), got {synchronous!r}")
        foreign_keys = self.con.execute("PRAGMA foreign_keys").fetchone()[0]
        if int(foreign_keys) != 1:
            raise LifecycleDbError(f"foreign_keys must be ON, got {foreign_keys!r}")
        busy_timeout = self.con.execute("PRAGMA busy_timeout").fetchone()[0]
        if int(busy_timeout) != 5000:
            raise LifecycleDbError(f"busy_timeout must be 5000, got {busy_timeout!r}")

    # -- unit of work --------------------------------------------------------- #

    @contextmanager
    def unit_of_work(self) -> Iterator[UnitOfWork]:
        """Run one ``BEGIN IMMEDIATE`` write transaction. Commits on clean
        exit; rolls back and re-raises on any exception, leaving no partial
        write visible to subsequent readers."""
        assert self.con is not None, "initialize() not called"
        con = self.con
        con.execute("BEGIN IMMEDIATE")
        uow = UnitOfWork(con)
        try:
            yield uow
        except BaseException:
            con.execute("ROLLBACK")
            raise
        else:
            con.execute("COMMIT")
    def apply_verified_overlay(self, overlay: VerifiedDeletionOverlay) -> AppliedDeletionOverlayToken:
        """Persist an overlay and issue a bearer token authenticated by this store."""
        assert self.con is not None, "initialize() not called"
        if (
            not isinstance(overlay, VerifiedDeletionOverlay)
            or not isinstance(overlay.overlay, SignedDeletionOverlay)
            or not isinstance(overlay.deleted_artifact_refs, frozenset)
            or any(not isinstance(ref, str) or not ref for ref in overlay.deleted_artifact_refs)
        ):
            raise LifecycleDbError("verified recovery deletion overlay is invalid")
        with self.unit_of_work() as uow:
            evidence = uow.persist_verified_recovery_deletion_overlay(overlay)
            while True:
                secret = secrets.token_urlsafe(32)
                token_digest = hashlib.sha256(secret.encode("ascii")).hexdigest()
                try:
                    uow._con.execute(
                        "INSERT INTO recovery_deletion_overlay_token "
                        "(token_digest, overlay_id, token_state) VALUES (?,?,?)",
                        (token_digest, evidence.overlay_id, "ACTIVE"),
                    )
                except sqlite3.IntegrityError:
                    continue
                return AppliedDeletionOverlayToken(secret)

    def redeem_applied_overlay(
        self, token: AppliedDeletionOverlayToken
    ) -> AppliedDeletionOverlayEvidence:
        """Redeem an authenticated token for immutable persisted overlay evidence."""
        assert self.con is not None, "initialize() not called"
        if not isinstance(token, AppliedDeletionOverlayToken):
            raise LifecycleDbError("recovery deletion overlay token is invalid")
        token_digest = hashlib.sha256(token._secret.encode("ascii")).hexdigest()
        self.con.row_factory = sqlite3.Row
        overlay = self.con.execute(
            "SELECT overlay.* FROM recovery_deletion_overlay_token AS token "
            "JOIN recovery_deletion_overlay AS overlay ON overlay.overlay_id=token.overlay_id "
            "WHERE token.token_digest=? AND token.token_state='ACTIVE'",
            (token_digest,),
        ).fetchone()
        if overlay is None:
            raise LifecycleDbError("recovery deletion overlay token is invalid")
        refs = frozenset(
            row[0]
            for row in self.con.execute(
                "SELECT artifact_id FROM recovery_deletion_veto "
                "WHERE overlay_id=? AND veto_state='ACTIVE' ORDER BY artifact_id",
                (overlay["overlay_id"],),
            )
        )
        return AppliedDeletionOverlayEvidence(
            overlay["overlay_id"],
            overlay["workspace_id"],
            overlay["manifest_id"],
            overlay["overlay_sequence"],
            overlay["previous_overlay_id"],
            refs,
        )

    # -- checked-snapshot read (linearization point; see module docstring) --- #

    def checked_snapshot_read(self, artifact_id: str) -> SnapshotResult:
        """Atomically capture ``(canonical_artifact.artifact_state,
        key_state.custody_state, event_chain head)`` as of one consistent
        point in WAL time. This acquisition — not any later commit — is the
        read's linearization point (ADR-0027 §9, R9-3/UF-3): a concurrent
        writer that commits after this snapshot's acquisition can never
        retroactively invalidate the values returned here."""
        assert self.con is not None, "initialize() not called"
        con = self.con
        con.row_factory = sqlite3.Row
        con.execute("BEGIN")
        try:
            artifact_row = con.execute(
                "SELECT artifact_state FROM canonical_artifact WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            key_row = con.execute(
                "SELECT custody_state FROM key_state WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            head_row = con.execute(
                "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
        except BaseException:
            con.execute("ROLLBACK")
            raise
        else:
            con.execute("COMMIT")
        return SnapshotResult(
            artifact_id=artifact_id,
            artifact_state=artifact_row["artifact_state"] if artifact_row else None,
            custody_state=key_row["custody_state"] if key_row else None,
            event_chain_head_digest=head_row["event_digest"] if head_row else None,
        )

    def checked_serve_snapshot_read(
        self, artifact_id: str, workspace_id: str
    ) -> ServeSnapshotResult:
        """Atomically capture ALL serve-gating state for ``artifact_id`` --
        canonical_artifact state, key_state custody, the latest deletion phase,
        the workspace freshness serve gate, and the event-chain head -- as of one
        consistent WAL point. This acquisition (not any later commit) is the serve
        path's sole linearization point (ADR-0027 §9): a concurrent writer that
        commits a veto/gate change after this snapshot can never retroactively
        invalidate the visibility decision made from the returned values."""
        assert self.con is not None, "initialize() not called"
        con = self.con
        con.row_factory = sqlite3.Row
        con.execute("BEGIN")
        try:
            artifact_row = con.execute(
                "SELECT artifact_state FROM canonical_artifact WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            key_row = con.execute(
                "SELECT custody_state FROM key_state WHERE artifact_id=?",
                (artifact_id,),
            ).fetchone()
            deletion_row = con.execute(
                "SELECT phase_state FROM deletion_state WHERE artifact_id=? "
                "ORDER BY updated_at DESC, deletion_id DESC LIMIT 1",
                (artifact_id,),
            ).fetchone()
            gate_row = con.execute(
                "SELECT gate_state, reason_state FROM freshness_serve_gate WHERE workspace_id=?",
                (workspace_id,),
            ).fetchone()
            head_row = con.execute(
                "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
        except BaseException:
            con.execute("ROLLBACK")
            raise
        else:
            con.execute("COMMIT")
        return ServeSnapshotResult(
            artifact_id=artifact_id,
            artifact_state=artifact_row["artifact_state"] if artifact_row else None,
            custody_state=key_row["custody_state"] if key_row else None,
            deletion_phase_state=deletion_row["phase_state"] if deletion_row else None,
            serve_gate_state=gate_row["gate_state"] if gate_row else None,
            serve_gate_reason=gate_row["reason_state"] if gate_row else None,
            event_chain_head_digest=head_row["event_digest"] if head_row else None,
        )

    # -- body-free hash-chained event log ------------------------------------- #

    def event_chain_head(self) -> str | None:
        """Return the ``event_digest`` of the most recently appended event,
        or ``None`` if the chain is empty."""
        assert self.con is not None, "initialize() not called"
        row = self.con.execute(
            "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def append_event(self, prev_digest: str | None, kind: str, ref_digest: str) -> str:
        """Append one body-free hash-chained event. ``prev_digest`` MUST equal
        the current :meth:`event_chain_head` (``None`` only for the first
        event); a mismatch raises :class:`EventChainError` without writing.
        The event payload carries only refs/digests — never a body — so
        ``event_digest = SHA-256(domain-prefixed canonical_bytes({schema,
        prev_digest, event_kind, ref_digest}))``, chaining strictly forward.
        Returns the new ``event_digest``."""
        assert self.con is not None, "initialize() not called"
        con = self.con
        con.execute("BEGIN IMMEDIATE")
        try:
            current_head = con.execute(
                "SELECT event_digest FROM event_log ORDER BY event_id DESC LIMIT 1"
            ).fetchone()
            actual_prev = current_head[0] if current_head else None
            if actual_prev != prev_digest:
                raise EventChainError(
                    f"stale prev_digest: expected {actual_prev!r}, got {prev_digest!r}"
                )
            payload = {
                "schema": "wiki-lifecycle-event-v1",
                "prev_digest": prev_digest or "",
                "event_kind": kind,
                "ref_digest": ref_digest,
            }
            message = EVENT_LOG_DOMAIN.encode("ascii") + b"\x00" + canonical_bytes(payload)
            event_digest = hashlib.sha256(message).hexdigest()
            created_at = "1970-01-01T00:00:00Z"
            con.execute(
                "INSERT INTO event_log (prev_digest, event_kind, ref_digest, event_digest, created_at) "
                "VALUES (?,?,?,?,?)",
                (prev_digest, kind, ref_digest, event_digest, created_at),
            )
        except BaseException:
            con.execute("ROLLBACK")
            raise
        else:
            con.execute("COMMIT")
        return event_digest

    def event_log_rows(self) -> list[sqlite3.Row]:
        assert self.con is not None, "initialize() not called"
        self.con.row_factory = sqlite3.Row
        return list(self.con.execute("SELECT * FROM event_log ORDER BY event_id"))

    # -- lifecycle ------------------------------------------------------------- #

    def close(self) -> None:
        if self.con is not None:
            try:
                self.con.close()
            except Exception:
                pass
            self.con = None

    def __del__(self) -> None:  # pragma: no cover - best-effort cleanup
        self.close()


class FixtureCaptureLifecycleDatabase(LifecycleDatabase):
    """Dedicated immutable synthetic-store type; never enabled by a public flag."""

    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        self._fixture_capture_capability = True


def fixture_capture_database(db_path: Path) -> FixtureCaptureLifecycleDatabase:
    """Construct the only database type permitted to install fixture capture DDL."""
    return FixtureCaptureLifecycleDatabase(db_path)


def table_columns(con: sqlite3.Connection, table: str) -> list[str]:
    """Introspect column names for ``table`` via ``PRAGMA table_info``."""
    return [row[1] for row in con.execute(f"PRAGMA table_info({table})")]


def assert_no_plaintext_columns(con: sqlite3.Connection) -> None:
    """Assert every installed schema table, including fixture capture tables, has
    only allowlisted opaque/id/digest/handle/state/wrapped/timestamp columns."""
    installed_tables = {
        row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    for table in TABLE_NAMES:
        if table not in installed_tables:
            continue
        for column in table_columns(con, table):
            if not is_allowed_column_name(column):
                raise LifecycleDbError(
                    f"non-allowlisted (potential plaintext) column {table}.{column}"
                )


class CapturePersistenceError(LifecycleDbError):
    """Capture evidence cannot be persisted as one complete durable unit."""


class EncryptedCapturePersistence(AtomicCapturePersistencePort):
    """The sole aggregate writer: encrypted CAS first, SQLite references second.

    CAS is write-once and may retain an unreferenced encrypted blob after a
    SQLite rollback; SQLite never exposes a partial aggregate.
    """

    def __init__(self, database: LifecycleDatabase, cas: EncryptedContentStore, dek: bytes) -> None:
        if len(dek) != 32:
            raise CapturePersistenceError("capture persistence requires a 32-byte encryption key")
        self._database, self._cas, self._dek = database, cas, bytes(dek)

    def persist_capture_aggregate(self, aggregate: CapturePersistenceAggregateV1) -> None:
        if not isinstance(aggregate, CapturePersistenceAggregateV1):
            raise CapturePersistenceError("only a complete capture persistence aggregate is accepted")
        if not isinstance(self._database, FixtureCaptureLifecycleDatabase):
            raise CapturePersistenceError("fixture capture persistence is prohibited for production databases")
        try:
            aggregate = CapturePersistenceAggregateV1.from_mapping(aggregate.to_mapping())
        except (TypeError, ValueError) as exc:
            raise CapturePersistenceError("capture aggregate fails canonical contract validation") from exc
        self._validate(aggregate)
        with self._database.unit_of_work() as uow:
            con = uow._con
            scope_digest = hashlib.sha256(
                canonical_bytes(aggregate.scope.to_mapping())
            ).hexdigest()
            existing_scope = con.execute(
                "SELECT workspace_id, source_id, scope_digest "
                "FROM capture_scope WHERE scope_id=?",
                (aggregate.scope.scope_ref,),
            ).fetchone()
            if existing_scope is not None and tuple(existing_scope) != (
                aggregate.scope.workspace_ref,
                aggregate.scope.source_ref,
                scope_digest,
            ):
                raise CapturePersistenceError("conflicting durable capture_scope evidence")
            existing_aggregate = con.execute(
                "SELECT cohort_digest, aggregate_handle FROM capture_cohort "
                "WHERE cohort_id=?",
                (aggregate.cohort.cohort_ref,),
            ).fetchone()
            if existing_aggregate is not None:
                if existing_aggregate[0] != aggregate.cohort.cohort_digest:
                    raise CapturePersistenceError("conflicting durable capture_cohort evidence")
                locator = existing_aggregate[1]
            else:
                raw = canonical_bytes(aggregate.to_mapping())
                nonce = secrets.token_bytes(12).hex()
                aad = ("second-brain-capture/aggregate/" + aggregate.aggregate_digest).encode("ascii")
                ciphertext_hex, tag_hex = aes_gcm_seal(self._dek, nonce, raw, aad)
                locator_digest = self._cas.put(bytes.fromhex(nonce + ciphertext_hex + tag_hex))
                locator = "encrypted-capture:" + locator_digest
            if existing_scope is None:
                self._insert_or_match(
                    con,
                    "capture_scope",
                    "scope_id",
                    aggregate.scope.scope_ref,
                    (
                        aggregate.scope.workspace_ref,
                        aggregate.scope.source_ref,
                        "NON_SERVING",
                        scope_digest,
                        locator,
                    ),
                )
            for receipt in aggregate.receipts:
                self._insert_or_match(
                    con,
                    "capture_receipt",
                    "capture_id",
                    receipt.capture_ref,
(
                        aggregate.scope.scope_ref,
                        receipt.scan_epoch,
                        receipt.disposition,
                        receipt.ciphertext_digest,
                        receipt.encrypted_content_ref,
                        receipt.encrypted_native_mapping_ref,
                        locator,
                    )
                )
            self._insert_or_match(
                con,
                "capture_manifest",
                "manifest_id",
                aggregate.manifest.manifest_ref,
                (
                    aggregate.scope.scope_ref,
                    aggregate.manifest.scan_epoch,
                    "NON_SERVING",
                    aggregate.manifest.manifest_digest,
                    locator,
                ),
            )
            reconciliation = aggregate.advance.reconciliation
            self._insert_or_match(
                con,
                "capture_reconciliation",
                "reconciliation_id",
                reconciliation.reconciliation_ref,
                (
                    aggregate.scope.scope_ref,
                    reconciliation.scan_epoch,
                    "COMPLETE",
                    reconciliation.reconciliation_digest,
                    locator,
                ),
            )
            checkpoint = aggregate.advance.checkpoint
            current = con.execute(
                "SELECT checkpoint_id, checkpoint_sequence, checkpoint_digest "
                "FROM capture_checkpoint WHERE scope_id=?",
                (aggregate.scope.scope_ref,),
            ).fetchone()
            if current is None:
                if aggregate.advance.previous_checkpoint_ref is not None:
                    raise CapturePersistenceError("stale checkpoint compare-and-swap")
            else:
                same_checkpoint = tuple(current) == (
                    checkpoint.checkpoint_ref,
                    checkpoint.scan_epoch,
                    checkpoint.checkpoint_digest,
                )
                if not (
                    same_checkpoint
                    and aggregate.advance.previous_checkpoint_ref is None
                ) and current[0] != aggregate.advance.previous_checkpoint_ref:
                    raise CapturePersistenceError("stale checkpoint compare-and-swap")
            self._upsert_checkpoint(
                con,
                aggregate.scope.scope_ref,
                checkpoint.checkpoint_ref,
                checkpoint.scan_epoch,
                checkpoint.checkpoint_digest,
                locator,
            )
            registration = aggregate.registration
            self._insert_or_match(
                con,
                "migration_registration",
                "registration_id",
                registration.registration_ref,
                (
                    aggregate.scope.scope_ref,
                    registration.migration_epoch,
                    "NON_SERVING",
                    registration.ciphertext_digest,
                    locator,
                ),
            )
            self._validate_durable_cohort(con, aggregate)
            self._insert_or_match(
                con,
                "capture_cohort",
                "cohort_id",
                aggregate.cohort.cohort_ref,
                (
                    aggregate.cohort.final_workspace_ref,
                    "NON_SERVING",
                    aggregate.cohort.cohort_digest,
                    locator,
                ),
            )

    @staticmethod
    def _insert_or_match(con: sqlite3.Connection, table: str, key_column: str, key: str, values: tuple[str, ...]) -> None:
        row = con.execute(f"SELECT * FROM {table} WHERE {key_column}=?", (key,)).fetchone()
        expected = (key, *values)
        if row is not None:
            if tuple(row) != expected:
                raise CapturePersistenceError(f"conflicting durable {table} evidence")
            return
        con.execute(f"INSERT INTO {table} VALUES ({','.join('?' for _ in expected)})", expected)

    @staticmethod
    def _validate_durable_cohort(con: sqlite3.Connection, aggregate: CapturePersistenceAggregateV1) -> None:
        for entry in aggregate.cohort.source_roster:
            scope = con.execute(
                "SELECT workspace_id, source_id FROM capture_scope WHERE scope_id=?",
                (entry.scope_ref,),
            ).fetchone()
            manifest = con.execute(
                "SELECT manifest_sequence FROM capture_manifest WHERE manifest_id=? AND scope_id=?",
                (entry.manifest_ref, entry.scope_ref),
            ).fetchone()
            registration = con.execute(
                "SELECT registration_sequence FROM migration_registration WHERE registration_id=? AND scope_id=?",
                (entry.registration_ref, entry.scope_ref),
            ).fetchone()
            reconciliation = con.execute(
                "SELECT reconciliation_sequence FROM capture_reconciliation WHERE reconciliation_id=? AND scope_id=? AND reconciliation_state='COMPLETE'",
                (entry.reconciliation_ref, entry.scope_ref),
            ).fetchone()
            checkpoint = con.execute(
                "SELECT checkpoint_id, checkpoint_sequence FROM capture_checkpoint WHERE scope_id=?",
                (entry.scope_ref,),
            ).fetchone()
            if (scope is None or tuple(scope) != (aggregate.cohort.final_workspace_ref, entry.source_ref)
                    or manifest is None or registration is None
                    or reconciliation is None or reconciliation[0] != entry.reconciliation_epoch
                    or checkpoint is None or checkpoint[0] != entry.checkpoint_ref
                    or checkpoint[1] != entry.checkpoint_epoch):
                raise CapturePersistenceError("cohort requires exact durable registration, manifest, reconciliation, and checkpoint evidence")
    @staticmethod
    def _upsert_checkpoint(con: sqlite3.Connection, scope_id: str, checkpoint_id: str, sequence: str, digest: str, locator: str) -> None:
        con.execute("INSERT INTO capture_checkpoint VALUES (?,?,?,?,?,?) ON CONFLICT(scope_id) DO UPDATE SET checkpoint_id=excluded.checkpoint_id, checkpoint_sequence=excluded.checkpoint_sequence, checkpoint_state=excluded.checkpoint_state, checkpoint_digest=excluded.checkpoint_digest, aggregate_handle=excluded.aggregate_handle", (scope_id, checkpoint_id, sequence, "NON_SERVING", digest, locator))

    @staticmethod
    def _validate(aggregate: CapturePersistenceAggregateV1) -> None:
        scope = aggregate.scope
        manifest = aggregate.manifest
        reconciliation = aggregate.advance.reconciliation
        checkpoint = aggregate.advance.checkpoint
        registration = aggregate.registration
        if reconciliation.disposition_counts["QUARANTINED"] != "0":
            raise CapturePersistenceError("quarantine blocks capture persistence")
        if (
            manifest.scope != scope
            or registration.scope != scope
            or checkpoint.scope != scope
            or reconciliation.scan_epoch != manifest.scan_epoch
            or checkpoint.scan_epoch != manifest.scan_epoch
        ):
            raise CapturePersistenceError("aggregate does not bind one exact scope and scan epoch")
        if (set(manifest.receipt_refs) != {receipt.capture_ref for receipt in aggregate.receipts}
                or reconciliation.manifest_ref != manifest.manifest_ref
                or checkpoint.manifest_ref != manifest.manifest_ref
                or checkpoint.reconciliation_ref != reconciliation.reconciliation_ref):
            raise CapturePersistenceError("aggregate manifest, reconciliation, and checkpoint do not reconcile")
        matched = [entry for entry in aggregate.cohort.source_roster if entry.scope_ref == scope.scope_ref]
        if len(matched) != 1:
            raise CapturePersistenceError("cohort lacks one exact durable scope registration")
        entry = matched[0]
        if (entry.registration_ref != registration.registration_ref or entry.manifest_ref != manifest.manifest_ref
                or entry.reconciliation_ref != reconciliation.reconciliation_ref or entry.checkpoint_ref != checkpoint.checkpoint_ref
                or entry.reconciliation_epoch != reconciliation.reconciliation_epoch or entry.checkpoint_epoch != checkpoint.scan_epoch
                or entry.source_ref != scope.source_ref or aggregate.cohort.final_workspace_ref != scope.workspace_ref):
            raise CapturePersistenceError("cohort ownership binding is not exactly reconciled")
