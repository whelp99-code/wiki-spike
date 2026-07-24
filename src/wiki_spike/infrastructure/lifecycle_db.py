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
exactly six kinds, enforced by a name-suffix convention so the shape is
mechanically auditable (see ``COLUMN_KIND_ALLOWLIST`` and
:func:`assert_no_plaintext_columns`):

- **id**       — ``*_id`` / ``workspace_id`` / ``artifact_id`` / ... — opaque identifiers.
- **digest**   — ``*_digest`` / ``*_sha256`` — content digests (never bodies).
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
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from wiki_spike.memory_core.contracts import canonical_bytes

# --------------------------------------------------------------------------- #
# Column-kind allowlist (no plaintext columns anywhere in this schema).
# --------------------------------------------------------------------------- #

COLUMN_KIND_ALLOWLIST: tuple[str, ...] = (
    "_id",
    "_digest",
    "_sha256",
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
COLUMN_KIND_EXACT_ALLOWLIST: tuple[str, ...] = ("ordinal",)


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
"""

# Tables in declaration order, used for both DDL introspection and the
# plaintext-column allowlist assertion.
TABLE_NAMES: tuple[str, ...] = (
    "command",
    "canonical_artifact",
    "command_artifact",
    "ark_key_intent",
    "wrapped_key",
    "key_state",
    "candidate_review",
    "floor_state",
    "deletion_state",
    "binding_leaf",
    "binding_checkpoint",
    "event_log",
    "outbox",
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


@dataclass
class LifecycleDatabase:
    """The encrypted-lifecycle SQLite unit-of-work database (schema-of-record).

    A NEW, standalone database file — separate from the legacy
    ``wiki_spike.controlplane.ControlPlane`` control plane. Construct with a
    path and call :meth:`initialize` before use.
    """

    db_path: Path
    con: sqlite3.Connection | None = None

    def initialize(self) -> None:
        """Open (creating if absent) ``db_path``, apply the contract PRAGMAs,
        and create the full DDL. Idempotent: safe to call repeatedly and safe
        to call again after a process restart against the same file."""
        self.con = sqlite3.connect(str(self.db_path), isolation_level=None)
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.execute("PRAGMA busy_timeout=5000")
        self.con.executescript(SCHEMA)
        self.assert_contract_pragmas()

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


def table_columns(con: sqlite3.Connection, table: str) -> list[str]:
    """Introspect column names for ``table`` via ``PRAGMA table_info``."""
    return [row[1] for row in con.execute(f"PRAGMA table_info({table})")]


def assert_no_plaintext_columns(con: sqlite3.Connection) -> None:
    """Assert every column of every table in :data:`TABLE_NAMES` is one of
    the allowlisted id/digest/handle/state/wrapped/ts column kinds."""
    for table in TABLE_NAMES:
        for column in table_columns(con, table):
            if not is_allowed_column_name(column):
                raise LifecycleDbError(
                    f"non-allowlisted (potential plaintext) column {table}.{column}"
                )
