"""SQLite control-plane (SUB-06 + SUB-07, v3.3 §5-2, §5-3, §11).

The SQLite commit is the SOLE authoritative activation boundary (orphan-first):
Git object creation is a *prepare* stage; nothing is "published" until the DB
transaction commits. We do NOT claim a single ACID transaction across Git+SQLite.

SUB-07 additions:
- claim_resolution: per-generation claim state -> lets search post-filter stale hits.
- search_index + current_search_generation_id: an independent search pointer that
  can lag the wiki pointer (§11).
- publisher_lease: single-publisher lease (prevents concurrent publishers).
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


class CASConflict(RuntimeError):
    """Publication compare-and-swap lost: current pointer != expected parent."""


class ActivationError(RuntimeError):
    pass


class LeaseError(RuntimeError):
    pass


SCHEMA = """
CREATE TABLE IF NOT EXISTS generation (
  generation_id TEXT PRIMARY KEY,
  parent_generation_id TEXT,
  candidate_commit_oid TEXT NOT NULL,
  manifest_hash TEXT NOT NULL,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  release_commit_oid TEXT,
  state TEXT NOT NULL,
  seq INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS claim_identity (
  claim_id TEXT PRIMARY KEY,
  subject TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object TEXT NOT NULL,
  polarity TEXT NOT NULL,
  scope_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS assertion (
  assertion_id TEXT PRIMARY KEY,
  claim_id TEXT NOT NULL,
  source_id TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  modality TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS generation_assertion (
  generation_id TEXT NOT NULL,
  assertion_id TEXT NOT NULL,
  PRIMARY KEY (generation_id, assertion_id)
);
CREATE TABLE IF NOT EXISTS read_model_status (
  generation_id TEXT NOT NULL,
  model_name TEXT NOT NULL,
  state TEXT NOT NULL,
  artifact_digest TEXT,
  PRIMARY KEY (generation_id, model_name),
  FOREIGN KEY (generation_id) REFERENCES generation(generation_id)
);
CREATE TABLE IF NOT EXISTS claim_resolution (
  generation_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  state TEXT NOT NULL,
  PRIMARY KEY (generation_id, claim_id),
  FOREIGN KEY (generation_id) REFERENCES generation(generation_id)
);
CREATE TABLE IF NOT EXISTS search_index (
  generation_id TEXT NOT NULL,
  claim_id TEXT NOT NULL,
  subject TEXT NOT NULL,
  predicate TEXT NOT NULL,
  object TEXT NOT NULL,
  PRIMARY KEY (generation_id, claim_id),
  FOREIGN KEY (generation_id) REFERENCES generation(generation_id)
);
CREATE TABLE IF NOT EXISTS publication (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  current_generation_id TEXT,
  current_release_commit_oid TEXT,
  current_search_generation_id TEXT
);
CREATE TABLE IF NOT EXISTS outbox (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type TEXT NOT NULL,
  generation_id TEXT NOT NULL,
  processed INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS publisher_lease (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  holder TEXT,
  expires_at INTEGER NOT NULL DEFAULT 0,
  fencing_token INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO publication (id, current_generation_id, current_release_commit_oid, current_search_generation_id)
VALUES (1, NULL, NULL, NULL);
INSERT OR IGNORE INTO publisher_lease (id, holder, expires_at, fencing_token) VALUES (1, NULL, 0, 0);
"""


@dataclass
class ControlPlane:
    db_path: Path

    def __post_init__(self) -> None:
        self.con = sqlite3.connect(str(self.db_path), isolation_level=None)
        # ---- sqlite_contract (v3.3 §3) ----
        self.con.execute("PRAGMA journal_mode=WAL")
        self.con.execute("PRAGMA synchronous=FULL")
        self.con.execute("PRAGMA foreign_keys=ON")
        self.con.execute("PRAGMA busy_timeout=5000")
        self.con.executescript(SCHEMA)

    # -- single-publisher lease (SUB-07) ----------------------------------- #
    def acquire_lease(self, holder: str, now: int, ttl: int) -> int | None:
        """Acquire/renew the lease. Returns a fencing token, or None if held by another."""
        con = self.con
        con.execute("BEGIN IMMEDIATE")
        try:
            row = con.execute(
                "SELECT holder, expires_at, fencing_token FROM publisher_lease WHERE id=1"
            ).fetchone()
            cur_holder, expires, token = row
            expired = expires <= now
            if cur_holder is not None and not expired and cur_holder != holder:
                con.execute("ROLLBACK")
                return None
            # New acquisition (free/expired/takeover) bumps the fencing token; a renew
            # by the same live holder keeps its token.
            if cur_holder == holder and not expired:
                new_token = token
            else:
                new_token = token + 1
            con.execute(
                "UPDATE publisher_lease SET holder=?, expires_at=?, fencing_token=? WHERE id=1",
                (holder, now + ttl, new_token),
            )
            con.execute("COMMIT")
            return new_token
        except BaseException:
            con.execute("ROLLBACK")
            raise

    def release_lease(self, holder: str) -> None:
        self.con.execute(
            "UPDATE publisher_lease SET holder=NULL, expires_at=0 WHERE id=1 AND holder=?",
            (holder,),
        )

    def lease_holder(self, now: int) -> str | None:
        row = self.con.execute("SELECT holder, expires_at FROM publisher_lease WHERE id=1").fetchone()
        holder, expires = row
        return holder if (holder is not None and expires > now) else None

    # -- registration (prepare-stage bookkeeping) -------------------------- #
    def register_generation(
        self,
        generation_id: str,
        parent: str | None,
        commit_oid: str,
        manifest_hash: str,
        manifest_json: str = "{}",
        release_commit_oid: str | None = None,
    ) -> None:
        seq = self.con.execute("SELECT COALESCE(MAX(seq),0)+1 FROM generation").fetchone()[0]
        self.con.execute(
            "INSERT OR IGNORE INTO generation "
            "(generation_id, parent_generation_id, candidate_commit_oid, manifest_hash, "
            " manifest_json, release_commit_oid, state, seq, created_at) "
            "VALUES (?,?,?,?,?,?, 'validated', ?, '2026-07-19T00:00:00Z')",
            (generation_id, parent, commit_oid, manifest_hash, manifest_json, release_commit_oid, seq),
        )

    def set_release_commit(self, generation_id: str, release_commit_oid: str) -> None:
        self.con.execute(
            "UPDATE generation SET release_commit_oid=? WHERE generation_id=?",
            (release_commit_oid, generation_id),
        )

    def _required_from_manifest(self, generation_id: str) -> list[tuple[str, str]]:
        import json

        row = self.con.execute(
            "SELECT manifest_json FROM generation WHERE generation_id=?", (generation_id,)
        ).fetchone()
        if not row or not row[0]:
            return []
        inline = json.loads(row[0]).get("descriptor", {}).get("inline_artifacts", {})
        req = []
        if "wiki_files_root" in inline:
            req.append(("wiki_files", inline["wiki_files_root"]))
        if "citation_index_digest" in inline:
            req.append(("citation_index", inline["citation_index_digest"]))
        return req

    # -- immutable dedup store + generation membership (#3.1, #3.4) -------- #
    def upsert_claim_and_assertion(self, compiled) -> None:
        import json

        c = compiled
        self.con.execute(
            "INSERT OR IGNORE INTO claim_identity "
            "(claim_id, subject, predicate, object, polarity, scope_json) VALUES (?,?,?,?,?,?)",
            (c.identity.claim_id, c.identity.subject_id, c.identity.predicate_id,
             c.identity.obj, c.identity.polarity, json.dumps(c.identity.scope, sort_keys=True)),
        )
        self.con.execute(
            "INSERT OR IGNORE INTO assertion "
            "(assertion_id, claim_id, source_id, evidence_json, modality) VALUES (?,?,?,?,?)",
            (c.assertion.assertion_id, c.identity.claim_id, c.assertion.source_id,
             json.dumps({
                 "evidence_id": c.evidence.evidence_id,
                 "source_object_hash": c.evidence.source_object_hash,
                 "representation_hash": c.evidence.representation_hash,
                 "quote_hash": c.evidence.quote_hash,
                 "locators": list(c.evidence.locators),
             }), c.assertion.modality),
        )

    def add_generation_assertions(self, generation_id: str, assertion_ids: list[str]) -> None:
        for aid in assertion_ids:
            self.con.execute(
                "INSERT OR IGNORE INTO generation_assertion (generation_id, assertion_id) VALUES (?,?)",
                (generation_id, aid),
            )

    def generation_assertion_ids(self, generation_id: str) -> list[str]:
        rows = self.con.execute(
            "SELECT assertion_id FROM generation_assertion WHERE generation_id=?", (generation_id,)
        ).fetchall()
        return [r[0] for r in rows]

    def get_assertions(self, assertion_ids: list[str]):
        """Reconstruct CompiledClaim objects for a set of assertion_ids (multi-source safe)."""
        import json

        from .claims import CompiledClaim
        from .models import ClaimAssertion, ClaimIdentity, Evidence

        out = []
        for aid in sorted(assertion_ids):
            arow = self.con.execute(
                "SELECT claim_id, source_id, evidence_json, modality FROM assertion WHERE assertion_id=?",
                (aid,),
            ).fetchone()
            if arow is None:
                continue
            claim_id, source_id, ev_json, modality = arow
            crow = self.con.execute(
                "SELECT subject, predicate, object, polarity, scope_json FROM claim_identity WHERE claim_id=?",
                (claim_id,),
            ).fetchone()
            if crow is None:
                continue
            subj, pred, obj, pol, scope_json = crow
            ev = json.loads(ev_json)
            identity = ClaimIdentity(claim_id, subj, pred, obj, pol, json.loads(scope_json))
            evidence = Evidence(ev["evidence_id"], ev["source_object_hash"],
                                ev["representation_hash"], ev["quote_hash"], tuple(ev["locators"]))
            assertion = ClaimAssertion(aid, claim_id, source_id, (ev["evidence_id"],), modality)
            out.append(CompiledClaim(identity=identity, assertion=assertion, evidence=evidence))
        return out

    def generation_seq(self, generation_id: str) -> int:
        row = self.con.execute("SELECT seq FROM generation WHERE generation_id=?", (generation_id,)).fetchone()
        return row[0] if row else -1

    def mark_read_model(self, generation_id: str, model_name: str, digest: str) -> None:
        self.con.execute(
            "INSERT OR REPLACE INTO read_model_status "
            "(generation_id, model_name, state, artifact_digest) VALUES (?,?, 'ready', ?)",
            (generation_id, model_name, digest),
        )

    def set_read_models_ready(self, generation_id: str) -> None:
        self.con.execute(
            "UPDATE generation SET state='read_models_ready' WHERE generation_id=? AND state='validated'",
            (generation_id,),
        )

    def current_pointer(self) -> str | None:
        return self.con.execute("SELECT current_generation_id FROM publication WHERE id=1").fetchone()[0]

    def current_release_oid(self) -> str | None:
        return self.con.execute("SELECT current_release_commit_oid FROM publication WHERE id=1").fetchone()[0]

    def generation_state(self, generation_id: str) -> str | None:
        row = self.con.execute("SELECT state FROM generation WHERE generation_id=?", (generation_id,)).fetchone()
        return row[0] if row else None

    def generation_commit(self, generation_id: str) -> str | None:
        row = self.con.execute(
            "SELECT candidate_commit_oid FROM generation WHERE generation_id=?", (generation_id,)
        ).fetchone()
        return row[0] if row else None

    # -- claim resolution + search read model (SUB-07) --------------------- #
    def record_resolution(self, generation_id: str, claim_id: str, state: str) -> None:
        self.con.execute(
            "INSERT OR REPLACE INTO claim_resolution (generation_id, claim_id, state) VALUES (?,?,?)",
            (generation_id, claim_id, state),
        )

    def resolution_state(self, generation_id: str, claim_id: str) -> str | None:
        row = self.con.execute(
            "SELECT state FROM claim_resolution WHERE generation_id=? AND claim_id=?",
            (generation_id, claim_id),
        ).fetchone()
        return row[0] if row else None

    def accepted_claims(self, generation_id: str) -> list[str]:
        rows = self.con.execute(
            "SELECT claim_id FROM claim_resolution WHERE generation_id=? AND state='accepted'",
            (generation_id,),
        ).fetchall()
        return [r[0] for r in rows]

    def build_search_index(self, generation_id: str, entries: list[tuple[str, str, str, str]]) -> None:
        for claim_id, subject, predicate, obj in entries:
            self.con.execute(
                "INSERT OR REPLACE INTO search_index "
                "(generation_id, claim_id, subject, predicate, object) VALUES (?,?,?,?,?)",
                (generation_id, claim_id, subject, predicate, obj),
            )

    def search_index_lookup(self, generation_id: str, term: str) -> list[tuple[str, str, str, str]]:
        like = f"%{term}%"
        rows = self.con.execute(
            "SELECT claim_id, subject, predicate, object FROM search_index "
            "WHERE generation_id=? AND (subject LIKE ? OR predicate LIKE ? OR object LIKE ?)",
            (generation_id, like, like, like),
        ).fetchall()
        return list(rows)

    def set_search_pointer(self, generation_id: str) -> None:
        self.con.execute(
            "UPDATE publication SET current_search_generation_id=? WHERE id=1", (generation_id,)
        )

    def current_search_pointer(self) -> str | None:
        return self.con.execute(
            "SELECT current_search_generation_id FROM publication WHERE id=1"
        ).fetchone()[0]

    # -- authoritative activation (single transaction) --------------------- #
    def activate(
        self,
        generation_id: str,
        expected_parent: str | None,
        release_commit_oid: str,
    ) -> None:
        con = self.con
        # Required artifacts are read from the REGISTERED signed manifest, never from
        # the caller (so an empty/forged list cannot bypass the binding check).
        required_read_models = self._required_from_manifest(generation_id)
        if not required_read_models:
            raise ActivationError("no required read models in registered manifest")
        con.execute("BEGIN IMMEDIATE")
        try:
            cur = con.execute("SELECT current_generation_id FROM publication WHERE id=1").fetchone()[0]
            if cur != expected_parent:
                raise CASConflict(f"expected parent {expected_parent!r}, found {cur!r}")

            state = self.generation_state(generation_id)
            if state != "read_models_ready":
                raise ActivationError(f"generation state must be read_models_ready, is {state!r}")

            rel = con.execute(
                "SELECT release_commit_oid FROM generation WHERE generation_id=?", (generation_id,)
            ).fetchone()[0]
            if not rel or rel != release_commit_oid:
                raise ActivationError("release commit not registered / mismatch")

            for model_name, expected_digest in required_read_models:
                row = con.execute(
                    "SELECT state, artifact_digest FROM read_model_status WHERE generation_id=? AND model_name=?",
                    (generation_id, model_name),
                ).fetchone()
                if row is None or row[0] != "ready":
                    raise ActivationError(f"read model {model_name} not ready")
                if row[1] != expected_digest:
                    raise ActivationError(f"read model {model_name} digest mismatch")

            con.execute(
                "UPDATE generation SET state='published' WHERE generation_id=? AND state='read_models_ready'",
                (generation_id,),
            )
            if cur is not None:
                con.execute("UPDATE generation SET state='superseded' WHERE generation_id=?", (cur,))

            if expected_parent is None:
                changed = con.execute(
                    "UPDATE publication SET current_generation_id=?, current_release_commit_oid=? "
                    "WHERE id=1 AND current_generation_id IS NULL",
                    (generation_id, release_commit_oid),
                ).rowcount
            else:
                changed = con.execute(
                    "UPDATE publication SET current_generation_id=?, current_release_commit_oid=? "
                    "WHERE id=1 AND current_generation_id=?",
                    (generation_id, release_commit_oid, expected_parent),
                ).rowcount
            if changed != 1:
                raise CASConflict("pointer moved during activation")

            con.execute(
                "INSERT INTO outbox (event_type, generation_id) VALUES ('release_mirror_requested', ?)",
                (generation_id,),
            )
            con.execute("COMMIT")
        except BaseException:
            con.execute("ROLLBACK")
            raise

    # -- outbox relay ------------------------------------------------------ #
    def pending_outbox(self) -> list[tuple[int, str, str]]:
        return list(
            self.con.execute(
                "SELECT event_id, event_type, generation_id FROM outbox WHERE processed=0 ORDER BY event_id"
            )
        )

    def mark_outbox_processed(self, event_id: int) -> None:
        self.con.execute("UPDATE outbox SET processed=1 WHERE event_id=?", (event_id,))

    def orphan_generations(self) -> list[str]:
        rows = self.con.execute(
            "SELECT generation_id FROM generation WHERE state IN ('validated','read_models_ready')"
        ).fetchall()
        return [r[0] for r in rows]

    def close(self) -> None:
        try:
            self.con.close()
        except Exception:
            pass

    def __del__(self) -> None:
        self.close()
