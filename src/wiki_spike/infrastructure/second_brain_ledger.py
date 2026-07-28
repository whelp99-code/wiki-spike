"""Durable Stage-3 ledger authority backed exclusively by LifecycleDatabase."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import sqlite3
from typing import Callable, Mapping

from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    CandidateOutcomeV2, ConflictOutcomeV2, GateStateV2, LedgerCommandV2,
    LedgerReceiptV2, RecallAuthorityV2, RecallCitationV2, RecallSnapshotRequestV2,
    canonical_ledger_digest, make_recall_snapshot_v2,
)
from wiki_spike.memory_core.second_brain_ledger_ports import (
    AtomicRecallSnapshotPort, LedgerCommandPort, ValidatedRecallSnapshotAcquisitionV2,
)


class LedgerAuthorityError(RuntimeError):
    """A command did not have the durable authority it claimed."""


@dataclass(frozen=True)
class LedgerAuthority:
    capability_ref: str
    authority_epoch: str
    state: str = "ACTIVE"


class LifecycleLedgerAuthority(LedgerCommandPort, AtomicRecallSnapshotPort):
    """The only Stage-3 writer and snapshot reader.

    The database is deliberately the sole mutable ledger: CAS objects may be
    written before the SQLite transaction, but no CAS object is treated as a
    visible ledger fact until its matching row commits.
    """
    def __init__(self, database: LifecycleDatabase, cas: object | None = None) -> None:
        self._db = database
        self._cas = cas

    def set_authority(self, workspace_ref: str, authority: LedgerAuthority, updated_at: str) -> None:
        if authority.state not in {"ACTIVE", "REVOKED"}:
            raise LedgerAuthorityError("authority state is closed")
        with self._db.unit_of_work() as uow:
            uow._con.execute(
                "INSERT INTO ledger_authority(workspace_ref,capability_ref,authority_epoch,authority_state,updated_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(workspace_ref) DO UPDATE SET capability_ref=excluded.capability_ref,authority_epoch=excluded.authority_epoch,authority_state=excluded.authority_state,updated_at=excluded.updated_at",
                (workspace_ref, authority.capability_ref, authority.authority_epoch, authority.state, updated_at),
            )

    def append_ledger_command(self, command: LedgerCommandV2) -> LedgerReceiptV2:
        # CAS is intentionally only an immutable availability check. The closed
        # command wire contains digests, never plaintext/envelope bytes.
        if command.payload.content_digest and self._cas is not None and not self._cas.exists(command.payload.content_digest):
            raise LedgerAuthorityError("immutable encrypted intent/evidence is unavailable")
        with self._db.unit_of_work() as uow:
            con = uow._con
            prior = con.execute("SELECT receipt_digest,transaction_sequence,ledger_epoch FROM ledger_command WHERE command_ref=?", (command.command_ref,)).fetchone()
            if prior:
                if con.execute("SELECT command_digest FROM ledger_command WHERE command_ref=?", (command.command_ref,)).fetchone()[0] != command.command_digest:
                    raise LedgerAuthorityError("command reference was reused with a different digest")
                return self._receipt(command, prior[1], prior[2], prior[0])
            authority = con.execute("SELECT capability_ref,authority_epoch,authority_state FROM ledger_authority WHERE workspace_ref=?", (command.workspace_ref,)).fetchone()
            if authority is None or tuple(authority) != (command.capability_ref, command.authority_epoch, "ACTIVE"):
                raise LedgerAuthorityError("capability or expected authority epoch is stale")
            current = con.execute("SELECT candidate_state,workspace_ref,revision_ref FROM ledger_candidate WHERE candidate_ref=?", (command.payload.candidate_ref,)).fetchone()
            if command.kind == "CREATE_CANDIDATE":
                if current is not None:
                    raise LedgerAuthorityError("candidate already exists")
            else:
                if current is None or current[1] != command.workspace_ref or current[0] != command.payload.prior_state:
                    raise LedgerAuthorityError("candidate expected revision/state is stale")
            self._validate_edges(con, command)
            sequence = str((con.execute("SELECT COUNT(*) FROM ledger_command WHERE workspace_ref=?", (command.workspace_ref,)).fetchone()[0]) + 1)
            epoch = sequence
            revision_ref = "revision:" + sha256((command.command_ref + command.command_digest).encode()).hexdigest()
            if command.kind == "CREATE_CANDIDATE":
                con.execute("INSERT INTO ledger_candidate VALUES(?,?,?,?,?,?,?,?,?,?)", (command.payload.candidate_ref, command.workspace_ref, "PENDING", revision_ref, command.payload.content_digest, command.authority_epoch, command.interval.valid_from, command.interval.valid_to, command.interval.recorded_from, command.interval.recorded_to))
            else:
                content = command.payload.content_digest or con.execute("SELECT content_digest FROM ledger_candidate WHERE candidate_ref=?", (command.payload.candidate_ref,)).fetchone()[0]
                con.execute("UPDATE ledger_candidate SET candidate_state=?,revision_ref=?,content_digest=?,authority_epoch=?,recorded_to_at=? WHERE candidate_ref=?", (command.payload.resulting_state, revision_ref, content, command.authority_epoch, command.interval.recorded_from, command.payload.candidate_ref))
                con.execute("UPDATE ledger_candidate SET recorded_to_at=NULL,recorded_from_at=? WHERE candidate_ref=?", (command.interval.recorded_from, command.payload.candidate_ref))
            content = command.payload.content_digest or con.execute("SELECT content_digest FROM ledger_candidate WHERE candidate_ref=?", (command.payload.candidate_ref,)).fetchone()[0]
            con.execute("INSERT INTO ledger_revision VALUES(?,?,?,?,?,?)", (revision_ref, command.payload.candidate_ref, command.workspace_ref, content, command.payload.resulting_state, command.interval.recorded_from))
            con.execute("INSERT INTO ledger_transition VALUES(?,?,?,?,?,?,?,?)", (command.command_ref, command.payload.candidate_ref, command.workspace_ref, command.payload.prior_state, command.payload.resulting_state, command.authority_epoch, command.command_digest, command.interval.recorded_from))
            for edge in command.payload.support_edges + command.payload.contradiction_edges:
                edge_ref = "edge:" + sha256((command.command_ref + edge.edge_kind + edge.from_candidate_ref + edge.to_candidate_ref).encode()).hexdigest()
                con.execute("INSERT INTO ledger_edge VALUES(?,?,?,?,?,?,?,?,?,?)", (edge_ref, edge.workspace_ref, edge.edge_kind, edge.from_candidate_ref, edge.to_candidate_ref, "SUPERSEDED" if command.kind == "SUPERSEDE" else "ACTIVE", edge.interval.valid_from, edge.interval.valid_to, edge.interval.recorded_from, edge.interval.recorded_to))
            if command.kind in {"REVOKE", "FORGET"}:
                self._invalidate_supported_candidates(con, command.payload.candidate_ref, command.interval.recorded_from, command.authority_epoch)
            receipt_digest = canonical_ledger_digest("receipt-v2", {"receipt_version":"second-brain-ledger-receipt-v2", "command_ref":command.command_ref, "workspace_ref":command.workspace_ref, "transaction_cut":sequence, "ledger_epoch":epoch})
            con.execute("INSERT INTO ledger_command VALUES(?,?,?,?,?,?,?,?)", (command.command_ref, command.workspace_ref, command.command_digest, receipt_digest, sequence, epoch, "COMMITTED", command.interval.recorded_from))
            uow.append_event(uow.event_chain_head(), "LEDGER_COMMAND", command.command_digest)
            con.execute(
                "INSERT INTO outbox(event_kind,ref_digest,outbox_state) VALUES(?,?,?)",
                ("LEDGER_COMMAND", command.command_digest, "PENDING"),
            )
            return self._receipt(command, sequence, epoch, receipt_digest)

    def _receipt(self, command: LedgerCommandV2, cut: str, epoch: str, digest: str) -> LedgerReceiptV2:
        return LedgerReceiptV2("second-brain-ledger-receipt-v2", command.command_ref, command.workspace_ref, cut, epoch, digest)

    def _validate_edges(self, con: sqlite3.Connection, command: LedgerCommandV2) -> None:
        for edge in command.payload.support_edges + command.payload.contradiction_edges:
            if edge.from_candidate_ref == edge.to_candidate_ref:
                raise LedgerAuthorityError("self edge is forbidden")
            for ref in (edge.from_candidate_ref, edge.to_candidate_ref):
                row = con.execute("SELECT workspace_ref FROM ledger_candidate WHERE candidate_ref=?", (ref,)).fetchone()
                # A CREATE command may reference its new candidate only; all
                # other endpoints must already be durable workspace members.
                if ref != command.payload.candidate_ref and (row is None or row[0] != command.workspace_ref):
                    raise LedgerAuthorityError("edge crosses workspace or references an absent candidate")
            duplicate = con.execute("SELECT 1 FROM ledger_edge WHERE workspace_ref=? AND edge_kind=? AND from_candidate_ref=? AND to_candidate_ref=? AND edge_state='ACTIVE'", (edge.workspace_ref, edge.edge_kind, edge.from_candidate_ref, edge.to_candidate_ref)).fetchone()
            if duplicate:
                raise LedgerAuthorityError("duplicate edge")
            if edge.edge_kind == "SUPPORT" and self._reachable(con, edge.to_candidate_ref, edge.from_candidate_ref):
                raise LedgerAuthorityError("support graph cycle")

    @staticmethod
    def _invalidate_supported_candidates(con: sqlite3.Connection, root: str, recorded_at: str, authority_epoch: str) -> None:
        """Revoke reverse-reachable support dependents in the command transaction."""
        seen, queue = {root}, [root]
        while queue:
            source = queue.pop(0)
            for (child,) in con.execute(
                "SELECT to_candidate_ref FROM ledger_edge WHERE edge_kind='SUPPORT' AND edge_state='ACTIVE' AND from_candidate_ref=?",
                (source,),
            ):
                if child in seen:
                    continue
                seen.add(child)
                queue.append(child)
                if con.execute("SELECT candidate_state FROM ledger_candidate WHERE candidate_ref=?", (child,)).fetchone()[0] == "APPROVED":
                    con.execute(
                        "UPDATE ledger_candidate SET candidate_state='REVOKED',authority_epoch=?,recorded_from_at=?,recorded_to_at=NULL WHERE candidate_ref=?",
                        (authority_epoch, recorded_at, child),
                    )
    @staticmethod
    def _reachable(con: sqlite3.Connection, start: str, target: str) -> bool:
        seen, queue = set(), [start]
        while queue:
            node = queue.pop(0)
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            queue.extend(r[0] for r in con.execute("SELECT to_candidate_ref FROM ledger_edge WHERE edge_kind='SUPPORT' AND edge_state='ACTIVE' AND from_candidate_ref=?", (node,)))
        return False

    def acquire_recall_snapshot(self, request: RecallSnapshotRequestV2) -> ValidatedRecallSnapshotAcquisitionV2:
        con = self._db.con
        assert con is not None, "initialize() not called"
        con.row_factory = sqlite3.Row
        con.execute("BEGIN")
        try:
            authority = con.execute("SELECT capability_ref,authority_epoch,authority_state FROM ledger_authority WHERE workspace_ref=?", (request.workspace_ref,)).fetchone()
            allowed = authority is not None and tuple(authority) == (request.capability_ref, request.authority_epoch, "ACTIVE")
            rows = con.execute(
                "SELECT * FROM ledger_candidate AS candidate WHERE workspace_ref=? AND candidate_state='APPROVED' "
                "AND valid_from_at<=? AND (valid_to_at IS NULL OR valid_to_at>?) "
                "AND NOT EXISTS (SELECT 1 FROM ledger_edge AS edge WHERE edge.workspace_ref=candidate.workspace_ref "
                "AND edge.from_candidate_ref=candidate.candidate_ref AND edge.edge_state='SUPERSEDED')",
                (request.workspace_ref, request.valid_at, request.valid_at),
            ).fetchall() if allowed else []
            displayed = {r["candidate_ref"] for r in rows}
            support_refs = {
                row["candidate_ref"]: tuple(
                    edge[0] for edge in con.execute(
                        "SELECT to_candidate_ref FROM ledger_edge WHERE edge_kind='SUPPORT' AND from_candidate_ref=? AND edge_state='ACTIVE'",
                        (row["candidate_ref"],),
                    )
                )
                for row in rows
            }
            conflicts = con.execute("SELECT from_candidate_ref,to_candidate_ref FROM ledger_edge WHERE workspace_ref=? AND edge_kind='CONTRADICTION' AND edge_state='ACTIVE'", (request.workspace_ref,)).fetchall() if allowed else []
            cut = str(con.execute("SELECT COUNT(*) FROM ledger_command WHERE workspace_ref=?", (request.workspace_ref,)).fetchone()[0] or 1)
        except BaseException:
            con.execute("ROLLBACK"); raise
        else:
            con.execute("COMMIT")
        digest = sha256((request.workspace_ref + cut).encode()).hexdigest()
        ref = lambda kind: f"{kind}:{digest}"
        gate = GateStateV2("PASS" if allowed else "DENY", request.authority_epoch, digest)
        candidates = tuple(
            CandidateOutcomeV2(row["candidate_ref"], row["revision_ref"], row["candidate_state"], row["content_digest"], support_refs[row["candidate_ref"]])
            for row in rows
        )
        citations = tuple(
            RecallCitationV2(
                "second-brain-recall-citation-v2",
                row["candidate_ref"],
                f"source:{row['content_digest']}",
                canonical_ledger_digest(
                    "citation-v2",
                    {
                        "candidate_ref": row["candidate_ref"],
                        "revision_ref": row["revision_ref"],
                        "content_digest": row["content_digest"],
                        "transaction_cut": cut,
                    },
                ),
            ).to_mapping()
            for row in rows
        )
        body = {"snapshot_version":"second-brain-recall-serve-snapshot-v2", "workspace_ref":request.workspace_ref, "capability_ref":request.capability_ref, "authority_epoch":request.authority_epoch, "query_digest":request.query_digest, "transaction_cut":cut, "valid_at":request.valid_at, "recorded_at":request.recorded_at, "scope_digest":request.scope_digest, "generation_ref":ref("generation"), "generation_digest":digest, "checkpoint_ref":ref("checkpoint"), "checkpoint_digest":digest, "freshness_digest":digest, "authority_checkpoint_digest":digest, "authorization":RecallAuthorityV2("ALLOW" if allowed else "DENY", request.capability_ref, request.authority_epoch, request.query_digest, request.workspace_ref, request.scope_digest).to_mapping(), "global_floor":gate.to_mapping(), "binding":gate.to_mapping(), "recovery":gate.to_mapping(), "route":gate.to_mapping(), "cohort":gate.to_mapping(), "deletion":gate.to_mapping(), "consent":gate.to_mapping(), "projection_digest":digest, "contract_digest":digest, "base_snapshot_digest":None, "incoming_cursor_digest":None, "incoming_continuation_ref":None, "candidates":[item.to_mapping() for item in candidates], "conflicts":[ConflictOutcomeV2(r[0],r[1],"OPEN").to_mapping() for r in conflicts if r[0] in displayed and r[1] in displayed], "citations":citations, "continuation":None}
        return ValidatedRecallSnapshotAcquisitionV2(request, make_recall_snapshot_v2(body))
