"""Durable Stage-3 ledger authority backed exclusively by LifecycleDatabase."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import sqlite3
from typing import Any, Callable, Mapping

from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2, CandidateOutcomeV2, CitationEvidenceV2,
    ConflictOutcomeV2, LedgerCommandV2, LedgerReceiptV2,
    RecallAuthorityV2, RecallCitationV2, RecallContinuationV2, RecallSnapshotRequestV2,
    RecallTrustAuthorityV2, canonical_ledger_bytes, canonical_ledger_digest,
    canonical_ledger_instant, make_recall_continuation_v2, make_recall_snapshot_v2,
)
from wiki_spike.memory_core.second_brain_ledger_ports import (
    AtomicRecallSnapshotPort, LedgerCommandPort, ValidatedRecallSnapshotAcquisitionV2,
)


_CONTINUATION_TTL_SECONDS = 300
# Mirrors second_brain_ledger_contracts._MAX_CLOCK_SKEW_SECONDS (F8): the bound
# tolerated between a request's declared recorded_at and the trusted clock.
_MAX_RECALL_CLOCK_SKEW_SECONDS = 30

class LedgerAuthorityError(RuntimeError):
    """A command did not have the durable authority it claimed."""


@dataclass(frozen=True)
class LedgerAuthority:
    capability_ref: str
    authority_epoch: str
    state: str = "ACTIVE"


class LifecycleLedgerAuthority(LedgerCommandPort, AtomicRecallSnapshotPort):
    """Stage-3's durable writer and separately-connected immutable snapshot reader."""

    def __init__(
        self,
        database: LifecycleDatabase,
        cas: object,
        trust_authority: RecallTrustAuthorityV2,
        snapshot_signer: Callable[[bytes], str],
        *,
        signer_ref: str,
        key_id: str,
        page_size: int = 50,
        # Recall pages a whole SUPPORT/CONTRADICTION connected component at a time so a
        # served page can never split off-page a support ref or contradiction endpoint
        # (see LifecycleLedgerAuthority._page_components). `page_size` therefore bounds
        # candidates per page *except* when a single component is larger than
        # `page_size`; that component is still served whole, on its own page.
    ) -> None:
        if not isinstance(trust_authority, RecallTrustAuthorityV2):
            raise LedgerAuthorityError("a minted RecallTrustAuthorityV2 is required")
        if not callable(snapshot_signer):
            raise LedgerAuthorityError("a trusted snapshot signer is required")
        if cas is None or not callable(getattr(cas, "available", None)):
            raise LedgerAuthorityError("a content-addressed availability authority is required")
        if not isinstance(page_size, int) or isinstance(page_size, bool) or not 1 <= page_size <= 500:
            raise LedgerAuthorityError("recall page size must be a bounded positive batch")
        self._db, self._cas = database, cas
        self._trust_authority, self._snapshot_signer = trust_authority, snapshot_signer
        self._signer_ref, self._key_id = signer_ref, key_id
        self._page_size = page_size

    def set_authority(self, workspace_ref: str, authority: LedgerAuthority, updated_at: str) -> None:
        if authority.state not in {"ACTIVE", "REVOKED"}:
            raise LedgerAuthorityError("authority state is closed")
        recorded_at = self._trusted_timestamp()
        self._classify_legacy_workspace(workspace_ref)
        with self._db.unit_of_work() as uow:
            con = uow._con
            if con.execute("SELECT 1 FROM ledger_authority WHERE workspace_ref=?", (workspace_ref,)).fetchone():
                raise LedgerAuthorityError("authority registration is immutable")
            sequence, epoch = self._next_sequence(con, workspace_ref, recorded_at)
            if sequence != "1":
                raise LedgerAuthorityError("authority registration must be the first workspace mutation")
            con.execute(
                "INSERT INTO ledger_authority VALUES(?,?,?,?,?)",
                (workspace_ref, authority.capability_ref, authority.authority_epoch, authority.state, recorded_at),
            )
            digest = canonical_ledger_digest("ledger-migration-v2", {"workspace_ref": workspace_ref, "migration_state": "SERVING_READY", "transaction_cut": sequence})
            con.execute("INSERT INTO ledger_migration VALUES(?,?,?,?,?)", ("migration:" + sha256((workspace_ref + digest).encode()).hexdigest(), workspace_ref, "SERVING_READY", digest, recorded_at))

    def purge_expired_recall_cursors(self) -> int:
        """F6 retention convenience: purge ``ledger_recall_cursor`` rows that
        have expired as of this authority's own trusted clock. Delegates to
        the narrow, trigger-backstopped DB primitive -- see
        ``LifecycleDatabase.purge_expired_recall_cursors``."""
        return self._db.purge_expired_recall_cursors(self._trusted_timestamp())

    def append_ledger_command(self, command: LedgerCommandV2) -> LedgerReceiptV2:
        self._classify_legacy_workspace(command.workspace_ref)
        with self._db.unit_of_work() as uow:
            con = uow._con
            prior = con.execute("SELECT command_digest,receipt_digest,transaction_sequence,ledger_epoch FROM ledger_command WHERE command_ref=?", (command.command_ref,)).fetchone()
            if prior:
                if prior[0] != command.command_digest:
                    raise LedgerAuthorityError("command reference was reused with a different digest")
                return self._receipt(command, prior[2], prior[3], prior[1])
            now = self._trusted_timestamp()
            self._require_serving_ready(con, command.workspace_ref)
            current_sequence = con.execute("SELECT transaction_sequence FROM ledger_sequence WHERE workspace_ref=?", (command.workspace_ref,)).fetchone()
            provenance = self._verify_command_provenance(command, now)
            try:
                content_available = (
                    self._cas.available(command.payload.content_digest)
                    if command.payload.content_digest
                    else True
                )
            except Exception as exc:
                raise LedgerAuthorityError("immutable encrypted intent/evidence availability is unavailable") from exc
            if not content_available:
                raise LedgerAuthorityError("immutable encrypted intent/evidence is unavailable")
            authority = con.execute("SELECT capability_ref,authority_epoch,authority_state FROM ledger_authority WHERE workspace_ref=?", (command.workspace_ref,)).fetchone()
            if authority is None or tuple(authority) != (command.capability_ref, command.authority_epoch, "ACTIVE"):
                raise LedgerAuthorityError("capability or expected authority epoch is stale")
            self._persist_provenance(con, provenance, command.command_ref, None, now)
            current = con.execute("SELECT candidate_state,workspace_ref,revision_ref,content_digest FROM ledger_candidate WHERE candidate_ref=?", (command.payload.candidate_ref,)).fetchone()
            if command.kind == "CREATE_CANDIDATE":
                if current is not None: raise LedgerAuthorityError("candidate already exists")
            elif current is None or tuple(current[:3]) != (command.payload.prior_state, command.workspace_ref, command.expected_active_revision_ref):
                raise LedgerAuthorityError("candidate expected revision/state is stale")
            if provenance.transaction_cut != (current_sequence[0] if current_sequence else None):
                raise LedgerAuthorityError("authority provenance does not exactly authorize this command")
            self._validate_edges(con, command)
            sequence, epoch = self._next_sequence(con, command.workspace_ref, now)
            revision_ref = "revision:" + sha256((command.command_ref + command.command_digest).encode()).hexdigest()
            content = command.payload.content_digest or (current[3] if current else None)
            if not content: raise LedgerAuthorityError("candidate content is absent")
            if current is not None:
                con.execute("UPDATE ledger_candidate SET recorded_to_at=? WHERE candidate_ref=? AND recorded_to_at IS NULL", (now, command.payload.candidate_ref))
                con.execute("INSERT INTO ledger_candidate_version_closure VALUES(?,?,?,?)", (command.payload.candidate_ref, current[2], sequence, now))
            values = (command.payload.candidate_ref, command.workspace_ref, command.payload.resulting_state, revision_ref, content, command.authority_epoch, command.interval.valid_from, command.interval.valid_to, now, None)
            con.execute("INSERT INTO ledger_candidate VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(candidate_ref) DO UPDATE SET workspace_ref=excluded.workspace_ref,candidate_state=excluded.candidate_state,revision_ref=excluded.revision_ref,content_digest=excluded.content_digest,authority_epoch=excluded.authority_epoch,valid_from_at=excluded.valid_from_at,valid_to_at=excluded.valid_to_at,recorded_from_at=excluded.recorded_from_at,recorded_to_at=NULL", values)
            con.execute("INSERT INTO ledger_candidate_version VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (command.payload.candidate_ref, revision_ref, command.workspace_ref, command.payload.resulting_state, content, command.authority_epoch, command.interval.valid_from, command.interval.valid_to, now, None, sequence, None, command.command_ref))
            con.execute("INSERT INTO ledger_revision VALUES(?,?,?,?,?,?)", (revision_ref, command.payload.candidate_ref, command.workspace_ref, content, command.payload.resulting_state, now))
            self._commit_citation(con, command, revision_ref, content, sequence, epoch, now)
            con.execute("INSERT INTO ledger_transition VALUES(?,?,?,?,?,?,?,?)", (command.command_ref, command.payload.candidate_ref, command.workspace_ref, command.payload.prior_state, command.payload.resulting_state, command.authority_epoch, command.command_digest, now))
            for edge in command.payload.support_edges + command.payload.contradiction_edges:
                edge_ref = "edge:" + sha256((command.command_ref + edge.edge_kind + edge.from_candidate_ref + edge.to_candidate_ref).encode()).hexdigest()
                con.execute("INSERT INTO ledger_edge VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (edge_ref, edge.workspace_ref, edge.edge_kind, edge.from_candidate_ref, edge.to_candidate_ref, "SUPERSEDED" if command.kind == "SUPERSEDE" else "ACTIVE", edge.interval.valid_from, edge.interval.valid_to, now, None, sequence, None))
            if command.kind in {"REVOKE", "FORGET"}:
                self._invalidate_supported_candidates(con, command.payload.candidate_ref, now, command.authority_epoch, sequence)
            receipt_digest = canonical_ledger_digest("receipt-v2", {"receipt_version": "second-brain-ledger-receipt-v2", "command_ref": command.command_ref, "workspace_ref": command.workspace_ref, "transaction_cut": sequence, "ledger_epoch": epoch})
            con.execute("INSERT INTO ledger_command VALUES(?,?,?,?,?,?,?,?)", (command.command_ref, command.workspace_ref, command.command_digest, receipt_digest, sequence, epoch, "COMMITTED", now))
            uow.append_event(uow.event_chain_head(), "LEDGER_COMMAND", command.command_digest)
            con.execute("INSERT INTO outbox(event_kind,ref_digest,outbox_state) VALUES(?,?,?)", ("LEDGER_COMMAND", command.command_digest, "PENDING"))
            return self._receipt(command, sequence, epoch, receipt_digest)

    def _trusted_timestamp(self) -> str:
        value = self._trust_authority._now()
        try:
            instant = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
        except (TypeError, ValueError) as exc:
            raise LedgerAuthorityError("trusted clock must return canonical UTC") from exc
        return instant.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    def _verify_command_provenance(self, command: LedgerCommandV2, now: str) -> object:
        try:
            provenance = self._trust_authority._provenance(command.authority_provenance_ref, command.authority_provenance_digest)
            provenance.validate_at(now)
        except Exception as exc:
            raise LedgerAuthorityError("authority provenance is unavailable or expired") from exc
        if not self._trust_authority._verify(
            signer_ref=provenance.signer_ref,
            algorithm=provenance.signer_algorithm,
            key_id=provenance.key_id,
            signature=provenance.signature,
            body=provenance.signing_body(),
        ):
            raise LedgerAuthorityError("authority provenance signature is invalid")
        expected = (
            command.workspace_ref,
            command.capability_ref,
            command.authority_epoch,
            command.subject_ref,
            command.action,
            command.scope_digest,
            self._command_provenance_binding(command),
        )
        actual = (
            provenance.workspace_ref,
            provenance.capability_ref,
            provenance.authority_epoch,
            provenance.subject_ref,
            provenance.action,
            provenance.scope_digest,
            provenance.command_payload_digest,
        )
        if (
            tuple(gate.state for gate in provenance.component_states)
            != ("PASS",) * len(provenance.component_states)
            or len(provenance.component_states) != 8
            or actual != expected
        ):
            raise LedgerAuthorityError("authority provenance does not exactly authorize this command")
        return provenance

    @staticmethod
    def _command_provenance_binding(command: LedgerCommandV2) -> str:
        """Bind every command field that is independent of signed provenance."""
        body = command.to_mapping()
        for field in ("authority_provenance_ref", "authority_provenance_digest", "command_digest"):
            body.pop(field)
        return canonical_ledger_digest("command-provenance-binding-v2", body)

    @staticmethod
    def _legacy_workspace_present(con: sqlite3.Connection, workspace: str) -> bool:
        return any(
            con.execute(
                f"SELECT 1 FROM {table} WHERE workspace_ref=? LIMIT 1", (workspace,)
            ).fetchone()
            for table in (
                "ledger_command",
                "ledger_candidate",
                "ledger_candidate_version",
                "ledger_revision",
                "ledger_transition",
                "ledger_edge",
                "ledger_authority",
                "ledger_provenance",
                "ledger_sequence",
            )
        )

    def _classify_legacy_workspace(self, workspace: str) -> None:
        """Commit legacy classification before a later serving rejection can roll it back."""
        recorded_at = self._trusted_timestamp()
        with self._db.unit_of_work() as uow:
            con = uow._con
            if (
                self._legacy_workspace_present(con, workspace)
                and not con.execute(
                    "SELECT 1 FROM ledger_migration WHERE workspace_ref=?", (workspace,)
                ).fetchone()
            ):
                digest = canonical_ledger_digest(
                    "ledger-migration-v2",
                    {"workspace_ref": workspace, "migration_state": "MIGRATION_BLOCKED"},
                )
                con.execute(
                    "INSERT INTO ledger_migration VALUES(?,?,?,?,?)",
                    (
                        "migration:" + sha256((workspace + digest).encode()).hexdigest(),
                        workspace,
                        "MIGRATION_BLOCKED",
                        digest,
                        recorded_at,
                    ),
                )

    @staticmethod
    def _require_serving_ready(con: sqlite3.Connection, workspace: str) -> None:
        row = con.execute("SELECT migration_state FROM ledger_migration WHERE workspace_ref=? ORDER BY rowid DESC LIMIT 1", (workspace,)).fetchone()
        if row is None or row[0] != "SERVING_READY":
            raise LedgerAuthorityError("workspace migration is not serving ready")
    def promote_legacy_workspace(self, workspace_ref: str, verifier: Callable[[sqlite3.Connection, str], str]) -> str:
        """Atomically promote only an externally verified legacy replay."""
        if not callable(verifier):
            raise LedgerAuthorityError("legacy promotion requires a verifier callback")
        self._classify_legacy_workspace(workspace_ref)
        recorded_at = self._trusted_timestamp()
        with self._db.unit_of_work() as uow:
            con = uow._con
            state = con.execute("SELECT migration_state FROM ledger_migration WHERE workspace_ref=? ORDER BY rowid DESC LIMIT 1", (workspace_ref,)).fetchone()
            if state is None or state[0] != "MIGRATION_BLOCKED":
                raise LedgerAuthorityError("workspace is not blocked legacy state")
            receipt_digest = verifier(con, workspace_ref)
            if not isinstance(receipt_digest, str) or len(receipt_digest) != 64:
                raise LedgerAuthorityError("legacy verifier must return an atomic receipt digest")
            receipt = con.execute(
                "SELECT receipt_state FROM ledger_migration_receipt WHERE receipt_digest=? AND workspace_ref=?",
                (receipt_digest, workspace_ref),
            ).fetchone()
            if receipt is None or receipt[0] != "VERIFIED":
                raise LedgerAuthorityError("legacy verifier receipt is not durably verified")
            con.execute("INSERT INTO ledger_migration VALUES(?,?,?,?,?)", ("migration:" + sha256((workspace_ref + receipt_digest).encode()).hexdigest(), workspace_ref, "SERVING_READY", receipt_digest, recorded_at))
            return receipt_digest

    def _persist_provenance(
        self, con: sqlite3.Connection, provenance: AuthorityProvenanceV2,
        command_ref: str | None, request_digest: str | None, recorded_at: str,
    ) -> None:
        payload_hex = canonical_ledger_bytes(
            "authority-provenance-persistence-v2", provenance.to_mapping()
        ).hex()
        row = con.execute(
            "SELECT provenance_digest,workspace_ref,command_ref,request_digest,"
            "provenance_payload_hex FROM ledger_provenance WHERE provenance_ref=?",
            (provenance.provenance_ref,),
        ).fetchone()
        expected = (provenance.provenance_digest, provenance.workspace_ref,
                    command_ref, request_digest, payload_hex)
        if row is not None:
            if tuple(row) != expected:
                raise LedgerAuthorityError("provenance reference conflicts with durable evidence")
            return
        con.execute(
            "INSERT INTO ledger_provenance "
            "(provenance_ref,provenance_digest,workspace_ref,command_ref,"
            "request_digest,provenance_state,recorded_at,provenance_payload_hex) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (provenance.provenance_ref, *expected[:4], "VERIFIED", recorded_at, payload_hex),
        )

    @staticmethod
    def _next_sequence(con: sqlite3.Connection, workspace: str, recorded_at: str) -> tuple[str, str]:
        row = con.execute("SELECT transaction_sequence,ledger_epoch FROM ledger_sequence WHERE workspace_ref=?", (workspace,)).fetchone()
        sequence = str(int(row[0]) + 1) if row else "1"; epoch = str(int(row[1]) + 1) if row else "1"
        con.execute("INSERT INTO ledger_sequence VALUES(?,?,?,?) ON CONFLICT(workspace_ref) DO UPDATE SET transaction_sequence=excluded.transaction_sequence,ledger_epoch=excluded.ledger_epoch,updated_at=excluded.updated_at", (workspace, sequence, epoch, recorded_at))
        return sequence, epoch

    def _receipt(self, command: LedgerCommandV2, cut: str, epoch: str, digest: str) -> LedgerReceiptV2:
        return LedgerReceiptV2("second-brain-ledger-receipt-v2", command.command_ref, command.workspace_ref, cut, epoch, digest)

    @staticmethod
    def _citation_evidence(candidate_ref: str, workspace_ref: str, revision_ref: str, content_digest: str) -> dict[str, str]:
        """Derive the immutable citation evidence a served revision must carry."""
        locator_digest = canonical_ledger_digest(
            "citation-locator-v2",
            {
                "workspace_ref": workspace_ref,
                "candidate_ref": candidate_ref,
                "revision_ref": revision_ref,
                "content_digest": content_digest,
            },
        )
        evidence = {
            "evidence_version": "second-brain-citation-evidence-v2",
            "locator_ref": "locator:" + locator_digest,
            "locator_digest": locator_digest,
            "immutable_source_ref": "source:" + content_digest,
            "revision_ref": revision_ref,
        }
        evidence["evidence_digest"] = canonical_ledger_digest("citation-evidence-v2", evidence)
        return evidence

    @classmethod
    def _citation_digest(cls, candidate_ref: str, evidence: Mapping[str, str]) -> str:
        return canonical_ledger_digest(
            "citation-v2",
            {
                "citation_version": "second-brain-recall-citation-v2",
                "candidate_ref": candidate_ref,
                "evidence": dict(evidence),
            },
        )

    def _served_citation(self, workspace_ref: str, row: sqlite3.Row) -> RecallCitationV2:
        """Serve a committed citation only when it still binds its durable evidence."""
        evidence = self._citation_evidence(
            row["candidate_ref"], workspace_ref, row["revision_ref"], row["content_digest"]
        )
        committed = (
            row["locator_ref"],
            row["locator_digest"],
            row["immutable_source_ref"],
            row["citation_digest"],
        )
        if committed != (
            evidence["locator_ref"],
            evidence["locator_digest"],
            evidence["immutable_source_ref"],
            self._citation_digest(row["candidate_ref"], evidence),
        ):
            raise LedgerAuthorityError("durable citation commitment failed revalidation")
        return RecallCitationV2(
            "second-brain-recall-citation-v2",
            row["candidate_ref"],
            CitationEvidenceV2.from_mapping(evidence),
            row["citation_digest"],
        )

    def _commit_citation(
        self, con: sqlite3.Connection, command: LedgerCommandV2, revision_ref: str,
        content_digest: str, sequence: str, epoch: str, recorded_at: str,
    ) -> None:
        """Commit the durable citation evidence that authorizes serving this revision."""
        candidate_ref, workspace_ref = command.payload.candidate_ref, command.workspace_ref
        evidence = self._citation_evidence(candidate_ref, workspace_ref, revision_ref, content_digest)
        citation_digest = self._citation_digest(candidate_ref, evidence)
        generation_digest = canonical_ledger_digest(
            "citation-generation-v2",
            {"workspace_ref": workspace_ref, "transaction_cut": sequence, "ledger_epoch": epoch},
        )
        checkpoint_digest = canonical_ledger_digest(
            "citation-checkpoint-v2",
            {
                "workspace_ref": workspace_ref,
                "transaction_cut": sequence,
                "command_ref": command.command_ref,
                "revision_ref": revision_ref,
            },
        )
        con.execute(
            "INSERT INTO ledger_citation_commitment VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                candidate_ref, revision_ref, workspace_ref,
                evidence["locator_ref"], evidence["locator_digest"], evidence["immutable_source_ref"],
                content_digest, "generation:" + generation_digest, "checkpoint:" + checkpoint_digest,
                command.authority_provenance_digest, citation_digest, "COMMITTED", recorded_at,
            ),
        )

    def _validate_edges(self, con: sqlite3.Connection, command: LedgerCommandV2) -> None:
        for edge in command.payload.support_edges + command.payload.contradiction_edges:
            if edge.from_candidate_ref == edge.to_candidate_ref: raise LedgerAuthorityError("self edge is forbidden")
            for ref in (edge.from_candidate_ref, edge.to_candidate_ref):
                row = con.execute("SELECT workspace_ref FROM ledger_candidate WHERE candidate_ref=?", (ref,)).fetchone()
                if ref != command.payload.candidate_ref and (row is None or row[0] != command.workspace_ref): raise LedgerAuthorityError("edge crosses workspace or references an absent candidate")
            if con.execute("SELECT 1 FROM ledger_edge WHERE workspace_ref=? AND edge_kind=? AND from_candidate_ref=? AND to_candidate_ref=? AND edge_state='ACTIVE' AND end_cut IS NULL", (edge.workspace_ref, edge.edge_kind, edge.from_candidate_ref, edge.to_candidate_ref)).fetchone(): raise LedgerAuthorityError("duplicate edge")
            if edge.edge_kind == "SUPPORT" and self._reachable(con, edge.to_candidate_ref, edge.from_candidate_ref): raise LedgerAuthorityError("support graph cycle")

    @staticmethod
    def _invalidate_supported_candidates(con: sqlite3.Connection, root: str, recorded_at: str, authority_epoch: str, cut: str) -> None:
        seen, queue = {root}, [root]
        while queue:
            source = queue.pop(0)
            for (child,) in con.execute("SELECT to_candidate_ref FROM ledger_edge WHERE edge_kind='SUPPORT' AND edge_state='ACTIVE' AND end_cut IS NULL AND from_candidate_ref=?", (source,)):
                if child not in seen:
                    seen.add(child); queue.append(child)
                    row = con.execute("SELECT candidate_state,revision_ref,workspace_ref,content_digest,valid_from_at,valid_to_at FROM ledger_candidate WHERE candidate_ref=?", (child,)).fetchone()
                    if row and row[0] == "APPROVED":
                        revision_ref = "revision:" + sha256(
                            f"cascade:{child}:{row[1]}:{cut}".encode()
                        ).hexdigest()
                        con.execute("INSERT INTO ledger_candidate_version_closure VALUES(?,?,?,?)", (child, row[1], cut, recorded_at))
                        con.execute("UPDATE ledger_candidate SET candidate_state='REVOKED',revision_ref=?,authority_epoch=?,recorded_from_at=?,recorded_to_at=NULL WHERE candidate_ref=?", (revision_ref, authority_epoch, recorded_at, child))
                        con.execute("INSERT INTO ledger_candidate_version VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)", (child, revision_ref, row[2], "REVOKED", row[3], authority_epoch, row[4], row[5], recorded_at, None, cut, None, "cascade:" + cut))
                        con.execute("INSERT INTO ledger_revision VALUES(?,?,?,?,?,?)", (revision_ref, child, row[2], row[3], "REVOKED", recorded_at))

    @staticmethod
    def _reachable(con: sqlite3.Connection, start: str, target: str) -> bool:
        seen, queue = set(), [start]
        while queue:
            node = queue.pop(0)
            if node == target: return True
            if node not in seen:
                seen.add(node)
                queue.extend(row[0] for row in con.execute("SELECT to_candidate_ref FROM ledger_edge WHERE edge_kind='SUPPORT' AND edge_state='ACTIVE' AND end_cut IS NULL AND from_candidate_ref=?", (node,)))
        return False
    @staticmethod
    def _instant_value(value: str) -> datetime:
        return datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)

    @staticmethod
    def _assert_recorded_at_within_skew(recorded_at: str, now: str) -> None:
        """F8: ``recorded_at`` is bitemporal transaction time. A request may look
        back arbitrarily far into recorded history -- the audit/as-of journeys
        depend on exactly that, and un-bounding the past keeps them working --
        but it may never claim knowledge recorded beyond a bounded tolerance
        past the trusted clock, since no request can legitimately assert a
        recorded_at the ledger has not reached yet. Enforced here, immediately,
        rather than left for Core to reject once has_more finally makes the
        drift observable on a later page."""
        recorded = LifecycleLedgerAuthority._instant_value(recorded_at)
        trusted = LifecycleLedgerAuthority._instant_value(now)
        if recorded > trusted + timedelta(seconds=_MAX_RECALL_CLOCK_SKEW_SECONDS):
            raise LedgerAuthorityError(
                "recall recorded_at exceeds the trusted clock skew bound"
            )

    def _verified_recall_provenance(self, request: RecallSnapshotRequestV2) -> object:
        now = self._trusted_timestamp()
        self._assert_recorded_at_within_skew(request.recorded_at, now)
        try:
            provenance = self._trust_authority._provenance(
                request.authority_provenance_ref, request.authority_provenance_digest
            )
            provenance.validate_at(now)
        except Exception as exc:
            raise LedgerAuthorityError("recall authority provenance is unavailable or expired") from exc
        if not self._trust_authority._verify(
            signer_ref=provenance.signer_ref, algorithm=provenance.signer_algorithm,
            key_id=provenance.key_id, signature=provenance.signature,
            body=provenance.signing_body(),
        ):
            raise LedgerAuthorityError("recall authority provenance signature is invalid")
        binding = {
            key: (
                request.continuation.to_mapping()
                if key == "continuation" and request.continuation is not None
                else getattr(request, key)
            )
            for key in RecallSnapshotRequestV2.FIELDS
            - {"authority_provenance_ref", "authority_provenance_digest", "request_digest"}
        }
        expected = (
            request.workspace_ref, request.capability_ref, request.authority_epoch,
            request.subject_ref, request.action, request.scope_digest,
            canonical_ledger_digest("request-provenance-binding-v2", binding),
        )
        actual = (
            provenance.workspace_ref, provenance.capability_ref, provenance.authority_epoch,
            provenance.subject_ref, provenance.action, provenance.scope_digest,
            provenance.request_digest,
        )
        states = provenance.component_states
        if len(states) != 8 or actual != expected or states[0].state not in {"PASS", "DENY", "ABSTAIN"}:
            raise LedgerAuthorityError("recall authority provenance does not exactly authorize request")
        if states[0].state == "PASS" and any(gate.state != "PASS" for gate in states):
            raise LedgerAuthorityError("recall authority provenance does not pass every gate")
        return provenance
    def _reload_verified_provenance(
        self, con: sqlite3.Connection, provenance: AuthorityProvenanceV2, now: str,
    ) -> AuthorityProvenanceV2:
        row = con.execute(
            "SELECT provenance_digest,provenance_state,provenance_payload_hex "
            "FROM ledger_provenance WHERE provenance_ref=?",
            (provenance.provenance_ref,),
        ).fetchone()
        if row is None or row[0] != provenance.provenance_digest or row[1] != "VERIFIED" or not row[2]:
            raise LedgerAuthorityError("durable authority provenance is unavailable")
        try:
            encoded = bytes.fromhex(row[2])
            persisted = AuthorityProvenanceV2.from_mapping(json.loads(encoded.split(b"\0", 1)[1]))
            persisted.validate_at(now)
        except Exception as exc:
            raise LedgerAuthorityError("durable authority provenance is malformed") from exc
        if persisted != provenance or not self._trust_authority._verify(
            signer_ref=persisted.signer_ref, algorithm=persisted.signer_algorithm,
            key_id=persisted.key_id, signature=persisted.signature,
            body=persisted.signing_body(),
        ):
            raise LedgerAuthorityError("durable authority provenance failed revalidation")
        return persisted

    @staticmethod
    def _cursor_state_digest(workspace_ref: str, cut: str, after_candidate_ref: str) -> str:
        return canonical_ledger_digest(
            "cursor-state-v2",
            {
                "workspace_ref": workspace_ref,
                "transaction_cut": cut,
                "after_candidate_ref": after_candidate_ref,
            },
        )

    @staticmethod
    def _continuation_window(issued_raw: str) -> tuple[str, str]:
        """Canonical (issued_at, expires_at) pair for the one shared 300s
        continuation/cursor TTL. F6 wires the durable ``ledger_recall_cursor``
        row's expiry to this exact window so a resume position never outlives
        the signed continuation that points at it."""
        issued = datetime.strptime(issued_raw, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        expires = issued + timedelta(seconds=_CONTINUATION_TTL_SECONDS)
        issued_at, expires_at = (
            canonical_ledger_instant(moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")) for moment in (issued, expires)
        )
        return issued_at, expires_at

    def _resume_after(self, con: sqlite3.Connection, request: RecallSnapshotRequestV2, cut: str) -> str:
        """Resolve the durable resume position an incoming continuation points at."""
        continuation = request.continuation
        if continuation is None:
            return ""
        row = con.execute(
            "SELECT workspace_ref,transaction_sequence,cursor_state_digest,after_candidate_ref,expires_at "
            "FROM ledger_recall_cursor WHERE cursor_handle_ref=?",
            (continuation.cursor_handle_ref,),
        ).fetchone()
        if row is None or tuple(row)[:3] != (
            request.workspace_ref, continuation.transaction_cut, continuation.cursor_state_digest
        ):
            raise LedgerAuthorityError("continuation cursor is not durably resolvable")
        # F6: the row is ephemeral serving state, not durable ledger evidence --
        # once its 300s TTL has elapsed it must refuse resumption even though it
        # remains structurally resolvable, so a stale cursor can never silently
        # keep paging.
        if self._instant_value(row["expires_at"]) <= self._instant_value(self._trusted_timestamp()):
            raise LedgerAuthorityError("continuation cursor has expired and can no longer be resumed")
        after = row["after_candidate_ref"]
        if continuation.cursor_state_digest != self._cursor_state_digest(request.workspace_ref, cut, after):
            raise LedgerAuthorityError("continuation cursor does not bind its durable position")
        return after

    def _issue_cursor(
        self, con: sqlite3.Connection, request: RecallSnapshotRequestV2, cut: str, after_candidate_ref: str,
    ) -> tuple[str, str]:
        """Durably record the next page position and return its handle/state pair."""
        state_digest = self._cursor_state_digest(request.workspace_ref, cut, after_candidate_ref)
        handle_ref = "cursor:" + canonical_ledger_digest(
            "cursor-handle-v2",
            {
                "workspace_ref": request.workspace_ref,
                "transaction_cut": cut,
                "query_digest": request.query_digest,
                "scope_digest": request.scope_digest,
                "cursor_state_digest": state_digest,
            },
        )
        recorded = (request.workspace_ref, cut, state_digest, after_candidate_ref)
        existing = con.execute(
            "SELECT workspace_ref,transaction_sequence,cursor_state_digest,after_candidate_ref "
            "FROM ledger_recall_cursor WHERE cursor_handle_ref=?",
            (handle_ref,),
        ).fetchone()
        if existing is None:
            issued_at, expires_at = self._continuation_window(self._trusted_timestamp())
            con.execute(
                "INSERT INTO ledger_recall_cursor VALUES(?,?,?,?,?,?,?)",
                (handle_ref, *recorded, issued_at, expires_at),
            )
        elif tuple(existing) != recorded:
            raise LedgerAuthorityError("recall cursor handle conflicts with durable evidence")
        return handle_ref, state_digest

    def _seal_continuation(self, unsigned: Mapping[str, Any]) -> RecallContinuationV2:
        """Sign an outgoing continuation once Core has bound it to its snapshot."""
        body = dict(unsigned)
        body["signature"] = self._snapshot_signer(
            canonical_ledger_bytes("signed-v2", {k: v for k, v in body.items() if k != "signature"})
        )
        return make_recall_continuation_v2(body)

    @staticmethod
    def _incoming_chain(continuation: RecallContinuationV2 | None) -> tuple[str | None, str | None, str | None, str | None]:
        """Echo the incoming continuation chain Core revalidates on admission."""
        if continuation is None:
            return None, None, None, None
        return (
            continuation.base_snapshot_digest,
            continuation.cursor_state_digest,
            canonical_ledger_digest(
                "cursor-v2",
                {
                    "cursor_handle_ref": continuation.cursor_handle_ref,
                    "cursor_state_digest": continuation.cursor_state_digest,
                    "base_snapshot_digest": continuation.base_snapshot_digest,
                },
            ),
            continuation.continuation_ref,
        )

    def _outgoing_continuation(
        self, request: RecallSnapshotRequestV2, cut: str, digest: str, cursor: tuple[str, str] | None,
    ) -> dict[str, Any] | None:
        """Unsigned next-page continuation; Core seals it against the bound snapshot."""
        if cursor is None:
            return None
        handle_ref, state_digest = cursor
        issued_at, expires_at = self._continuation_window(self._trusted_timestamp())
        return {
            "continuation_version": "second-brain-recall-continuation-v2",
            "continuation_ref": "continuation:" + canonical_ledger_digest(
                "continuation-ref-v2", {"cursor_handle_ref": handle_ref, "issued_at": issued_at}
            ),
            "workspace_ref": request.workspace_ref,
            "capability_ref": request.capability_ref,
            "authority_epoch": request.authority_epoch,
            "subject_ref": request.subject_ref,
            "action": request.action,
            "query_digest": request.query_digest,
            "scope_digest": request.scope_digest,
            "valid_at": request.valid_at,
            "recorded_at": request.recorded_at,
            "transaction_cut": cut,
            "authority_provenance_ref": request.authority_provenance_ref,
            "authority_provenance_digest": request.authority_provenance_digest,
            "signer_ref": self._signer_ref,
            "signer_algorithm": "Ed25519",
            "key_id": self._key_id,
            "generation_ref": "generation:" + digest,
            "generation_digest": digest,
            "checkpoint_ref": "checkpoint:" + digest,
            "checkpoint_digest": digest,
            "freshness_digest": digest,
            "authority_checkpoint_digest": digest,
            "cursor_handle_ref": handle_ref,
            "cursor_state_digest": state_digest,
            "issued_at": issued_at,
            "expires_at": expires_at,
        }

    @staticmethod
    def _page_components(
        candidate_refs: Any,
        support_edges: Any,
        conflict_edges: Any,
        resume_after: str,
        page_size: int,
    ) -> tuple[frozenset[str], bool, str | None]:
        """Group visible candidates into whole connected components and page components,
        never candidates. A component (candidates transitively joined by SUPPORT or
        CONTRADICTION edges whose endpoints are both visible) is emitted whole or not at
        all, so `page_size` bounds candidates per page except when a single component is
        larger than `page_size` -- that component is still served whole on its own page.
        """
        refs = set(candidate_refs)
        parent = {candidate_ref: candidate_ref for candidate_ref in refs}

        def find(node: str) -> str:
            while parent[node] != node:
                parent[node] = parent[parent[node]]
                node = parent[node]
            return node

        def union(left: str, right: str) -> None:
            root_left, root_right = find(left), find(right)
            if root_left != root_right:
                parent[root_left] = root_right

        for source, target in list(support_edges) + list(conflict_edges):
            if source in refs and target in refs:
                union(source, target)

        groups: dict[str, list[str]] = {}
        for candidate_ref in refs:
            groups.setdefault(find(candidate_ref), []).append(candidate_ref)
        components = sorted(
            (sorted(members) for members in groups.values()), key=lambda members: members[0]
        )
        components = [component for component in components if component[0] > resume_after]

        displayed: set[str] = set()
        total = 0
        last_component_min: str | None = None
        emitted = 0
        for component in components:
            if emitted > 0 and total + len(component) > page_size:
                break
            displayed.update(component)
            total += len(component)
            last_component_min = component[0]
            emitted += 1

        has_more = emitted < len(components)
        return frozenset(displayed), has_more, last_component_min

    def acquire_recall_snapshot(self, request: RecallSnapshotRequestV2) -> ValidatedRecallSnapshotAcquisitionV2:
        provenance = self._verified_recall_provenance(request)
        authorization_state = provenance.component_states[0].state
        if authorization_state == "PASS":
            self._classify_legacy_workspace(request.workspace_ref)
        con = self._db.open_read_connection()
        con.row_factory = sqlite3.Row
        con.execute("BEGIN IMMEDIATE")
        try:
            self._persist_provenance(
                con, provenance, None, request.request_digest, self._trusted_timestamp()
            )
            provenance = self._reload_verified_provenance(
                con, provenance, self._trusted_timestamp()
            )
            authority = con.execute("SELECT capability_ref,authority_epoch,authority_state FROM ledger_authority WHERE workspace_ref=?", (request.workspace_ref,)).fetchone()
            migration = con.execute("SELECT migration_state FROM ledger_migration WHERE workspace_ref=? ORDER BY rowid DESC LIMIT 1", (request.workspace_ref,)).fetchone()
            allowed = authorization_state == "PASS" and authority is not None and migration is not None and migration[0] == "SERVING_READY" and tuple(authority) == (request.capability_ref, request.authority_epoch, "ACTIVE")
            if authorization_state == "PASS" and not allowed:
                raise LedgerAuthorityError("recall requires active durable authority and serving migration")
            cut_row = con.execute("SELECT transaction_sequence FROM ledger_sequence WHERE workspace_ref=?", (request.workspace_ref,)).fetchone()
            if allowed and (cut_row is None or (len(request.transaction_cut), request.transaction_cut) > (len(cut_row[0]), cut_row[0])):
                raise LedgerAuthorityError("requested transaction cut is unavailable")
            cut = request.transaction_cut
            resume_after = self._resume_after(con, request, cut)
            visible = "(length({column})<length(?) OR (length({column})=length(?) AND {column}<=?))"
            all_rows = con.execute(
                f"""SELECT v.*, c.locator_ref, c.locator_digest, c.immutable_source_ref,
                           c.content_digest AS citation_content_digest, c.citation_digest,
                           c.generation_ref, c.checkpoint_ref,
                           c.provenance_digest AS citation_provenance_digest
                   FROM ledger_candidate_version AS v
                   JOIN ledger_citation_commitment AS c
                     ON c.candidate_ref=v.candidate_ref AND c.revision_ref=v.revision_ref
                    AND c.workspace_ref=v.workspace_ref AND c.commitment_state='COMMITTED'
                   WHERE v.workspace_ref=? AND v.candidate_state='APPROVED'
                     AND c.content_digest=v.content_digest
                     AND {visible.format(column='v.start_cut')}
                     AND NOT EXISTS (SELECT 1 FROM ledger_candidate_version_closure vc
                       WHERE vc.candidate_ref=v.candidate_ref AND vc.revision_ref=v.revision_ref
                         AND {visible.format(column='vc.end_cut')})
                     AND NOT EXISTS (SELECT 1 FROM ledger_edge e WHERE e.from_candidate_ref=v.candidate_ref
                       AND e.edge_kind='SUPPORT' AND e.edge_state='SUPERSEDED' AND {visible.format(column='e.start_cut')})
                     AND v.valid_from_at<=? AND (v.valid_to_at IS NULL OR v.valid_to_at>?)
                     AND v.recorded_from_at<=? AND (v.recorded_to_at IS NULL OR v.recorded_to_at>?)
                   ORDER BY v.candidate_ref""",
                (request.workspace_ref, cut, cut, cut, cut, cut, cut, cut, cut, cut, request.valid_at, request.valid_at, request.recorded_at, request.recorded_at),
            ).fetchall() if allowed else []
            support_rows = con.execute(
                f"""SELECT from_candidate_ref,to_candidate_ref FROM ledger_edge e WHERE e.workspace_ref=?
                   AND e.edge_kind='SUPPORT' AND e.edge_state='ACTIVE' AND {visible.format(column='e.start_cut')}
                   AND NOT EXISTS (SELECT 1 FROM ledger_edge_closure ec WHERE ec.edge_ref=e.edge_ref AND {visible.format(column='ec.end_cut')})
                   AND e.valid_from_at<=? AND (e.valid_to_at IS NULL OR e.valid_to_at>?)
                   AND e.recorded_from_at<=? AND (e.recorded_to_at IS NULL OR e.recorded_to_at>?)""",
                (request.workspace_ref, cut, cut, cut, cut, cut, cut, request.valid_at, request.valid_at, request.recorded_at, request.recorded_at),
            ).fetchall() if allowed else []
            conflict_rows = con.execute(
                f"""SELECT from_candidate_ref,to_candidate_ref FROM ledger_edge e WHERE e.workspace_ref=? AND e.edge_kind='CONTRADICTION' AND e.edge_state='ACTIVE'
                   AND {visible.format(column='e.start_cut')}
                   AND NOT EXISTS (SELECT 1 FROM ledger_edge_closure ec WHERE ec.edge_ref=e.edge_ref AND {visible.format(column='ec.end_cut')})
                   AND e.valid_from_at<=? AND (e.valid_to_at IS NULL OR e.valid_to_at>?) AND e.recorded_from_at<=? AND (e.recorded_to_at IS NULL OR e.recorded_to_at>?)
                   ORDER BY from_candidate_ref,to_candidate_ref""",
                (request.workspace_ref, cut, cut, cut, cut, cut, cut, request.valid_at, request.valid_at, request.recorded_at, request.recorded_at),
            ).fetchall() if allowed else []
            displayed_refs, has_more, last_component_min = self._page_components(
                (row["candidate_ref"] for row in all_rows),
                ((row["from_candidate_ref"], row["to_candidate_ref"]) for row in support_rows),
                ((row["from_candidate_ref"], row["to_candidate_ref"]) for row in conflict_rows),
                resume_after,
                self._page_size,
            )
            rows = [row for row in all_rows if row["candidate_ref"] in displayed_refs]
            outgoing_cursor = self._issue_cursor(con, request, cut, last_component_min) if has_more else None
        except BaseException:
            con.execute("ROLLBACK")
            raise
        else:
            con.execute("COMMIT")
        finally:
            con.close()
        if any(not self._cas.available(row["content_digest"]) for row in rows):
            raise LedgerAuthorityError("citation content is unavailable or corrupt")
        digest = sha256((request.workspace_ref + cut).encode()).hexdigest()
        gates = provenance.component_states
        supports: dict[str, list[str]] = {}
        for edge in support_rows:
            supports.setdefault(edge["to_candidate_ref"], []).append(edge["from_candidate_ref"])
        candidates = tuple(CandidateOutcomeV2(row["candidate_ref"], row["revision_ref"], row["candidate_state"], row["content_digest"], tuple(sorted(supports.get(row["candidate_ref"], ())))) for row in rows)
        citations = tuple(
            self._served_citation(request.workspace_ref, row) for row in rows
        )
        displayed = {row["candidate_ref"] for row in rows}
        conflicts = tuple(
            ConflictOutcomeV2(
                "second-brain-conflict-decision-v2", *sorted((row[0], row[1])), "OPEN",
                None, None, None, None, None,
                canonical_ledger_digest("conflict-decision-v2", {
                    "decision_version": "second-brain-conflict-decision-v2",
                    "left_candidate_ref": min(row[0], row[1]), "right_candidate_ref": max(row[0], row[1]),
                    "state": "OPEN", "winning_candidate_ref": None,
                    "expected_decision_revision_ref": None, "authority_provenance_ref": None,
                    "authority_provenance_digest": None, "winning_revision_citation": None,
                }),
            )
            for row in conflict_rows if row[0] in displayed and row[1] in displayed
        )
        chain = self._incoming_chain(request.continuation)
        outgoing = self._outgoing_continuation(request, cut, digest, outgoing_cursor)
        body = {"snapshot_version":"second-brain-recall-serve-snapshot-v2","snapshot_attestation_version":"second-brain-recall-snapshot-attestation-v2","snapshot_signer_ref":self._signer_ref,"snapshot_signer_algorithm":"Ed25519","snapshot_key_id":self._key_id,"snapshot_signature":"pending","provenance_component_labels":["authorization","global_floor","binding","recovery","route","cohort","deletion","consent"],"provenance_component_states":[gate.to_mapping() for gate in gates],"has_more":has_more,"workspace_ref":request.workspace_ref,"capability_ref":request.capability_ref,"authority_epoch":request.authority_epoch,"subject_ref":request.subject_ref,"action":request.action,"query_digest":request.query_digest,"transaction_cut":cut,"valid_at":request.valid_at,"recorded_at":request.recorded_at,"scope_digest":request.scope_digest,"authority_provenance_ref":request.authority_provenance_ref,"authority_provenance_digest":request.authority_provenance_digest,"generation_ref":"generation:"+digest,"generation_digest":digest,"checkpoint_ref":"checkpoint:"+digest,"checkpoint_digest":digest,"freshness_digest":digest,"authority_checkpoint_digest":digest,"authorization":RecallAuthorityV2("ALLOW" if allowed else authorization_state,request.capability_ref,request.authority_epoch,request.query_digest,request.workspace_ref,request.scope_digest).to_mapping(),"global_floor":gates[1].to_mapping(),"binding":gates[2].to_mapping(),"recovery":gates[3].to_mapping(),"route":gates[4].to_mapping(),"cohort":gates[5].to_mapping(),"deletion":gates[6].to_mapping(),"consent":gates[7].to_mapping(),"projection_digest":digest,"contract_digest":digest,"base_snapshot_digest":chain[0],"cursor_state_digest":chain[1],"incoming_cursor_digest":chain[2],"incoming_continuation_ref":chain[3],"candidates":[item.to_mapping() for item in candidates],"conflicts":[item.to_mapping() for item in conflicts],"citations":[item.to_mapping() for item in citations],"continuation":outgoing}
        seal = self._seal_continuation if outgoing is not None else None
        provisional = make_recall_snapshot_v2(body, seal_continuation=seal)
        body["snapshot_signature"] = self._snapshot_signer(canonical_ledger_bytes("snapshot-attestation-v2", {k: v for k, v in provisional.to_mapping().items() if k not in {"snapshot_signature", "continuation"}}))
        return ValidatedRecallSnapshotAcquisitionV2(request, make_recall_snapshot_v2(body, seal_continuation=seal), self._trust_authority)
