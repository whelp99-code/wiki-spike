"""Forward-only deletion phase state machine and ``DeletionStateV1`` builder.

Implements the ADR-0027 deletion lifecycle machine per
``schemas/encrypted-lifecycle/deletion-state-v1.schema.json``:

    REQUESTED -> API_VETO_ACTIVE -> TOMBSTONE_ACTIVE -> CHECKPOINT_COMMITTED
    -> REVOCATION_KEYS_DESTROYED -> CRYPTO_SHRED_COMPLETE -> PURGE_PENDING
    -> COMPLETE

This is a strictly linear, forward-only machine: from any phase the only
legal transition is to its single immediate successor. Same-phase
"advances", skip-ahead, and backward transitions are all illegal. REQUESTED
through CHECKPOINT_COMMITTED are application/API-denial phases only (the
object is vetoed from serving but may still be cryptographically
decryptable); cryptographic undecryptability is claimable only from
CRYPTO_SHRED_COMPLETE onward, once every usable wrap has been destroyed.

``report`` carries three independent surface tiers (live corpus, 30-day
backup residual, egress ledger) that each complete independently of one
another and independently of the phase machine's own progress.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure only. Never
``memory_runtime``/applications/connectors/ui/legacy-storage.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
import re
from enum import Enum
from pathlib import Path
from typing import Any, Mapping
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .lifecycle_db import UnitOfWork

try:
    import jsonschema  # type: ignore

    _HAVE_JSONSCHEMA = True
except Exception:  # pragma: no cover - exercised only when jsonschema absent
    jsonschema = None  # type: ignore
    _HAVE_JSONSCHEMA = False

DELETION_STATE_SCHEMA = "wiki-deletion-state-v1"

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[3]
    / "schemas"
    / "encrypted-lifecycle"
    / "deletion-state-v1.schema.json"
)
_DELETION_STATE_SCHEMA_DOC: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


class DeletionPhase(str, Enum):
    REQUESTED = "REQUESTED"
    API_VETO_ACTIVE = "API_VETO_ACTIVE"
    TOMBSTONE_ACTIVE = "TOMBSTONE_ACTIVE"
    CHECKPOINT_COMMITTED = "CHECKPOINT_COMMITTED"
    REVOCATION_KEYS_DESTROYED = "REVOCATION_KEYS_DESTROYED"
    CRYPTO_SHRED_COMPLETE = "CRYPTO_SHRED_COMPLETE"
    PURGE_PENDING = "PURGE_PENDING"
    COMPLETE = "COMPLETE"


class ReportTierStatus(str, Enum):
    PENDING = "PENDING"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETE = "COMPLETE"


class DeletionError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


_PHASE_ORDER: tuple[DeletionPhase, ...] = (
    DeletionPhase.REQUESTED,
    DeletionPhase.API_VETO_ACTIVE,
    DeletionPhase.TOMBSTONE_ACTIVE,
    DeletionPhase.CHECKPOINT_COMMITTED,
    DeletionPhase.REVOCATION_KEYS_DESTROYED,
    DeletionPhase.CRYPTO_SHRED_COMPLETE,
    DeletionPhase.PURGE_PENDING,
    DeletionPhase.COMPLETE,
)

# Each phase maps to the single legal next phase; COMPLETE is terminal (maps
# to no successor). Forward-only, single-step: this is a linear machine, so
# only current -> the immediate next phase is ever legal. Same-phase
# "advances" and any skip/backward transition are rejected.
_NEXT_PHASE: dict[DeletionPhase, DeletionPhase] = {
    _PHASE_ORDER[i]: _PHASE_ORDER[i + 1] for i in range(len(_PHASE_ORDER) - 1)
}

_CRYPTO_SHREDDED_PHASES = frozenset({
    DeletionPhase.CRYPTO_SHRED_COMPLETE,
    DeletionPhase.PURGE_PENDING,
    DeletionPhase.COMPLETE,
})

_REPORT_TIERS: tuple[str, ...] = ("live", "backup", "egress")


def _coerce_phase(phase: "DeletionPhase | str") -> DeletionPhase:
    if isinstance(phase, DeletionPhase):
        return phase
    try:
        return DeletionPhase(phase)
    except ValueError as exc:
        raise DeletionError("unknown_deletion_phase", f"not a valid deletion phase: {phase!r}") from exc


def advance(current: DeletionPhase, target: DeletionPhase) -> DeletionPhase:
    """Public forward-only transition helper.

    Only the immediate successor of ``current`` in the linear phase order is
    a legal ``target``. Same-phase, skip-ahead, and backward transitions all
    raise ``DeletionError('illegal_deletion_transition', ...)``. ``COMPLETE``
    has no successor, so any advance attempted from ``COMPLETE`` is illegal.
    """
    next_phase = _NEXT_PHASE.get(current)
    if next_phase is None or target != next_phase:
        raise DeletionError(
            "illegal_deletion_transition",
            f"{current.value} -> {target.value} is not a valid deletion transition",
        )
    return target


def initial_report() -> dict:
    """Return a fresh ``deletionReportV1`` with all three tiers PENDING."""
    return {
        tier: {"status": ReportTierStatus.PENDING.value, "verified_at": None, "evidence_digest": None}
        for tier in _REPORT_TIERS
    }


def set_report_tier(
    report: Mapping,
    tier: str,
    *,
    status: str,
    verified_at: "str | None",
    evidence_digest: "str | None",
) -> dict:
    """Return a NEW report dict with exactly ``tier`` updated.

    The other two tiers are copied through unchanged: the three surface
    tiers complete independently of one another.
    """
    if tier not in _REPORT_TIERS:
        raise DeletionError("unknown_report_tier", f"not a valid report tier: {tier!r}")
    try:
        ReportTierStatus(status)
    except ValueError as exc:
        raise DeletionError("unknown_report_tier_status", f"not a valid report tier status: {status!r}") from exc

    new_report = {key: dict(value) for key, value in report.items()}
    new_report[tier] = {
        "status": status,
        "verified_at": verified_at,
        "evidence_digest": evidence_digest,
    }
    return new_report


# ---------------------------------------------------------------------------
# DeletionStateV1 schema validation (fail-closed; jsonschema when available,
# else a strict manual fallback kept in lockstep with the schema file).
# ---------------------------------------------------------------------------

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_ID_RE = re.compile(r"^[a-z][a-z0-9_-]{0,62}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")

_PHASE_VALUES = frozenset(p.value for p in DeletionPhase)
_TIER_STATUS_VALUES = frozenset(s.value for s in ReportTierStatus)


def _manual_validate_deletion_state(obj: Any) -> None:
    if not isinstance(obj, dict):
        raise DeletionError("deletion_state_schema_violation", f"expected object, got {type(obj).__name__}")

    required = ["schema", "workspace_id", "deletion_command_id", "phase", "report", "updated_at"]
    missing = [k for k in required if k not in obj]
    if missing:
        raise DeletionError("deletion_state_schema_violation", f"missing required field(s) {missing}")

    extra = sorted(set(obj) - set(required))
    if extra:
        raise DeletionError("deletion_state_schema_violation", f"unexpected field(s) {extra}")

    if obj["schema"] != DELETION_STATE_SCHEMA:
        raise DeletionError(
            "deletion_state_schema_violation", f"schema: expected {DELETION_STATE_SCHEMA!r}, got {obj['schema']!r}"
        )

    workspace_id = obj["workspace_id"]
    if not isinstance(workspace_id, str) or _OPAQUE_ID_RE.fullmatch(workspace_id) is None:
        raise DeletionError("deletion_state_schema_violation", f"workspace_id: invalid opaqueId {workspace_id!r}")

    deletion_command_id = obj["deletion_command_id"]
    if not isinstance(deletion_command_id, str) or _HEX64_RE.fullmatch(deletion_command_id) is None:
        raise DeletionError(
            "deletion_state_schema_violation", f"deletion_command_id: invalid hex64 {deletion_command_id!r}"
        )

    phase = obj["phase"]
    if not isinstance(phase, str) or phase not in _PHASE_VALUES:
        raise DeletionError("deletion_state_schema_violation", f"phase: invalid deletion phase {phase!r}")

    updated_at = obj["updated_at"]
    if not isinstance(updated_at, str) or _TIMESTAMP_RE.fullmatch(updated_at) is None:
        raise DeletionError("deletion_state_schema_violation", f"updated_at: invalid timestamp {updated_at!r}")

    report = obj["report"]
    if not isinstance(report, dict):
        raise DeletionError("deletion_state_schema_violation", f"report: expected object, got {type(report).__name__}")

    tier_missing = [t for t in _REPORT_TIERS if t not in report]
    if tier_missing:
        raise DeletionError("deletion_state_schema_violation", f"report: missing tier(s) {tier_missing}")

    tier_extra = sorted(set(report) - set(_REPORT_TIERS))
    if tier_extra:
        raise DeletionError("deletion_state_schema_violation", f"report: unexpected tier(s) {tier_extra}")

    for tier in _REPORT_TIERS:
        tier_obj = report[tier]
        if not isinstance(tier_obj, dict):
            raise DeletionError(
                "deletion_state_schema_violation", f"report.{tier}: expected object, got {type(tier_obj).__name__}"
            )
        tier_required = ["status", "verified_at", "evidence_digest"]
        tier_missing_fields = [k for k in tier_required if k not in tier_obj]
        if tier_missing_fields:
            raise DeletionError(
                "deletion_state_schema_violation", f"report.{tier}: missing required field(s) {tier_missing_fields}"
            )
        tier_extra_fields = sorted(set(tier_obj) - set(tier_required))
        if tier_extra_fields:
            raise DeletionError(
                "deletion_state_schema_violation", f"report.{tier}: unexpected field(s) {tier_extra_fields}"
            )

        status = tier_obj["status"]
        if not isinstance(status, str) or status not in _TIER_STATUS_VALUES:
            raise DeletionError("deletion_state_schema_violation", f"report.{tier}.status: invalid status {status!r}")

        verified_at = tier_obj["verified_at"]
        if verified_at is not None and (
            not isinstance(verified_at, str) or _TIMESTAMP_RE.fullmatch(verified_at) is None
        ):
            raise DeletionError(
                "deletion_state_schema_violation", f"report.{tier}.verified_at: invalid timestamp {verified_at!r}"
            )

        evidence_digest = tier_obj["evidence_digest"]
        if evidence_digest is not None and (
            not isinstance(evidence_digest, str) or _HEX64_RE.fullmatch(evidence_digest) is None
        ):
            raise DeletionError(
                "deletion_state_schema_violation", f"report.{tier}.evidence_digest: invalid hex64 {evidence_digest!r}"
            )


def _validate_deletion_state_schema(obj: dict[str, Any]) -> None:
    if _HAVE_JSONSCHEMA:
        try:
            jsonschema.validate(obj, _DELETION_STATE_SCHEMA_DOC)  # type: ignore[union-attr]
        except Exception as exc:  # jsonschema.ValidationError or resolver errors
            raise DeletionError("deletion_state_schema_violation", str(exc)) from exc
        # Belt-and-suspenders: jsonschema draft-07 $ref resolution edge cases
        # aside, always also run the manual check so both paths agree.
        _manual_validate_deletion_state(obj)
    else:
        _manual_validate_deletion_state(obj)


def build_deletion_state(
    *,
    workspace_id: str,
    deletion_command_id: str,
    phase: "DeletionPhase | str",
    report: Mapping,
    updated_at: str,
) -> dict:
    """Assemble and fail-closed validate a ``DeletionStateV1`` object."""
    phase_value = phase.value if isinstance(phase, DeletionPhase) else phase
    state = {
        "schema": DELETION_STATE_SCHEMA,
        "workspace_id": workspace_id,
        "deletion_command_id": deletion_command_id,
        "phase": phase_value,
        "report": {tier: dict(report[tier]) for tier in report},
        "updated_at": updated_at,
    }
    _validate_deletion_state_schema(state)
    return state


def is_vetoed(phase: "DeletionPhase | str") -> bool:
    """True for every phase REQUESTED..COMPLETE.

    Any live/active or completed deletion vetoes history/cache/restore/reads:
    once a deletion_state row exists in any phase, the object is vetoed.
    There is no non-vetoed deletion phase.
    """
    _coerce_phase(phase)
    return True


def is_crypto_shredded(phase: "DeletionPhase | str") -> bool:
    """True only from CRYPTO_SHRED_COMPLETE onward.

    REQUESTED..REVOCATION_KEYS_DESTROYED are application/API-denial phases
    only; cryptographic undecryptability is claimable only once every usable
    wrap has been destroyed.
    """
    resolved = _coerce_phase(phase)
    return resolved in _CRYPTO_SHREDDED_PHASES
@dataclass(frozen=True)
class SourceDeletionRecoveryStatus:
    """Truthful deletion status for one recovered source artifact.

    This reports the API veto and crypto-shred boundary separately.  Backup and
    egress are never claimed erased here: their independent report tiers remain
    the authoritative evidence.
    """

    artifact_id: str
    phase: DeletionPhase
    api_veto_active: bool
    crypto_shredded: bool
    backup_residual: bool
    irreversible_egress: bool


def map_source_deletion_request(
    uow: "UnitOfWork",
    *,
    workspace_id: str,
    source_ref_id: str,
    deletion_ref_id: str,
    updated_at: str,
) -> tuple[SourceDeletionRecoveryStatus, ...]:
    """Apply an existing source/deletion/recovery mapping to the deletion FSM.

    A mapping never asserts provider erasure.  It creates only the initial
    REQUESTED state when absent; existing rows are read unchanged, preserving
    the forward-only state machine.  Every mapped artifact is therefore vetoed
    before a recovery target can make it visible again.
    """

    rows = uow.list_source_deletion_recovery_maps(workspace_id, source_ref_id, deletion_ref_id)
    statuses: list[SourceDeletionRecoveryStatus] = []
    for row in rows:
        deletion = uow.get_deletion_state_by_artifact(row["artifact_id"])
        if deletion is None:
            deletion_id = sha256(
                f"{workspace_id}\x00{deletion_ref_id}\x00{row['artifact_id']}".encode("ascii")
            ).hexdigest()
            uow.insert_deletion_state(
                deletion_id, row["artifact_id"], DeletionPhase.REQUESTED.value, updated_at
            )
            phase = DeletionPhase.REQUESTED
        else:
            phase = _coerce_phase(deletion["phase_state"])
        statuses.append(
            SourceDeletionRecoveryStatus(
                artifact_id=row["artifact_id"],
                phase=phase,
                api_veto_active=is_vetoed(phase),
                crypto_shredded=is_crypto_shredded(phase),
                backup_residual=True,
                irreversible_egress=False,
            )
        )
    return tuple(statuses)
