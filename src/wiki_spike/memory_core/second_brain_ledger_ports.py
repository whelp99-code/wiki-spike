"""Stage-3 ledger and recall ports. Runtime adapters implement these outside Core."""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping, Protocol, runtime_checkable

from .second_brain_ledger_contracts import (
    LedgerCommandV2,
    LedgerReceiptV2,
    RecallServeSnapshotV2,
    RecallTrustAuthorityV2,
    RecallContinuationV2,
    RecallSnapshotRequestV2,
    make_recall_continuation_v2,
    make_recall_snapshot_v2,
    validate_recall_snapshot_acquisition,
)


@runtime_checkable
class LedgerCommandPort(Protocol):
    """Atomic append boundary; capability verification is part of command acceptance."""
    def append_ledger_command(self, command: LedgerCommandV2) -> LedgerReceiptV2: ...


@runtime_checkable
class AtomicRecallSnapshotPort(Protocol):
    """One atomic Runtime boundary returning only a validated acquisition wrapper."""
    def acquire_recall_snapshot(self, request: RecallSnapshotRequestV2) -> "ValidatedRecallSnapshotAcquisitionV2": ...


RECONCILIATION_VERIFIER_V1 = "second-brain-reconcile-v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_RULE_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


def _reconciliation_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _reconciliation_count(value: object, field: str) -> str:
    if not isinstance(value, str) or _DECIMAL.fullmatch(value) is None:
        raise ValueError(f"{field} must be a canonical decimal string")
    return value


@dataclass(frozen=True, slots=True)
class ReconciliationRequestV1:
    """Hash-only inputs for an offline reconciliation decision.

    The request intentionally carries no source records, paths, or credentials.
    A caller must bind each exact input file separately before constructing it.
    """

    verifier_version: str
    source_inventory_digest: str
    cohort_inventory_digest: str
    cohort_manifest_digest: str
    backup_manifest_digest: str

    def __post_init__(self) -> None:
        if self.verifier_version != RECONCILIATION_VERIFIER_V1:
            raise ValueError("unsupported reconciliation verifier version")
        for field in (
            "source_inventory_digest",
            "cohort_inventory_digest",
            "cohort_manifest_digest",
            "backup_manifest_digest",
        ):
            _reconciliation_digest(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class ReconciliationCoverageV1:
    """Exact record coverage, represented only by canonical count strings."""

    source_total: str
    cohort_total: str
    accepted_total: str
    quarantined_total: str

    def __post_init__(self) -> None:
        for field in (
            "source_total",
            "cohort_total",
            "accepted_total",
            "quarantined_total",
        ):
            _reconciliation_count(getattr(self, field), field)
        if self.source_total != self.cohort_total:
            raise ValueError("reconciliation coverage must account for every source record")
        if int(self.accepted_total) + int(self.quarantined_total) != int(self.cohort_total):
            raise ValueError("reconciliation coverage disposition totals do not match cohort total")


@dataclass(frozen=True, slots=True)
class ReconciliationFindingV1:
    """A non-serving finding with only a rule code and evidence hash."""

    rule_code: str
    evidence_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule_code, str) or _RULE_CODE.fullmatch(self.rule_code) is None:
            raise ValueError("finding rule_code must be a canonical code")
        _reconciliation_digest(self.evidence_sha256, "finding evidence_sha256")


@dataclass(frozen=True, slots=True)
class ReconciliationResultV1:
    """Fail-closed reconciliation state; it never authorizes a live operation."""

    result: str
    no_import: bool
    live_operation_authorized: bool
    coverage: ReconciliationCoverageV1
    findings: tuple[ReconciliationFindingV1, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.coverage, ReconciliationCoverageV1):
            raise ValueError("reconciliation result requires validated coverage")
        if not isinstance(self.findings, tuple) or any(
            not isinstance(finding, ReconciliationFindingV1) for finding in self.findings
        ):
            raise ValueError("reconciliation findings must be an immutable finding tuple")
        if self.live_operation_authorized is not False:
            raise ValueError("reconciliation never authorizes live operations")
        pass_state = self.result == "PASS" and self.no_import is False and not self.findings
        quarantine_state = self.result == "QUARANTINED" and self.no_import is True and bool(self.findings)
        if not (pass_state or quarantine_state):
            raise ValueError("contradictory reconciliation result state")


@runtime_checkable
class ReconciliationVerifierPort(AtomicRecallSnapshotPort, Protocol):
    """Offline verifier composed with, never substituting for, recall snapshots."""

    def verify_reconciliation(self, request: ReconciliationRequestV1) -> ReconciliationResultV1: ...


@dataclass(frozen=True, slots=True, init=False)
class ValidatedRecallSnapshotAcquisitionV2:
    """Core-owned, non-bypassable request/result proof returned by the port."""
    _request: RecallSnapshotRequestV2
    _snapshot: RecallServeSnapshotV2

    def __init__(self, request: RecallSnapshotRequestV2, snapshot: RecallServeSnapshotV2, authority: RecallTrustAuthorityV2) -> None:
        if not isinstance(request, RecallSnapshotRequestV2):
            raise TypeError("request must be RecallSnapshotRequestV2")
        object.__setattr__(self, "_request", request)
        object.__setattr__(self, "_snapshot", validate_recall_snapshot_acquisition(request, snapshot, authority))

    @property
    def request(self) -> RecallSnapshotRequestV2:
        return self._request

    @property
    def snapshot(self) -> RecallServeSnapshotV2:
        return self._snapshot


@runtime_checkable
class CanonicalRecallSnapshotFactoryV2(Protocol):
    """Core factory: adapters cannot expose an unvalidated acquisition result."""
    def acquire(self, request: RecallSnapshotRequestV2) -> ValidatedRecallSnapshotAcquisitionV2: ...

    @staticmethod
    def validated(request: RecallSnapshotRequestV2, result: RecallServeSnapshotV2, authority: RecallTrustAuthorityV2) -> ValidatedRecallSnapshotAcquisitionV2:
        return ValidatedRecallSnapshotAcquisitionV2(request, result, authority)

    @staticmethod
    def continuation(body: Mapping[str, Any]) -> RecallContinuationV2:
        return make_recall_continuation_v2(body)

    @staticmethod
    def snapshot(body: Mapping[str, Any]) -> RecallServeSnapshotV2:
        return make_recall_snapshot_v2(body)
