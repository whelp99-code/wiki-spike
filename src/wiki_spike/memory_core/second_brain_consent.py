"""Fail-closed source consent, classification, and retention policy."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .policy import Sensitivity


class ConsentState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class RetentionState(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"


class ConsentRetentionDisposition(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    DELETION_REQUIRED = "deletion_required"


class ConsentRetentionReason(str, Enum):
    ALLOW = "allow"
    ABSENT = "absent"
    WORKSPACE_MISMATCH = "workspace_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    DISABLED = "disabled"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    SENSITIVITY_EXCEEDED = "sensitivity_exceeded"
    CLASSIFICATION_DOWNGRADE = "classification_downgrade"
    RETENTION_EXPIRED = "retention_expired"


@dataclass(frozen=True)
class SourceConsentState:
    workspace_id: str
    source_ref_id: str
    project_ref_id: str
    consent_epoch: str
    consent_state: ConsentState
    max_sensitivity: Sensitivity
    expires_at: str
    consent_digest: str
    updated_at: str


@dataclass(frozen=True)
class RetentionPolicy:
    workspace_id: str
    source_ref_id: str
    project_ref_id: str
    retention_epoch: str
    retention_state: RetentionState
    max_sensitivity: Sensitivity
    expires_at: str
    retention_digest: str
    updated_at: str


@dataclass(frozen=True)
class ConsentRetentionDecision:
    allowed: bool
    disposition: ConsentRetentionDisposition
    reason: ConsentRetentionReason


class ConsentRetentionPolicy:
    """Authorize only a current, exact-scope consent and retention pair.

    Timestamps are canonical UTC ISO-8601 strings, so lexical comparison is
    deliberate and avoids accepting ambiguous local-clock values.
    """

    def authorize_capture(
        self,
        *,
        workspace_id: str,
        source_ref_id: str,
        project_ref_id: str,
        consent: SourceConsentState | None,
        retention: RetentionPolicy | None,
        sensitivity: Sensitivity,
        now: str,
        prior_sensitivity: Sensitivity | None = None,
    ) -> ConsentRetentionDecision:
        decision = self._authorize_current(
            workspace_id=workspace_id,
            source_ref_id=source_ref_id,
            project_ref_id=project_ref_id,
            consent=consent,
            retention=retention,
            sensitivity=sensitivity,
            now=now,
        )
        if not decision.allowed:
            return decision
        if prior_sensitivity is not None and sensitivity.rank < prior_sensitivity.rank:
            return self._deny(ConsentRetentionReason.CLASSIFICATION_DOWNGRADE)
        return self._allow()

    def authorize_serve(
        self,
        *,
        workspace_id: str,
        source_ref_id: str,
        project_ref_id: str,
        consent_epoch: str,
        retention_epoch: str,
        consent: SourceConsentState | None,
        retention: RetentionPolicy | None,
        sensitivity: Sensitivity,
        now: str,
    ) -> ConsentRetentionDecision:
        decision = self._authorize_current(
            workspace_id=workspace_id,
            source_ref_id=source_ref_id,
            project_ref_id=project_ref_id,
            consent=consent,
            retention=retention,
            sensitivity=sensitivity,
            now=now,
        )
        if not decision.allowed:
            return decision
        assert consent is not None and retention is not None
        if consent.consent_epoch != consent_epoch or retention.retention_epoch != retention_epoch:
            return self._deny(ConsentRetentionReason.SUPERSEDED)
        return self._allow()

    def _authorize_current(
        self,
        *,
        workspace_id: str,
        source_ref_id: str,
        project_ref_id: str,
        consent: SourceConsentState | None,
        retention: RetentionPolicy | None,
        sensitivity: Sensitivity,
        now: str,
    ) -> ConsentRetentionDecision:
        if consent is None or retention is None:
            return self._deny(ConsentRetentionReason.ABSENT)
        for record in (consent, retention):
            if record.workspace_id != workspace_id:
                return self._deny(ConsentRetentionReason.WORKSPACE_MISMATCH)
            if record.source_ref_id != source_ref_id or record.project_ref_id != project_ref_id:
                return self._deny(ConsentRetentionReason.SCOPE_MISMATCH)
        if consent.consent_state is not ConsentState.ENABLED or retention.retention_state is not RetentionState.ACTIVE:
            return self._deny(ConsentRetentionReason.DISABLED)
        if consent.expires_at <= now:
            return self._deny(ConsentRetentionReason.EXPIRED)
        if retention.expires_at <= now:
            return ConsentRetentionDecision(False, ConsentRetentionDisposition.DELETION_REQUIRED, ConsentRetentionReason.RETENTION_EXPIRED)
        if sensitivity.rank > consent.max_sensitivity.rank or sensitivity.rank > retention.max_sensitivity.rank:
            return self._deny(ConsentRetentionReason.SENSITIVITY_EXCEEDED)
        return self._allow()

    @staticmethod
    def _allow() -> ConsentRetentionDecision:
        return ConsentRetentionDecision(True, ConsentRetentionDisposition.ALLOW, ConsentRetentionReason.ALLOW)

    @staticmethod
    def _deny(reason: ConsentRetentionReason) -> ConsentRetentionDecision:
        return ConsentRetentionDecision(False, ConsentRetentionDisposition.DENY, reason)
