"""Fail-closed source consent, classification, and retention policy."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
import re
from typing import Any

from .errors import InvalidContractValue
from .policy import Sensitivity
from .second_brain_contracts import _canonical_utc_timestamp, _digest, _positive_decimal

_REF = re.compile(r"^[A-Za-z0-9._:-]+$")


def _ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or _REF.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be an opaque reference")
    return value


def _strict(data: Mapping[str, Any], fields: frozenset[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or set(data) != fields:
        raise InvalidContractValue("consent/retention DTO fields are invalid")
    return dict(data)


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

    FIELDS = frozenset({
        "workspace_id", "source_ref_id", "project_ref_id", "consent_epoch",
        "consent_state", "max_sensitivity", "expires_at", "consent_digest", "updated_at",
    })

    def to_mapping(self) -> dict[str, str]:
        return {
            "workspace_id": self.workspace_id, "source_ref_id": self.source_ref_id,
            "project_ref_id": self.project_ref_id, "consent_epoch": self.consent_epoch,
            "consent_state": self.consent_state.value, "max_sensitivity": self.max_sensitivity.value,
            "expires_at": self.expires_at, "consent_digest": self.consent_digest,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceConsentState":
        v = _strict(data, cls.FIELDS)
        expires_at, updated_at = v["expires_at"], v["updated_at"]
        _canonical_utc_timestamp(expires_at, "expires_at")
        _canonical_utc_timestamp(updated_at, "updated_at")
        try:
            state, sensitivity = ConsentState(v["consent_state"]), Sensitivity(v["max_sensitivity"])
        except (TypeError, ValueError) as exc:
            raise InvalidContractValue("consent state or sensitivity is invalid") from exc
        return cls(
            _ref(v["workspace_id"], "workspace_id"), _ref(v["source_ref_id"], "source_ref_id"),
            _ref(v["project_ref_id"], "project_ref_id"), _positive_decimal(v["consent_epoch"], "consent_epoch"),
            state, sensitivity, expires_at, _digest(v["consent_digest"], "consent_digest"), updated_at,
        )


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

    FIELDS = frozenset({
        "workspace_id", "source_ref_id", "project_ref_id", "retention_epoch",
        "retention_state", "max_sensitivity", "expires_at", "retention_digest", "updated_at",
    })

    def to_mapping(self) -> dict[str, str]:
        return {
            "workspace_id": self.workspace_id, "source_ref_id": self.source_ref_id,
            "project_ref_id": self.project_ref_id, "retention_epoch": self.retention_epoch,
            "retention_state": self.retention_state.value, "max_sensitivity": self.max_sensitivity.value,
            "expires_at": self.expires_at, "retention_digest": self.retention_digest,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RetentionPolicy":
        v = _strict(data, cls.FIELDS)
        expires_at, updated_at = v["expires_at"], v["updated_at"]
        _canonical_utc_timestamp(expires_at, "expires_at")
        _canonical_utc_timestamp(updated_at, "updated_at")
        try:
            state, sensitivity = RetentionState(v["retention_state"]), Sensitivity(v["max_sensitivity"])
        except (TypeError, ValueError) as exc:
            raise InvalidContractValue("retention state or sensitivity is invalid") from exc
        return cls(
            _ref(v["workspace_id"], "workspace_id"), _ref(v["source_ref_id"], "source_ref_id"),
            _ref(v["project_ref_id"], "project_ref_id"), _positive_decimal(v["retention_epoch"], "retention_epoch"),
            state, sensitivity, expires_at, _digest(v["retention_digest"], "retention_digest"), updated_at,
        )


@dataclass(frozen=True)
class ConsentRetentionDecision:
    allowed: bool
    disposition: ConsentRetentionDisposition
    reason: ConsentRetentionReason


class ConsentRetentionPolicy:
    """Authorize only revalidated, current, exact-scope consent and retention DTOs."""

    def authorize_capture(
        self, *, workspace_id: str, source_ref_id: str, project_ref_id: str,
        consent: SourceConsentState | None, retention: RetentionPolicy | None,
        sensitivity: Sensitivity, now: str, prior_sensitivity: Sensitivity | None = None,
    ) -> ConsentRetentionDecision:
        decision, _, _ = self._authorize_current(
            workspace_id=workspace_id, source_ref_id=source_ref_id, project_ref_id=project_ref_id,
            consent=consent, retention=retention, sensitivity=sensitivity, now=now,
        )
        if not decision.allowed:
            return decision
        if not isinstance(prior_sensitivity, (Sensitivity, type(None))) or (
            prior_sensitivity is not None and sensitivity.rank < prior_sensitivity.rank
        ):
            return self._deny(ConsentRetentionReason.CLASSIFICATION_DOWNGRADE)
        return self._allow()

    def authorize_serve(
        self, *, workspace_id: str, source_ref_id: str, project_ref_id: str,
        consent_epoch: str, retention_epoch: str, consent: SourceConsentState | None,
        retention: RetentionPolicy | None, sensitivity: Sensitivity, now: str,
    ) -> ConsentRetentionDecision:
        decision, current_consent, current_retention = self._authorize_current(
            workspace_id=workspace_id, source_ref_id=source_ref_id, project_ref_id=project_ref_id,
            consent=consent, retention=retention, sensitivity=sensitivity, now=now,
        )
        if not decision.allowed:
            return decision
        try:
            if _positive_decimal(consent_epoch, "consent_epoch") != current_consent.consent_epoch or _positive_decimal(retention_epoch, "retention_epoch") != current_retention.retention_epoch:
                return self._deny(ConsentRetentionReason.SUPERSEDED)
        except InvalidContractValue:
            return self._deny(ConsentRetentionReason.SUPERSEDED)
        return self._allow()

    def _authorize_current(
        self, *, workspace_id: str, source_ref_id: str, project_ref_id: str,
        consent: SourceConsentState | None, retention: RetentionPolicy | None,
        sensitivity: Sensitivity, now: str,
    ) -> tuple[ConsentRetentionDecision, SourceConsentState | None, RetentionPolicy | None]:
        if consent is None or retention is None:
            return self._deny(ConsentRetentionReason.ABSENT), None, None
        try:
            current_consent = SourceConsentState.from_mapping(consent.to_mapping())
            current_retention = RetentionPolicy.from_mapping(retention.to_mapping())
            now_utc = _canonical_utc_timestamp(now, "now")
            requested_sensitivity = Sensitivity(sensitivity)
            for value, field in ((workspace_id, "workspace_id"), (source_ref_id, "source_ref_id"), (project_ref_id, "project_ref_id")):
                _ref(value, field)
        except (AttributeError, InvalidContractValue, TypeError, ValueError):
            return self._deny(ConsentRetentionReason.ABSENT), None, None
        for record in (current_consent, current_retention):
            if record.workspace_id != workspace_id:
                return self._deny(ConsentRetentionReason.WORKSPACE_MISMATCH), None, None
            if record.source_ref_id != source_ref_id or record.project_ref_id != project_ref_id:
                return self._deny(ConsentRetentionReason.SCOPE_MISMATCH), None, None
        if current_consent.consent_state is not ConsentState.ENABLED or current_retention.retention_state is not RetentionState.ACTIVE:
            return self._deny(ConsentRetentionReason.DISABLED), None, None
        if _canonical_utc_timestamp(current_consent.expires_at, "expires_at") <= now_utc:
            return self._deny(ConsentRetentionReason.EXPIRED), None, None
        if _canonical_utc_timestamp(current_retention.expires_at, "expires_at") <= now_utc:
            return ConsentRetentionDecision(False, ConsentRetentionDisposition.DELETION_REQUIRED, ConsentRetentionReason.RETENTION_EXPIRED), None, None
        if requested_sensitivity.rank > current_consent.max_sensitivity.rank or requested_sensitivity.rank > current_retention.max_sensitivity.rank:
            return self._deny(ConsentRetentionReason.SENSITIVITY_EXCEEDED), None, None
        return self._allow(), current_consent, current_retention

    @staticmethod
    def _allow() -> ConsentRetentionDecision:
        return ConsentRetentionDecision(True, ConsentRetentionDisposition.ALLOW, ConsentRetentionReason.ALLOW)

    @staticmethod
    def _deny(reason: ConsentRetentionReason) -> ConsentRetentionDecision:
        return ConsentRetentionDecision(False, ConsentRetentionDisposition.DENY, reason)
