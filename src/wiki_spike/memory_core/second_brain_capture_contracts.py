"""Fixture-only, non-serving Stage-2 source-capture contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
import re
from typing import Any, ClassVar

from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

SOURCE_SCOPE_REF_VERSION = "second-brain-source-scope-ref-v1"
SCAN_CHECKPOINT_VERSION = "second-brain-scan-checkpoint-v1"
CAPTURE_ITEM_RECEIPT_VERSION = "second-brain-capture-item-receipt-v1"
CAPTURE_SCAN_MANIFEST_VERSION = "second-brain-capture-scan-manifest-v1"
CAPTURE_RECONCILIATION_VERSION = "second-brain-capture-reconciliation-v1"
MIGRATION_REGISTRATION_VERSION = "second-brain-migration-registration-v1"
NON_SERVING_CAPTURE_COHORT_VERSION = "second-brain-non-serving-capture-cohort-v1"
RECONCILED_CHECKPOINT_ADVANCE_VERSION = "second-brain-reconciled-checkpoint-advance-v1"
SOURCE_DOMAINS = {"Codex": "codex", "Claude/Memory Bank": "claude-memory-bank", "Git": "git", "Markdown": "markdown"}
MIGRATION_DOMAINS = {"unified-db": "unified-db", "legacy Mem0/RAG": "legacy-mem0-rag", "me-wiki": "me-wiki"}
SOURCE_PROFILES = frozenset(SOURCE_DOMAINS)
MIGRATION_SOURCES = frozenset(MIGRATION_DOMAINS)
CAPTURE_DISPOSITIONS = frozenset({"ACCEPTED", "DUPLICATE", "TOMBSTONE", "SKIPPED", "QUARANTINED"})
RECONCILIATION_COMPLETION = "COMPLETE"
RECONCILIATION_OUTCOME = "RECONCILED"
NON_SERVING = "NON_SERVING"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_KEYED_REF = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")


def _strict(value: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidContractValue("contract must be an object")
    unknown, missing = set(value) - fields, fields - set(value)
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(value)


def _version(value: Any, expected: str, field: str) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a string")
    if value != expected:
        raise UnsupportedContractVersion(f"unsupported {field}")
    return expected


def _closed(value: Any, allowed: frozenset[str] | set[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise InvalidContractValue(f"{field} is not closed")
    return value


def _ref(value: Any, field: str, *, kind: str | None = None) -> str:
    if not isinstance(value, str) or _KEYED_REF.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a keyed opaque reference")
    if kind is not None and not value.startswith(f"{kind}:"):
        raise InvalidContractValue(f"{field} must be a {kind} reference")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return value


def _decimal(value: Any, field: str, *, positive: bool = False) -> str:
    pattern = _POSITIVE_DECIMAL if positive else _DECIMAL
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a canonical {'positive ' if positive else ''}decimal string")
    return value


def _refs(value: Any, field: str, *, kind: str, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise InvalidContractValue(f"{field} must be an array")
    result = tuple(_ref(item, field, kind=kind) for item in value)
    if (nonempty and not result) or len(set(result)) != len(result):
        raise InvalidContractValue(f"{field} must contain unique {kind} references")
    return result


@dataclass(frozen=True)
class SourceScopeRefV1:
    scope_version: str; source_profile: str; source_domain: str; source_ref: str; workspace_ref: str; scope_ref: str; scope_epoch: str
    FIELDS: ClassVar[set[str]] = {"scope_version", "source_profile", "source_domain", "source_ref", "workspace_ref", "scope_ref", "scope_epoch"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "SourceScopeRefV1":
        v = _strict(data, cls.FIELDS); _version(v["scope_version"], SOURCE_SCOPE_REF_VERSION, "scope_version")
        profile = _closed(v["source_profile"], SOURCE_PROFILES, "source_profile")
        domain = SOURCE_DOMAINS[profile]
        if not isinstance(v["source_domain"], str) or v["source_domain"] != domain:
            raise InvalidContractValue("source_profile and source_domain must be a closed matching pair")
        return cls(SOURCE_SCOPE_REF_VERSION, profile, domain, _ref(v["source_ref"], "source_ref", kind=f"{domain}-source"), _ref(v["workspace_ref"], "workspace_ref", kind="workspace"), _ref(v["scope_ref"], "scope_ref", kind=f"{domain}-scope"), _decimal(v["scope_epoch"], "scope_epoch", positive=True))

    def to_mapping(self) -> dict[str, str]:
        return {"scope_version": self.scope_version, "source_profile": self.source_profile, "source_domain": self.source_domain, "source_ref": self.source_ref, "workspace_ref": self.workspace_ref, "scope_ref": self.scope_ref, "scope_epoch": self.scope_epoch}


def _scope(value: Any, field: str = "scope") -> SourceScopeRefV1:
    try:
        return SourceScopeRefV1.from_mapping(value)
    except (InvalidContractValue, UnknownContractField, UnsupportedContractVersion) as exc:
        raise InvalidContractValue(f"{field} is invalid: {exc}") from exc


@dataclass(frozen=True)
class ScanCheckpointV1:
    checkpoint_version: str; scope: SourceScopeRefV1; scan_epoch: str; checkpoint_ref: str; checkpoint_digest: str; manifest_ref: str; reconciliation_ref: str; reconciliation_digest: str; reconciliation_epoch: str; reconciliation_completion: str; reconciliation_outcome: str
    FIELDS: ClassVar[set[str]] = {"checkpoint_version", "scope", "scan_epoch", "checkpoint_ref", "checkpoint_digest", "manifest_ref", "reconciliation_ref", "reconciliation_digest", "reconciliation_epoch", "reconciliation_completion", "reconciliation_outcome"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ScanCheckpointV1":
        v = _strict(data, cls.FIELDS); _version(v["checkpoint_version"], SCAN_CHECKPOINT_VERSION, "checkpoint_version")
        scan_epoch = _decimal(v["scan_epoch"], "scan_epoch", positive=True)
        reconciliation_epoch = _decimal(v["reconciliation_epoch"], "reconciliation_epoch", positive=True)
        if reconciliation_epoch != scan_epoch or not isinstance(v["reconciliation_completion"], str) or not isinstance(v["reconciliation_outcome"], str) or v["reconciliation_completion"] != RECONCILIATION_COMPLETION or v["reconciliation_outcome"] != RECONCILIATION_OUTCOME:
            raise InvalidContractValue("checkpoint advancement requires a complete reconciled matching epoch")
        return cls(SCAN_CHECKPOINT_VERSION, _scope(v["scope"]), scan_epoch, _ref(v["checkpoint_ref"], "checkpoint_ref", kind="checkpoint"), _digest(v["checkpoint_digest"], "checkpoint_digest"), _ref(v["manifest_ref"], "manifest_ref", kind="manifest"), _ref(v["reconciliation_ref"], "reconciliation_ref", kind="reconciliation"), _digest(v["reconciliation_digest"], "reconciliation_digest"), reconciliation_epoch, RECONCILIATION_COMPLETION, RECONCILIATION_OUTCOME)

    def to_mapping(self) -> dict[str, Any]:
        return {"checkpoint_version": self.checkpoint_version, "scope": self.scope.to_mapping(), "scan_epoch": self.scan_epoch, "checkpoint_ref": self.checkpoint_ref, "checkpoint_digest": self.checkpoint_digest, "manifest_ref": self.manifest_ref, "reconciliation_ref": self.reconciliation_ref, "reconciliation_digest": self.reconciliation_digest, "reconciliation_epoch": self.reconciliation_epoch, "reconciliation_completion": self.reconciliation_completion, "reconciliation_outcome": self.reconciliation_outcome}


@dataclass(frozen=True)
class CaptureItemReceiptV1:
    receipt_version: str; scope: SourceScopeRefV1; scan_epoch: str; capture_ref: str; ciphertext_digest: str; disposition: str
    FIELDS: ClassVar[set[str]] = {"receipt_version", "scope", "scan_epoch", "capture_ref", "ciphertext_digest", "disposition"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CaptureItemReceiptV1":
        v = _strict(data, cls.FIELDS); _version(v["receipt_version"], CAPTURE_ITEM_RECEIPT_VERSION, "receipt_version")
        disposition = _closed(v["disposition"], CAPTURE_DISPOSITIONS, "disposition")
        return cls(CAPTURE_ITEM_RECEIPT_VERSION, _scope(v["scope"]), _decimal(v["scan_epoch"], "scan_epoch", positive=True), _ref(v["capture_ref"], "capture_ref", kind="capture"), _digest(v["ciphertext_digest"], "ciphertext_digest"), disposition)

    def to_mapping(self) -> dict[str, Any]:
        return {"receipt_version": self.receipt_version, "scope": self.scope.to_mapping(), "scan_epoch": self.scan_epoch, "capture_ref": self.capture_ref, "ciphertext_digest": self.ciphertext_digest, "disposition": self.disposition}


@dataclass(frozen=True)
class CaptureScanManifestV1:
    manifest_version: str; scope: SourceScopeRefV1; scan_epoch: str; checkpoint_ref: str; receipt_refs: tuple[str, ...]; manifest_ref: str; manifest_digest: str
    FIELDS: ClassVar[set[str]] = {"manifest_version", "scope", "scan_epoch", "checkpoint_ref", "receipt_refs", "manifest_ref", "manifest_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CaptureScanManifestV1":
        v = _strict(data, cls.FIELDS); _version(v["manifest_version"], CAPTURE_SCAN_MANIFEST_VERSION, "manifest_version")
        return cls(CAPTURE_SCAN_MANIFEST_VERSION, _scope(v["scope"]), _decimal(v["scan_epoch"], "scan_epoch", positive=True), _ref(v["checkpoint_ref"], "checkpoint_ref", kind="checkpoint"), _refs(v["receipt_refs"], "receipt_refs", kind="capture"), _ref(v["manifest_ref"], "manifest_ref", kind="manifest"), _digest(v["manifest_digest"], "manifest_digest"))

    def to_mapping(self) -> dict[str, Any]:
        return {"manifest_version": self.manifest_version, "scope": self.scope.to_mapping(), "scan_epoch": self.scan_epoch, "checkpoint_ref": self.checkpoint_ref, "receipt_refs": list(self.receipt_refs), "manifest_ref": self.manifest_ref, "manifest_digest": self.manifest_digest}


@dataclass(frozen=True)
class CaptureReconciliationV1:
    reconciliation_version: str; scope: SourceScopeRefV1; scan_epoch: str; manifest_ref: str; reconciliation_ref: str; reconciliation_epoch: str; completion: str; outcome: str; expected_receipt_count: str; accounted_receipt_count: str; disposition_counts: Mapping[str, str]; reconciliation_digest: str
    FIELDS: ClassVar[set[str]] = {"reconciliation_version", "scope", "scan_epoch", "manifest_ref", "reconciliation_ref", "reconciliation_epoch", "completion", "outcome", "expected_receipt_count", "accounted_receipt_count", "disposition_counts", "reconciliation_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CaptureReconciliationV1":
        v = _strict(data, cls.FIELDS); _version(v["reconciliation_version"], CAPTURE_RECONCILIATION_VERSION, "reconciliation_version")
        scan_epoch = _decimal(v["scan_epoch"], "scan_epoch", positive=True)
        reconciliation_epoch = _decimal(v["reconciliation_epoch"], "reconciliation_epoch", positive=True)
        expected = _decimal(v["expected_receipt_count"], "expected_receipt_count")
        accounted = _decimal(v["accounted_receipt_count"], "accounted_receipt_count")
        counts = _strict(v["disposition_counts"], set(CAPTURE_DISPOSITIONS))
        parsed_counts = {name: _decimal(counts[name], f"disposition_counts.{name}") for name in CAPTURE_DISPOSITIONS}
        if reconciliation_epoch != scan_epoch or not isinstance(v["completion"], str) or not isinstance(v["outcome"], str) or v["completion"] != RECONCILIATION_COMPLETION or v["outcome"] != RECONCILIATION_OUTCOME or expected != accounted or sum(map(int, parsed_counts.values())) != int(accounted):
            raise InvalidContractValue("reconciliation must completely account for its matching scan epoch")
        return cls(CAPTURE_RECONCILIATION_VERSION, _scope(v["scope"]), scan_epoch, _ref(v["manifest_ref"], "manifest_ref", kind="manifest"), _ref(v["reconciliation_ref"], "reconciliation_ref", kind="reconciliation"), reconciliation_epoch, RECONCILIATION_COMPLETION, RECONCILIATION_OUTCOME, expected, accounted, MappingProxyType(parsed_counts), _digest(v["reconciliation_digest"], "reconciliation_digest"))

    def to_mapping(self) -> dict[str, Any]:
        return {"reconciliation_version": self.reconciliation_version, "scope": self.scope.to_mapping(), "scan_epoch": self.scan_epoch, "manifest_ref": self.manifest_ref, "reconciliation_ref": self.reconciliation_ref, "reconciliation_epoch": self.reconciliation_epoch, "completion": self.completion, "outcome": self.outcome, "expected_receipt_count": self.expected_receipt_count, "accounted_receipt_count": self.accounted_receipt_count, "disposition_counts": dict(self.disposition_counts), "reconciliation_digest": self.reconciliation_digest}


@dataclass(frozen=True)
class MigrationRegistrationV1:
    registration_version: str; migration_source: str; migration_ref: str; migration_scope_ref: str; scope: SourceScopeRefV1; migration_epoch: str; registration_ref: str; ciphertext_digest: str
    FIELDS: ClassVar[set[str]] = {"registration_version", "migration_source", "migration_ref", "migration_scope_ref", "scope", "migration_epoch", "registration_ref", "ciphertext_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationRegistrationV1":
        v = _strict(data, cls.FIELDS); _version(v["registration_version"], MIGRATION_REGISTRATION_VERSION, "registration_version")
        source = _closed(v["migration_source"], MIGRATION_SOURCES, "migration_source")
        domain = MIGRATION_DOMAINS[source]
        return cls(MIGRATION_REGISTRATION_VERSION, source, _ref(v["migration_ref"], "migration_ref", kind=f"{domain}-migration"), _ref(v["migration_scope_ref"], "migration_scope_ref", kind=f"{domain}-migration-scope"), _scope(v["scope"]), _decimal(v["migration_epoch"], "migration_epoch", positive=True), _ref(v["registration_ref"], "registration_ref", kind="migration-registration"), _digest(v["ciphertext_digest"], "ciphertext_digest"))

    def to_mapping(self) -> dict[str, Any]:
        return {"registration_version": self.registration_version, "migration_source": self.migration_source, "migration_ref": self.migration_ref, "migration_scope_ref": self.migration_scope_ref, "scope": self.scope.to_mapping(), "migration_epoch": self.migration_epoch, "registration_ref": self.registration_ref, "ciphertext_digest": self.ciphertext_digest}


@dataclass(frozen=True)
class CaptureCohortRosterEntryV1:
    source_domain: str; source_ref: str; registration_ref: str; scope_ref: str; manifest_ref: str; ownership_binding: Mapping[str, str]
    FIELDS: ClassVar[set[str]] = {"source_domain", "source_ref", "registration_ref", "scope_ref", "manifest_ref", "ownership_binding"}
    BINDING_FIELDS: ClassVar[set[str]] = {"workspace_ref", "source_ref", "registration_ref", "scope_ref", "manifest_ref"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CaptureCohortRosterEntryV1":
        v = _strict(data, cls.FIELDS)
        domain = _closed(v["source_domain"], set(SOURCE_DOMAINS.values()), "source_domain")
        source_ref = _ref(v["source_ref"], "source_ref", kind=f"{domain}-source")
        registration_ref = _ref(v["registration_ref"], "registration_ref", kind="migration-registration")
        scope_ref = _ref(v["scope_ref"], "scope_ref", kind=f"{domain}-scope")
        manifest_ref = _ref(v["manifest_ref"], "manifest_ref", kind="manifest")
        binding = _strict(v["ownership_binding"], cls.BINDING_FIELDS)
        parsed_binding = {
            "workspace_ref": _ref(binding["workspace_ref"], "ownership_binding.workspace_ref", kind="workspace"),
            "source_ref": _ref(binding["source_ref"], "ownership_binding.source_ref", kind=f"{domain}-source"),
            "registration_ref": _ref(binding["registration_ref"], "ownership_binding.registration_ref", kind="migration-registration"),
            "scope_ref": _ref(binding["scope_ref"], "ownership_binding.scope_ref", kind=f"{domain}-scope"),
            "manifest_ref": _ref(binding["manifest_ref"], "ownership_binding.manifest_ref", kind="manifest"),
        }
        if any(parsed_binding[name] != value for name, value in (("source_ref", source_ref), ("registration_ref", registration_ref), ("scope_ref", scope_ref), ("manifest_ref", manifest_ref))):
            raise InvalidContractValue("ownership_binding must exactly bind roster references")
        return cls(domain, source_ref, registration_ref, scope_ref, manifest_ref, MappingProxyType(parsed_binding))

    def to_mapping(self) -> dict[str, Any]:
        return {"source_domain": self.source_domain, "source_ref": self.source_ref, "registration_ref": self.registration_ref, "scope_ref": self.scope_ref, "manifest_ref": self.manifest_ref, "ownership_binding": dict(self.ownership_binding)}


@dataclass(frozen=True)
class NonServingCaptureCohortV1:
    cohort_version: str; cohort_ref: str; final_workspace_ref: str; state: str; source_roster: tuple[CaptureCohortRosterEntryV1, ...]; cohort_digest: str
    FIELDS: ClassVar[set[str]] = {"cohort_version", "cohort_ref", "final_workspace_ref", "state", "source_roster", "cohort_digest"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "NonServingCaptureCohortV1":
        v = _strict(data, cls.FIELDS); _version(v["cohort_version"], NON_SERVING_CAPTURE_COHORT_VERSION, "cohort_version")
        if not isinstance(v["state"], str) or v["state"] != NON_SERVING or not isinstance(v["source_roster"], list) or not v["source_roster"]:
            raise InvalidContractValue("capture cohort must be NON_SERVING with a non-empty source roster")
        workspace_ref = _ref(v["final_workspace_ref"], "final_workspace_ref", kind="workspace")
        roster = tuple(CaptureCohortRosterEntryV1.from_mapping(entry) for entry in v["source_roster"])
        if len({entry.source_ref for entry in roster}) != len(roster) or len({entry.registration_ref for entry in roster}) != len(roster) or any(entry.ownership_binding["workspace_ref"] != workspace_ref for entry in roster):
            raise InvalidContractValue("source roster must exactly bind its final workspace, sources, and registrations")
        return cls(NON_SERVING_CAPTURE_COHORT_VERSION, _ref(v["cohort_ref"], "cohort_ref", kind="cohort"), workspace_ref, NON_SERVING, roster, _digest(v["cohort_digest"], "cohort_digest"))

    def to_mapping(self) -> dict[str, Any]:
        return {"cohort_version": self.cohort_version, "cohort_ref": self.cohort_ref, "final_workspace_ref": self.final_workspace_ref, "state": self.state, "source_roster": [entry.to_mapping() for entry in self.source_roster], "cohort_digest": self.cohort_digest}


@dataclass(frozen=True)
class ReconciledCheckpointAdvanceV1:
    advance_version: str; previous_checkpoint_ref: str | None; reconciliation: CaptureReconciliationV1; checkpoint: ScanCheckpointV1
    FIELDS: ClassVar[set[str]] = {"advance_version", "previous_checkpoint_ref", "reconciliation", "checkpoint"}

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "ReconciledCheckpointAdvanceV1":
        v = _strict(data, cls.FIELDS); _version(v["advance_version"], RECONCILED_CHECKPOINT_ADVANCE_VERSION, "advance_version")
        previous = v["previous_checkpoint_ref"]
        if previous is not None:
            previous = _ref(previous, "previous_checkpoint_ref", kind="checkpoint")
        reconciliation = CaptureReconciliationV1.from_mapping(v["reconciliation"])
        checkpoint = ScanCheckpointV1.from_mapping(v["checkpoint"])
        if checkpoint.scope != reconciliation.scope or checkpoint.scan_epoch != reconciliation.scan_epoch or checkpoint.manifest_ref != reconciliation.manifest_ref or checkpoint.reconciliation_ref != reconciliation.reconciliation_ref or checkpoint.reconciliation_digest != reconciliation.reconciliation_digest:
            raise InvalidContractValue("checkpoint must authoritatively correlate to its reconciliation")
        return cls(RECONCILED_CHECKPOINT_ADVANCE_VERSION, previous, reconciliation, checkpoint)

    def to_mapping(self) -> dict[str, Any]:
        return {"advance_version": self.advance_version, "previous_checkpoint_ref": self.previous_checkpoint_ref, "reconciliation": self.reconciliation.to_mapping(), "checkpoint": self.checkpoint.to_mapping()}
