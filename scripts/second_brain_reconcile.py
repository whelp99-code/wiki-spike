#!/usr/bin/env python3
"""Fail-closed, offline validators for Second Brain reconciliation Slice A.

This module validates the evidence that a later reconciliation operation will
need.  It deliberately does not restore data, acquire a recall snapshot, or
authorize an import.  Those operational checks remain Slice B/C work.
"""
from __future__ import annotations

import argparse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Any


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_cutover import (  # noqa: E402
    MigrationCohortManifestV1,
)
from wiki_spike.memory_core.second_brain_ledger_ports import (  # noqa: E402
    AtomicRecallSnapshotPort,
    ReconciliationCoverageV1,
    ReconciliationFindingV1,
    ReconciliationRequestV1,
    ReconciliationResultV1,
    ValidatedRecallSnapshotAcquisitionV2,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (  # noqa: E402
    RecallSnapshotRequestV2,
    RecallTrustAuthorityV2,
    validate_recall_snapshot_acquisition,
)


RECONCILIATION_VERIFIER_V1 = "second-brain-reconcile-v1"
SOURCE_INVENTORY_V1 = "second-brain-reconcile-source-inventory-v1"
COHORT_INVENTORY_V1 = "second-brain-reconcile-cohort-inventory-v1"
BACKUP_MANIFEST_V1 = "second-brain-reconcile-backup-manifest-v1"
RECONCILIATION_RECEIPT_V1 = "second-brain-reconciliation-receipt-v1"
RECALL_SAMPLE_V1 = "second-brain-reconciliation-recall-sample-v1"
CONSERVATION_ONLY = "CONSERVATION_ONLY"
RESTORE_RECALL_VERIFIED = "RESTORE_RECALL_VERIFIED"

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_REASON_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_READ_CHUNK_BYTES = 1024 * 1024
_NON_SERVING_PRE_CUTOVER_STATES = frozenset(
    {
        "DISCOVERED",
        "IMPORTING",
        "QUARANTINED_ITEM",
        "RECONCILING",
        "READY_NON_SERVING",
        "CUTOVER_READY",
    }
)


class ReconciliationError(Exception):
    """A deterministic, caller-visible refusal at the offline boundary."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReconciliationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _strict_mapping(data: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(data, Mapping) or any(not isinstance(key, str) for key in data):
        raise ReconciliationError(f"{label} must be an object with string keys")
    unknown = set(data) - fields
    missing = fields - set(data)
    if unknown or missing:
        raise ReconciliationError(
            f"{label} fields are wrong; missing={sorted(missing)} unknown={sorted(unknown)}"
        )
    return dict(data)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ReconciliationError(f"{label} must be a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SHA256.fullmatch(value) is None:
        raise ReconciliationError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _positive_decimal(value: Any, label: str) -> str:
    if not isinstance(value, str) or _POSITIVE_DECIMAL.fullmatch(value) is None:
        raise ReconciliationError(f"{label} must be a positive canonical decimal string")
    return value


def _stat_identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    """Identity and mutation-sensitive metadata required around every file read."""
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


def _canonical_absolute_path(
    raw: str | os.PathLike[str],
    label: str,
    *,
    allow_missing_leaf: bool = False,
) -> Path:
    """Return a non-aliased absolute path without resolving symlinks.

    Normalization is rejected rather than performed.  That makes a path such as
    ``/a/../b`` or an ancestor symlink a different input instead of silently
    turning it into a trusted path.
    """
    raw_path = os.fspath(raw)
    if not isinstance(raw_path, str):
        raise ReconciliationError(f"{label} must be a path string")
    if (
        not raw_path
        or not os.path.isabs(raw_path)
        or raw_path.startswith("//")
        or raw_path != os.path.normpath(raw_path)
        or any(part in {"", ".", ".."} for part in raw_path.split(os.sep)[1:])
    ):
        raise ReconciliationError(f"{label} must be a canonical absolute path without aliases")

    path = Path(raw_path)
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            if allow_missing_leaf and index == len(components) - 1:
                return path
            raise ReconciliationError(f"{label} has a missing path component: {current}") from exc
        except OSError as exc:
            raise ReconciliationError(f"cannot stat {label} path component {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ReconciliationError(f"{label} must not traverse a symlink: {current}")
    return path


def _require_regular_file(path: Path, label: str) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ReconciliationError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ReconciliationError(f"{label} must be a regular non-symlink file")
    return info


def _open_readonly_no_follow(path: Path, label: str) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise ReconciliationError(f"cannot open {label}: {exc}") from exc


def _read_stable_regular_file(
    path: Path,
    label: str,
    *,
    maximum_size: int | None = None,
    reject_hardlinks: bool,
) -> tuple[bytes, str, int]:
    """Read a regular file once while proving it did not change across the read."""
    before = _require_regular_file(path, label)
    if reject_hardlinks and before.st_nlink != 1:
        raise ReconciliationError(f"{label} must not be hard-linked")
    if maximum_size is not None and before.st_size > maximum_size:
        raise ReconciliationError(f"{label} exceeds the maximum supported size")

    descriptor: int | None = None
    try:
        descriptor = _open_readonly_no_follow(path, label)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stat_identity(opened) != _stat_identity(before):
            raise ReconciliationError(f"{label} changed before it could be read")
        if reject_hardlinks and opened.st_nlink != 1:
            raise ReconciliationError(f"{label} must not be hard-linked")

        digest = sha256()
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, _READ_CHUNK_BYTES)
            if not chunk:
                break
            total += len(chunk)
            if maximum_size is not None and total > maximum_size:
                raise ReconciliationError(f"{label} exceeds the maximum supported size")
            digest.update(chunk)
            chunks.append(chunk)

        after = _require_regular_file(path, label)
        if _stat_identity(after) != _stat_identity(before) or total != before.st_size:
            raise ReconciliationError(f"{label} changed while it was read")
        if reject_hardlinks and after.st_nlink != 1:
            raise ReconciliationError(f"{label} must not be hard-linked")
        return b"".join(chunks), digest.hexdigest(), total
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_canonical_object(
    raw_path: str | os.PathLike[str],
    label: str,
) -> tuple[dict[str, Any], str]:
    path = _canonical_absolute_path(raw_path, label)
    raw, digest, _ = _read_stable_regular_file(
        path,
        label,
        maximum_size=_MAX_JSON_BYTES,
        reject_hardlinks=False,
    )
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReconciliationError(f"cannot parse {label} as UTF-8 canonical JSON") from exc
    if not isinstance(data, dict):
        raise ReconciliationError(f"{label} must contain a JSON object")
    try:
        canonical = canonical_bytes(data)
    except Exception as exc:
        raise ReconciliationError(f"{label} cannot be canonicalized") from exc
    if raw != canonical:
        raise ReconciliationError(f"{label} is not canonical JSON")
    return data, digest


@dataclass(frozen=True, slots=True)
class SourceCitationEvidenceV1:
    citation_ref: str
    citation_sha256: str

    FIELDS = {"citation_ref", "citation_sha256"}

    @classmethod
    def from_mapping(cls, data: Any, label: str) -> "SourceCitationEvidenceV1":
        values = _strict_mapping(data, cls.FIELDS, label)
        return cls(
            citation_ref=_text(values["citation_ref"], f"{label}.citation_ref"),
            citation_sha256=_digest(values["citation_sha256"], f"{label}.citation_sha256"),
        )

    def to_mapping(self) -> dict[str, str]:
        return {"citation_ref": self.citation_ref, "citation_sha256": self.citation_sha256}


@dataclass(frozen=True, slots=True)
class SourceInventoryRecordV1:
    native_id: str
    revision: str
    payload_sha256: str
    tombstone: bool
    dedupe_root_ref: str
    citation: SourceCitationEvidenceV1

    FIELDS = {
        "native_id",
        "revision",
        "payload_sha256",
        "tombstone",
        "dedupe_root_ref",
        "citation",
    }

    @classmethod
    def from_mapping(cls, data: Any, label: str) -> "SourceInventoryRecordV1":
        values = _strict_mapping(data, cls.FIELDS, label)
        if type(values["tombstone"]) is not bool:
            raise ReconciliationError(f"{label}.tombstone must be a boolean")
        return cls(
            native_id=_text(values["native_id"], f"{label}.native_id"),
            revision=_positive_decimal(values["revision"], f"{label}.revision"),
            payload_sha256=_digest(values["payload_sha256"], f"{label}.payload_sha256"),
            tombstone=values["tombstone"],
            dedupe_root_ref=_text(values["dedupe_root_ref"], f"{label}.dedupe_root_ref"),
            citation=SourceCitationEvidenceV1.from_mapping(
                values["citation"], f"{label}.citation"
            ),
        )

    @property
    def identity(self) -> tuple[str, str]:
        return self.native_id, self.revision

    def to_mapping(self) -> dict[str, Any]:
        return {
            "native_id": self.native_id,
            "revision": self.revision,
            "payload_sha256": self.payload_sha256,
            "tombstone": self.tombstone,
            "dedupe_root_ref": self.dedupe_root_ref,
            "citation": self.citation.to_mapping(),
        }


@dataclass(frozen=True, slots=True)
class CohortInventoryRecordV1:
    native_id: str
    revision: str
    payload_sha256: str
    tombstone: bool
    dedupe_root_ref: str
    citation: SourceCitationEvidenceV1
    disposition: str
    reason_code: str | None

    FIELDS = SourceInventoryRecordV1.FIELDS | {"disposition", "reason_code"}

    @classmethod
    def from_mapping(cls, data: Any, label: str) -> "CohortInventoryRecordV1":
        values = _strict_mapping(data, cls.FIELDS, label)
        source_record = SourceInventoryRecordV1.from_mapping(
            {field: values[field] for field in SourceInventoryRecordV1.FIELDS}, label
        )
        disposition = values["disposition"]
        reason_code = values["reason_code"]
        if disposition not in {"ACCEPTED", "QUARANTINED"}:
            raise ReconciliationError(f"{label}.disposition must be ACCEPTED or QUARANTINED")
        if disposition == "ACCEPTED" and reason_code is not None:
            raise ReconciliationError(f"{label}.reason_code must be null for ACCEPTED")
        if disposition == "QUARANTINED" and (
            not isinstance(reason_code, str) or _REASON_CODE.fullmatch(reason_code) is None
        ):
            raise ReconciliationError(
                f"{label}.reason_code must be a non-empty canonical code for QUARANTINED"
            )
        return cls(
            native_id=source_record.native_id,
            revision=source_record.revision,
            payload_sha256=source_record.payload_sha256,
            tombstone=source_record.tombstone,
            dedupe_root_ref=source_record.dedupe_root_ref,
            citation=source_record.citation,
            disposition=disposition,
            reason_code=reason_code,
        )

    @property
    def identity(self) -> tuple[str, str]:
        return self.native_id, self.revision

    def conservation_mapping(self) -> dict[str, Any]:
        return {
            "native_id": self.native_id,
            "revision": self.revision,
            "payload_sha256": self.payload_sha256,
            "tombstone": self.tombstone,
            "dedupe_root_ref": self.dedupe_root_ref,
            "citation": self.citation.to_mapping(),
        }

    def to_mapping(self) -> dict[str, Any]:
        return self.conservation_mapping() | {
            "disposition": self.disposition,
            "reason_code": self.reason_code,
        }


def _validate_record_order(
    records: tuple[SourceInventoryRecordV1, ...] | tuple[CohortInventoryRecordV1, ...],
    source_ref: str,
    label: str,
) -> None:
    identities = tuple((source_ref, record.native_id, int(record.revision)) for record in records)
    if identities != tuple(sorted(identities)):
        raise ReconciliationError(
            f"{label}.records must be sorted by source_ref, native_id, numeric revision"
        )
    if len(set(identities)) != len(identities):
        raise ReconciliationError(f"{label}.records contain duplicate native identity/revision")


@dataclass(frozen=True, slots=True)
class SourceInventoryV1:
    source_ref: str
    source_root: Path
    records: tuple[SourceInventoryRecordV1, ...]

    FIELDS = {"inventory_version", "source_ref", "source_root", "records"}

    @classmethod
    def from_mapping(cls, data: Any) -> "SourceInventoryV1":
        values = _strict_mapping(data, cls.FIELDS, "source inventory")
        if values["inventory_version"] != SOURCE_INVENTORY_V1:
            raise ReconciliationError("unsupported source inventory version")
        source_ref = _text(values["source_ref"], "source inventory.source_ref")
        source_root_value = _text(values["source_root"], "source inventory.source_root")
        source_root = _canonical_absolute_path(
            source_root_value,
            "source inventory.source_root",
            allow_missing_leaf=True,
        )
        if not isinstance(values["records"], list):
            raise ReconciliationError("source inventory.records must be a list")
        records = tuple(
            SourceInventoryRecordV1.from_mapping(item, f"source inventory.records[{index}]")
            for index, item in enumerate(values["records"])
        )
        _validate_record_order(records, source_ref, "source inventory")
        return cls(source_ref=source_ref, source_root=source_root, records=records)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "inventory_version": SOURCE_INVENTORY_V1,
            "source_ref": self.source_ref,
            "source_root": str(self.source_root),
            "records": [record.to_mapping() for record in self.records],
        }


@dataclass(frozen=True, slots=True)
class CohortInventoryV1:
    source_ref: str
    workspace_ref: str
    records: tuple[CohortInventoryRecordV1, ...]

    FIELDS = {"inventory_version", "source_ref", "workspace_ref", "records"}

    @classmethod
    def from_mapping(cls, data: Any) -> "CohortInventoryV1":
        values = _strict_mapping(data, cls.FIELDS, "cohort inventory")
        if values["inventory_version"] != COHORT_INVENTORY_V1:
            raise ReconciliationError("unsupported cohort inventory version")
        source_ref = _text(values["source_ref"], "cohort inventory.source_ref")
        workspace_ref = _text(values["workspace_ref"], "cohort inventory.workspace_ref")
        if not isinstance(values["records"], list):
            raise ReconciliationError("cohort inventory.records must be a list")
        records = tuple(
            CohortInventoryRecordV1.from_mapping(item, f"cohort inventory.records[{index}]")
            for index, item in enumerate(values["records"])
        )
        _validate_record_order(records, source_ref, "cohort inventory")
        return cls(source_ref=source_ref, workspace_ref=workspace_ref, records=records)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "inventory_version": COHORT_INVENTORY_V1,
            "source_ref": self.source_ref,
            "workspace_ref": self.workspace_ref,
            "records": [record.to_mapping() for record in self.records],
        }


def validate_source_inventory(data: Any) -> SourceInventoryV1:
    """Validate the closed source inventory schema without adding dispositions."""
    return SourceInventoryV1.from_mapping(data)


def validate_cohort_inventory(data: Any) -> CohortInventoryV1:
    """Validate the closed cohort inventory schema and disposition semantics."""
    return CohortInventoryV1.from_mapping(data)


def validate_inventory_conservation(
    source_inventory: SourceInventoryV1,
    cohort_inventory: CohortInventoryV1,
) -> None:
    """Require an exact, lossless source-to-cohort identity and payload mapping."""
    if source_inventory.source_ref != cohort_inventory.source_ref:
        raise ReconciliationError("source and cohort inventory source_ref values must match")
    source_records = {record.identity: record for record in source_inventory.records}
    cohort_records = {record.identity: record for record in cohort_inventory.records}
    if source_records.keys() != cohort_records.keys():
        raise ReconciliationError("source and cohort inventories must contain exactly the same identities")
    for identity, source_record in source_records.items():
        if source_record.to_mapping() != cohort_records[identity].conservation_mapping():
            raise ReconciliationError(f"cohort record changed source conservation fields: {identity!r}")


@dataclass(frozen=True, slots=True)
class ReconciliationAggregateDigestsV1:
    """Closed set digests.  The receipt contains these hashes, never record content."""

    identities_sha256: str
    revisions_history_sha256: str
    payloads_sha256: str
    tombstones_sha256: str
    dedupe_bindings_sha256: str
    citations_sha256: str
    quarantine_bindings_sha256: str

    def __post_init__(self) -> None:
        for field in (
            "identities_sha256",
            "revisions_history_sha256",
            "payloads_sha256",
            "tombstones_sha256",
            "dedupe_bindings_sha256",
            "citations_sha256",
            "quarantine_bindings_sha256",
        ):
            _digest(getattr(self, field), field)

    def to_mapping(self) -> dict[str, str]:
        return {
            "identities_sha256": self.identities_sha256,
            "revisions_history_sha256": self.revisions_history_sha256,
            "payloads_sha256": self.payloads_sha256,
            "tombstones_sha256": self.tombstones_sha256,
            "dedupe_bindings_sha256": self.dedupe_bindings_sha256,
            "citations_sha256": self.citations_sha256,
            "quarantine_bindings_sha256": self.quarantine_bindings_sha256,
        }

    @classmethod
    def from_mapping(cls, data: Any) -> "ReconciliationAggregateDigestsV1":
        values = _strict_mapping(
            data,
            {
                "identities_sha256",
                "revisions_history_sha256",
                "payloads_sha256",
                "tombstones_sha256",
                "dedupe_bindings_sha256",
                "citations_sha256",
                "quarantine_bindings_sha256",
            },
            "reconciliation receipt.aggregate_digests",
        )
        try:
            return cls(**values)
        except (TypeError, ValueError) as exc:
            raise ReconciliationError(f"invalid reconciliation aggregate digests: {exc}") from exc


def _request_mapping(request: ReconciliationRequestV1) -> dict[str, str]:
    return {
        "verifier_version": request.verifier_version,
        "source_inventory_digest": request.source_inventory_digest,
        "cohort_inventory_digest": request.cohort_inventory_digest,
        "cohort_manifest_digest": request.cohort_manifest_digest,
        "backup_manifest_digest": request.backup_manifest_digest,
    }


def _result_mapping(result: ReconciliationResultV1) -> dict[str, Any]:
    return {
        "result": result.result,
        "no_import": result.no_import,
        "live_operation_authorized": False,
        "coverage": {
            "source_total": result.coverage.source_total,
            "cohort_total": result.coverage.cohort_total,
            "accepted_total": result.coverage.accepted_total,
            "quarantined_total": result.coverage.quarantined_total,
        },
        "findings": [
            {"rule_code": finding.rule_code, "evidence_sha256": finding.evidence_sha256}
            for finding in result.findings
        ],
    }


def _request_from_mapping(data: Any) -> ReconciliationRequestV1:
    values = _strict_mapping(
        data,
        {
            "verifier_version",
            "source_inventory_digest",
            "cohort_inventory_digest",
            "cohort_manifest_digest",
            "backup_manifest_digest",
        },
        "reconciliation receipt.request",
    )
    try:
        return ReconciliationRequestV1(**values)
    except (TypeError, ValueError) as exc:
        raise ReconciliationError(f"invalid reconciliation receipt request: {exc}") from exc


def _result_from_mapping(data: Any) -> ReconciliationResultV1:
    values = _strict_mapping(
        data,
        {"result", "no_import", "live_operation_authorized", "coverage", "findings"},
        "reconciliation receipt.result",
    )
    coverage_values = _strict_mapping(
        values["coverage"],
        {"source_total", "cohort_total", "accepted_total", "quarantined_total"},
        "reconciliation receipt.result.coverage",
    )
    if not isinstance(values["findings"], list):
        raise ReconciliationError("reconciliation receipt.result.findings must be a list")
    findings: list[ReconciliationFindingV1] = []
    for index, item in enumerate(values["findings"]):
        finding_values = _strict_mapping(
            item,
            {"rule_code", "evidence_sha256"},
            f"reconciliation receipt.result.findings[{index}]",
        )
        try:
            findings.append(ReconciliationFindingV1(**finding_values))
        except (TypeError, ValueError) as exc:
            raise ReconciliationError(f"invalid reconciliation receipt finding: {exc}") from exc
    if type(values["no_import"]) is not bool or type(values["live_operation_authorized"]) is not bool:
        raise ReconciliationError("reconciliation receipt result flags must be booleans")
    try:
        return ReconciliationResultV1(
            values["result"],
            values["no_import"],
            values["live_operation_authorized"],
            ReconciliationCoverageV1(**coverage_values),
            tuple(findings),
        )
    except (TypeError, ValueError) as exc:
        raise ReconciliationError(f"invalid reconciliation receipt result: {exc}") from exc


@dataclass(frozen=True, slots=True)
class ReconciliationReceiptV1:
    """Closed, self-digesting receipt that carries no source record contents."""

    request: ReconciliationRequestV1
    result: ReconciliationResultV1
    aggregate_digests: ReconciliationAggregateDigestsV1
    verification_mode: str
    recall_sample_digest: str | None
    isolated_restore_target_digest: str | None
    deterministic_recall_digest: str | None
    receipt_sha256: str

    FIELDS = {
        "reconciliation_receipt_version",
        "request",
        "result",
        "aggregate_digests",
        "verification_mode",
        "recall_sample_digest",
        "isolated_restore_target_digest",
        "deterministic_recall_digest",
        "receipt_sha256",
    }

    def __post_init__(self) -> None:
        if not isinstance(self.request, ReconciliationRequestV1):
            raise ReconciliationError("reconciliation receipt requires a validated request")
        if not isinstance(self.result, ReconciliationResultV1):
            raise ReconciliationError("reconciliation receipt requires a validated result")
        if not isinstance(self.aggregate_digests, ReconciliationAggregateDigestsV1):
            raise ReconciliationError("reconciliation receipt requires validated aggregate digests")
        required_digests = (
            self.recall_sample_digest,
            self.isolated_restore_target_digest,
            self.deterministic_recall_digest,
        )
        if self.verification_mode == CONSERVATION_ONLY:
            if any(value is not None for value in required_digests):
                raise ReconciliationError("CONSERVATION_ONLY receipt must not carry operational digests")
        elif self.verification_mode == RESTORE_RECALL_VERIFIED:
            if (
                self.result.result != "PASS"
                or self.result.no_import
                or self.result.live_operation_authorized
                or any(not isinstance(value, str) or _digest(value, "receipt operational digest") != value for value in required_digests)
            ):
                raise ReconciliationError("RESTORE_RECALL_VERIFIED receipt requires PASS non-live operational digests")
        else:
            raise ReconciliationError("unsupported reconciliation receipt verification_mode")
        expected = self.body_digest()
        if _digest(self.receipt_sha256, "reconciliation receipt.receipt_sha256") != expected:
            raise ReconciliationError("reconciliation receipt self-digest mismatch")

    def body_mapping(self) -> dict[str, Any]:
        return {
            "reconciliation_receipt_version": RECONCILIATION_RECEIPT_V1,
            "request": _request_mapping(self.request),
            "result": _result_mapping(self.result),
            "aggregate_digests": self.aggregate_digests.to_mapping(),
            "verification_mode": self.verification_mode,
            "recall_sample_digest": self.recall_sample_digest,
            "isolated_restore_target_digest": self.isolated_restore_target_digest,
            "deterministic_recall_digest": self.deterministic_recall_digest,
        }

    def body_digest(self) -> str:
        return sha256(canonical_bytes(self.body_mapping())).hexdigest()

    def to_mapping(self) -> dict[str, Any]:
        return self.body_mapping() | {"receipt_sha256": self.receipt_sha256}

    @classmethod
    def create(
        cls,
        request: ReconciliationRequestV1,
        result: ReconciliationResultV1,
        aggregate_digests: ReconciliationAggregateDigestsV1,
        *,
        verification_mode: str = CONSERVATION_ONLY,
        recall_sample_digest: str | None = None,
        isolated_restore_target_digest: str | None = None,
        deterministic_recall_digest: str | None = None,
    ) -> "ReconciliationReceiptV1":
        body = {
            "reconciliation_receipt_version": RECONCILIATION_RECEIPT_V1,
            "request": _request_mapping(request),
            "result": _result_mapping(result),
            "aggregate_digests": aggregate_digests.to_mapping(),
            "verification_mode": verification_mode,
            "recall_sample_digest": recall_sample_digest,
            "isolated_restore_target_digest": isolated_restore_target_digest,
            "deterministic_recall_digest": deterministic_recall_digest,
        }
        return cls(
            request, result, aggregate_digests, verification_mode, recall_sample_digest,
            isolated_restore_target_digest, deterministic_recall_digest,
            sha256(canonical_bytes(body)).hexdigest(),
        )

    @classmethod
    def from_mapping(cls, data: Any) -> "ReconciliationReceiptV1":
        values = _strict_mapping(data, cls.FIELDS, "reconciliation receipt")
        if values["reconciliation_receipt_version"] != RECONCILIATION_RECEIPT_V1:
            raise ReconciliationError("unsupported reconciliation receipt version")
        return cls(
            _request_from_mapping(values["request"]),
            _result_from_mapping(values["result"]),
            ReconciliationAggregateDigestsV1.from_mapping(values["aggregate_digests"]),
            values["verification_mode"],
            values["recall_sample_digest"],
            values["isolated_restore_target_digest"],
            values["deterministic_recall_digest"],
            _digest(values["receipt_sha256"], "reconciliation receipt.receipt_sha256"),
        )


def validate_reconciliation_receipt(data: Any) -> ReconciliationReceiptV1:
    return ReconciliationReceiptV1.from_mapping(data)


def _canonical_set_digest(entries: Iterable[Mapping[str, Any]]) -> str:
    """Hash a deterministic, closed canonical set without retaining source contents."""
    try:
        return sha256(canonical_bytes(sorted((dict(entry) for entry in entries), key=canonical_bytes))).hexdigest()
    except Exception as exc:
        raise ReconciliationError("cannot canonicalize reconciliation aggregate") from exc


def _validate_dedupe_bindings(records: Iterable[SourceInventoryRecordV1]) -> None:
    """A payload may be deduplicated only under one non-empty root, and vice versa."""
    payload_to_root: dict[str, str] = {}
    root_to_payload: dict[str, str] = {}
    for record in records:
        root = record.dedupe_root_ref
        payload = record.payload_sha256
        prior_root = payload_to_root.setdefault(payload, root)
        if prior_root != root:
            raise ReconciliationError("dedupe payload is bound to multiple roots")
        prior_payload = root_to_payload.setdefault(root, payload)
        if prior_payload != payload:
            raise ReconciliationError("dedupe root is bound to multiple payloads")


def _aggregate_digests(
    source_inventory: SourceInventoryV1,
    cohort_inventory: CohortInventoryV1,
) -> ReconciliationAggregateDigestsV1:
    source_records = source_inventory.records
    histories: list[dict[str, Any]] = []
    revisions_by_native_id: dict[str, list[str]] = {}
    for record in source_records:
        revisions_by_native_id.setdefault(record.native_id, []).append(record.revision)
    for native_id, revisions in revisions_by_native_id.items():
        histories.append(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": native_id,
                "revisions": revisions,
            }
        )
    return ReconciliationAggregateDigestsV1(
        identities_sha256=_canonical_set_digest(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
            }
            for record in source_records
        ),
        revisions_history_sha256=_canonical_set_digest(histories),
        payloads_sha256=_canonical_set_digest(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
                "payload_sha256": record.payload_sha256,
            }
            for record in source_records
        ),
        tombstones_sha256=_canonical_set_digest(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
                "tombstone": record.tombstone,
            }
            for record in source_records
        ),
        dedupe_bindings_sha256=_canonical_set_digest(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
                "dedupe_root_ref": record.dedupe_root_ref,
                "payload_sha256": record.payload_sha256,
            }
            for record in source_records
        ),
        citations_sha256=_canonical_set_digest(
            {
                "source_ref": source_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
                "payload_sha256": record.payload_sha256,
                "citation_ref": record.citation.citation_ref,
                "citation_sha256": record.citation.citation_sha256,
            }
            for record in source_records
        ),
        quarantine_bindings_sha256=_canonical_set_digest(
            {
                "source_ref": cohort_inventory.source_ref,
                "native_id": record.native_id,
                "revision": record.revision,
                "reason_code": record.reason_code,
            }
            for record in cohort_inventory.records
            if record.disposition == "QUARANTINED"
        ),
    )


def reconcile_inventory_conservation(
    source_inventory: SourceInventoryV1,
    cohort_inventory: CohortInventoryV1,
) -> tuple[ReconciliationResultV1, ReconciliationAggregateDigestsV1]:
    """Produce an offline-only decision from two already closed inventories.

    A quarantined record is deliberately retained in coverage and becomes a
    hash-only finding.  This function neither imports nor makes any record
    recallable; ``live_operation_authorized`` is always false by the Core DTO.
    """
    validate_inventory_conservation(source_inventory, cohort_inventory)
    _validate_dedupe_bindings(source_inventory.records)
    aggregate_digests = _aggregate_digests(source_inventory, cohort_inventory)
    quarantined = tuple(
        record for record in cohort_inventory.records if record.disposition == "QUARANTINED"
    )
    findings = tuple(
        ReconciliationFindingV1(
            record.reason_code or "INVALID_QUARANTINE_REASON",
            _canonical_set_digest(
                (
                    {
                        "source_ref": source_inventory.source_ref,
                        "native_id": record.native_id,
                        "revision": record.revision,
                        "reason_code": record.reason_code,
                    },
                )
            ),
        )
        for record in quarantined
    )
    coverage = ReconciliationCoverageV1(
        str(len(source_inventory.records)),
        str(len(cohort_inventory.records)),
        str(len(cohort_inventory.records) - len(quarantined)),
        str(len(quarantined)),
    )
    result = ReconciliationResultV1(
        "QUARANTINED" if quarantined else "PASS",
        bool(quarantined),
        False,
        coverage,
        findings,
    )
    return result, aggregate_digests


def reconciliation_receipt_mapping(
    request: ReconciliationRequestV1,
    result: ReconciliationResultV1,
    aggregate_digests: ReconciliationAggregateDigestsV1,
    *,
    verification_mode: str = CONSERVATION_ONLY,
    recall_sample_digest: str | None = None,
    isolated_restore_target_digest: str | None = None,
    deterministic_recall_digest: str | None = None,
) -> dict[str, Any]:
    """Return a closed, hash-only receipt suitable for atomic offline publish."""
    return ReconciliationReceiptV1.create(
        request, result, aggregate_digests,
        verification_mode=verification_mode,
        recall_sample_digest=recall_sample_digest,
        isolated_restore_target_digest=isolated_restore_target_digest,
        deterministic_recall_digest=deterministic_recall_digest,
    ).to_mapping()


def load_source_inventory_document(path: str | os.PathLike[str]) -> tuple[SourceInventoryV1, str]:
    data, digest = _load_canonical_object(path, "source inventory")
    return validate_source_inventory(data), digest


def load_cohort_inventory_document(path: str | os.PathLike[str]) -> tuple[CohortInventoryV1, str]:
    data, digest = _load_canonical_object(path, "cohort inventory")
    return validate_cohort_inventory(data), digest


@dataclass(frozen=True, slots=True)
class CohortManifestBindingV1:
    """Both the canonical file digest and Core-validated manifest body digest."""

    manifest: MigrationCohortManifestV1
    canonical_file_digest: str
    manifest_digest: str


def parse_and_bind_cohort_manifest(
    path: str | os.PathLike[str],
    cohort_inventory: CohortInventoryV1,
) -> CohortManifestBindingV1:
    """Use the existing public Core parser; do not duplicate its state machine."""
    data, file_digest = _load_canonical_object(path, "cohort manifest")
    try:
        manifest = MigrationCohortManifestV1.from_mapping(data)
    except Exception as exc:
        raise ReconciliationError(f"invalid cohort manifest: {exc}") from exc
    if manifest.cohort_state not in _NON_SERVING_PRE_CUTOVER_STATES:
        raise ReconciliationError("cohort manifest must remain non-serving and pre-cutover")
    if len(manifest.source_names) != 1 or manifest.source_names[0] != cohort_inventory.source_ref:
        raise ReconciliationError("cohort manifest must bind exactly the inventory source")
    if manifest.workspace_ref != cohort_inventory.workspace_ref:
        raise ReconciliationError("cohort manifest workspace_ref must match cohort inventory")
    return CohortManifestBindingV1(
        manifest=manifest,
        canonical_file_digest=file_digest,
        manifest_digest=manifest.manifest_digest,
    )


def _canonical_relative_path(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/") or value.startswith("//"):
        raise ReconciliationError(f"{label} must be a canonical relative path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ReconciliationError(f"{label} must not contain traversal or aliases")
    if Path(value).as_posix() != value:
        raise ReconciliationError(f"{label} must be a canonical POSIX relative path")
    return value


@dataclass(frozen=True, slots=True)
class BackupFileV1:
    relative_path: str
    size: str
    sha256: str

    FIELDS = {"relative_path", "size", "sha256"}

    @classmethod
    def from_mapping(cls, data: Any, label: str) -> "BackupFileV1":
        values = _strict_mapping(data, cls.FIELDS, label)
        return cls(
            relative_path=_canonical_relative_path(values["relative_path"], f"{label}.relative_path"),
            size=_positive_decimal(values["size"], f"{label}.size"),
            sha256=_digest(values["sha256"], f"{label}.sha256"),
        )

    def to_mapping(self) -> dict[str, str]:
        return {"relative_path": self.relative_path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True, slots=True)
class BackupManifestV1:
    source_inventory_digest: str
    cohort_inventory_digest: str
    cohort_manifest_digest: str
    backup_root: Path
    files: tuple[BackupFileV1, ...]

    FIELDS = {
        "backup_manifest_version",
        "source_inventory_digest",
        "cohort_inventory_digest",
        "cohort_manifest_digest",
        "backup_root",
        "files",
    }

    @classmethod
    def from_mapping(
        cls,
        data: Any,
        *,
        source_inventory_digest: str,
        cohort_inventory_digest: str,
        cohort_manifest_digest: str,
    ) -> "BackupManifestV1":
        values = _strict_mapping(data, cls.FIELDS, "backup manifest")
        if values["backup_manifest_version"] != BACKUP_MANIFEST_V1:
            raise ReconciliationError("unsupported backup manifest version")
        actual_source_digest = _digest(
            values["source_inventory_digest"], "backup manifest.source_inventory_digest"
        )
        actual_cohort_digest = _digest(
            values["cohort_inventory_digest"], "backup manifest.cohort_inventory_digest"
        )
        actual_manifest_digest = _digest(
            values["cohort_manifest_digest"], "backup manifest.cohort_manifest_digest"
        )
        if (
            actual_source_digest != _digest(source_inventory_digest, "source inventory file digest")
            or actual_cohort_digest != _digest(cohort_inventory_digest, "cohort inventory file digest")
            or actual_manifest_digest != _digest(cohort_manifest_digest, "cohort manifest file digest")
        ):
            raise ReconciliationError("backup manifest input digest binding mismatch")
        backup_root = _canonical_absolute_path(
            _text(values["backup_root"], "backup manifest.backup_root"),
            "backup manifest.backup_root",
        )
        if not isinstance(values["files"], list):
            raise ReconciliationError("backup manifest.files must be a list")
        files = tuple(
            BackupFileV1.from_mapping(item, f"backup manifest.files[{index}]")
            for index, item in enumerate(values["files"])
        )
        paths = tuple(item.relative_path for item in files)
        if paths != tuple(sorted(paths)):
            raise ReconciliationError("backup manifest.files must be sorted by relative_path")
        if len(set(paths)) != len(paths):
            raise ReconciliationError("backup manifest.files must not contain duplicate paths")
        return cls(
            source_inventory_digest=actual_source_digest,
            cohort_inventory_digest=actual_cohort_digest,
            cohort_manifest_digest=actual_manifest_digest,
            backup_root=backup_root,
            files=files,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "backup_manifest_version": BACKUP_MANIFEST_V1,
            "source_inventory_digest": self.source_inventory_digest,
            "cohort_inventory_digest": self.cohort_inventory_digest,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "backup_root": str(self.backup_root),
            "files": [item.to_mapping() for item in self.files],
        }


def validate_backup_manifest(
    data: Any,
    *,
    source_inventory_digest: str,
    cohort_inventory_digest: str,
    cohort_manifest_digest: str,
) -> BackupManifestV1:
    return BackupManifestV1.from_mapping(
        data,
        source_inventory_digest=source_inventory_digest,
        cohort_inventory_digest=cohort_inventory_digest,
        cohort_manifest_digest=cohort_manifest_digest,
    )


def load_backup_manifest_document(
    path: str | os.PathLike[str],
    *,
    source_inventory_digest: str,
    cohort_inventory_digest: str,
    cohort_manifest_digest: str,
) -> tuple[BackupManifestV1, str]:
    data, digest = _load_canonical_object(path, "backup manifest")
    return (
        validate_backup_manifest(
            data,
            source_inventory_digest=source_inventory_digest,
            cohort_inventory_digest=cohort_inventory_digest,
            cohort_manifest_digest=cohort_manifest_digest,
        ),
        digest,
    )


def _path_is_related(left: Path, right: Path) -> bool:
    try:
        left.relative_to(right)
        return True
    except ValueError:
        pass
    try:
        right.relative_to(left)
        return True
    except ValueError:
        return False


def _assert_backup_root_isolated(
    backup_root: Path,
    source_root: Path,
    *,
    workspace_root: str | os.PathLike[str] | None,
    restore_path: str | os.PathLike[str] | None,
    input_paths: Iterable[str | os.PathLike[str]],
    output_path: str | os.PathLike[str] | None,
) -> None:
    protected: list[tuple[str, Path]] = [("source_root", source_root)]
    if workspace_root is not None:
        protected.append(
            (
                "workspace_root",
                _canonical_absolute_path(workspace_root, "workspace_root", allow_missing_leaf=True),
            )
        )
    if restore_path is not None:
        protected.append(
            (
                "restore_path",
                _canonical_absolute_path(restore_path, "restore_path", allow_missing_leaf=True),
            )
        )
    if output_path is not None:
        protected.append(
            (
                "output_path",
                _canonical_absolute_path(output_path, "output_path", allow_missing_leaf=True),
            )
        )
    for index, input_path in enumerate(input_paths):
        protected.append(
            (
                f"input_paths[{index}]",
                _canonical_absolute_path(input_path, f"input_paths[{index}]", allow_missing_leaf=True),
            )
        )
    for label, path in protected:
        if _path_is_related(backup_root, path):
            raise ReconciliationError(f"backup_root must be isolated from {label}")


def _directory_snapshot(directory: Path, label: str) -> tuple[tuple[int, int, int, int, int], tuple[str, ...]]:
    try:
        before = directory.lstat()
    except OSError as exc:
        raise ReconciliationError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        raise ReconciliationError(f"{label} must be a non-symlink directory")
    try:
        with os.scandir(directory) as entries:
            names = tuple(sorted(entry.name for entry in entries))
        after = directory.lstat()
    except OSError as exc:
        raise ReconciliationError(f"cannot enumerate {label}: {exc}") from exc
    if _stat_identity(before) != _stat_identity(after):
        raise ReconciliationError(f"{label} changed during inventory")
    return _stat_identity(before), names


def _scan_backup_tree(root: Path) -> tuple[BackupFileV1, ...]:
    """Produce a stable, regular-file-only tree inventory without following links."""
    seen_inodes: set[tuple[int, int]] = set()
    found: list[BackupFileV1] = []

    def visit(directory: Path, relative_directory: str) -> None:
        directory_identity, names = _directory_snapshot(directory, f"backup directory {directory}")
        inode = directory_identity[:2]
        if inode in seen_inodes:
            raise ReconciliationError("backup tree contains a duplicate directory inode")
        seen_inodes.add(inode)
        for name in names:
            child = directory / name
            relative_path = name if not relative_directory else f"{relative_directory}/{name}"
            try:
                info = child.lstat()
            except OSError as exc:
                raise ReconciliationError(f"cannot stat backup entry {relative_path}: {exc}") from exc
            if stat.S_ISLNK(info.st_mode):
                raise ReconciliationError(f"backup tree contains a symlink: {relative_path}")
            if stat.S_ISDIR(info.st_mode):
                visit(child, relative_path)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ReconciliationError(f"backup tree contains a special file: {relative_path}")
            if info.st_nlink != 1:
                raise ReconciliationError(f"backup tree contains a hard-linked file: {relative_path}")
            inode = info.st_dev, info.st_ino
            if inode in seen_inodes:
                raise ReconciliationError(f"backup tree contains a duplicate inode: {relative_path}")
            seen_inodes.add(inode)
            _, digest, size = _read_stable_regular_file(
                child,
                f"backup file {relative_path}",
                reject_hardlinks=True,
            )
            found.append(BackupFileV1(relative_path, _positive_decimal(str(size), relative_path), digest))

        final_identity, final_names = _directory_snapshot(directory, f"backup directory {directory}")
        if directory_identity != final_identity or names != final_names:
            raise ReconciliationError(f"backup directory changed during recursive inventory: {directory}")

    visit(root, "")
    return tuple(sorted(found, key=lambda item: item.relative_path))


def verify_backup_inventory(
    backup_manifest: BackupManifestV1,
    source_inventory: SourceInventoryV1,
    *,
    workspace_root: str | os.PathLike[str] | None = None,
    restore_path: str | os.PathLike[str] | None = None,
    input_paths: Iterable[str | os.PathLike[str]] = (),
    output_path: str | os.PathLike[str] | None = None,
) -> tuple[BackupFileV1, ...]:
    """Check exact backup content and path isolation.  This is read-only."""
    try:
        root_info = backup_manifest.backup_root.lstat()
    except OSError as exc:
        raise ReconciliationError(f"cannot stat backup_root: {exc}") from exc
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        raise ReconciliationError("backup_root must be a non-symlink directory")
    _assert_backup_root_isolated(
        backup_manifest.backup_root,
        source_inventory.source_root,
        workspace_root=workspace_root,
        restore_path=restore_path,
        input_paths=input_paths,
        output_path=output_path,
    )
    actual = _scan_backup_tree(backup_manifest.backup_root)
    expected = backup_manifest.files
    if tuple(item.relative_path for item in actual) != tuple(item.relative_path for item in expected):
        raise ReconciliationError("backup inventory has missing or extra files")
    if actual != expected:
        raise ReconciliationError("backup inventory file size or SHA-256 mismatch")
    return actual


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write while creating atomic output")
        offset += written


def _fsync_directory(directory: Path) -> None:
    descriptor: int | None = None
    try:
        descriptor = os.open(directory, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def publish_canonical_json_atomic(
    raw_path: str | os.PathLike[str],
    document: Mapping[str, Any],
) -> None:
    """Durably create a new canonical JSON file without overwriting a collision.

    A hard link is the publish step.  If the durability sync afterwards fails,
    only the inode created by this invocation is removed; a raced replacement is
    never unlinked.
    """
    path = _canonical_absolute_path(raw_path, "output", allow_missing_leaf=True)
    try:
        existing = path.lstat()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise ReconciliationError(f"cannot stat output: {exc}") from exc
    if existing is not None:
        raise ReconciliationError("output collision")

    try:
        payload = canonical_bytes(document)
    except Exception as exc:
        raise ReconciliationError("output document cannot be canonicalized") from exc

    temporary: str | None = None
    temporary_identity: tuple[int, int] | None = None
    linked = False
    committed = False
    descriptor: int | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        try:
            os.close(descriptor)
        finally:
            descriptor = None

        temp_info = os.stat(temporary)
        temporary_identity = temp_info.st_dev, temp_info.st_ino
        os.link(temporary, path)
        linked = True
        _fsync_directory(path.parent)
        committed = True
    except FileExistsError as exc:
        raise ReconciliationError("output collision") from exc
    except OSError as exc:
        if linked and temporary_identity is not None:
            try:
                published = path.stat()
                if (published.st_dev, published.st_ino) == temporary_identity:
                    os.unlink(path)
                    _fsync_directory(path.parent)
            except OSError:
                # Preserve a raced replacement or an uncertain cleanup target.
                pass
        raise ReconciliationError(f"cannot atomically publish output: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError as exc:
                # Once the linked receipt and its parent are durable, that is the
                # commit point.  A failed best-effort removal can leave only the
                # private temp; reporting failure here would make callers roll
                # back a restore while retaining a valid receipt.
                if not committed:
                    raise ReconciliationError(f"cannot clean private output temp: {exc}") from exc


def validate_slice_a_documents(
    *,
    source_inventory_path: str | os.PathLike[str],
    cohort_inventory_path: str | os.PathLike[str],
    cohort_manifest_path: str | os.PathLike[str],
    backup_manifest_path: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str] | None = None,
    restore_path: str | os.PathLike[str] | None = None,
    output_path: str | os.PathLike[str] | None = None,
) -> tuple[SourceInventoryV1, CohortInventoryV1, CohortManifestBindingV1, BackupManifestV1]:
    """Validate every Slice A artifact without performing a restore or recall."""
    source, source_digest = load_source_inventory_document(source_inventory_path)
    cohort, cohort_digest = load_cohort_inventory_document(cohort_inventory_path)
    validate_inventory_conservation(source, cohort)
    manifest = parse_and_bind_cohort_manifest(cohort_manifest_path, cohort)
    backup, _ = load_backup_manifest_document(
        backup_manifest_path,
        source_inventory_digest=source_digest,
        cohort_inventory_digest=cohort_digest,
        cohort_manifest_digest=manifest.canonical_file_digest,
    )
    verify_backup_inventory(
        backup,
        source,
        workspace_root=workspace_root,
        restore_path=restore_path,
        input_paths=(
            source_inventory_path,
            cohort_inventory_path,
            cohort_manifest_path,
            backup_manifest_path,
        ),
        output_path=output_path,
    )
    return source, cohort, manifest, backup


def conserve_documents(
    *,
    source_inventory_path: str | os.PathLike[str],
    cohort_inventory_path: str | os.PathLike[str],
    cohort_manifest_path: str | os.PathLike[str],
    backup_manifest_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    workspace_root: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    """Validate Slice A evidence, conserve it, and publish no live capability.

    The only mutation is a collision-safe receipt write.  No restore, source
    read, recall acquisition, or import is part of this command.
    """
    source, source_digest = load_source_inventory_document(source_inventory_path)
    cohort, cohort_digest = load_cohort_inventory_document(cohort_inventory_path)
    manifest = parse_and_bind_cohort_manifest(cohort_manifest_path, cohort)
    backup, backup_digest = load_backup_manifest_document(
        backup_manifest_path,
        source_inventory_digest=source_digest,
        cohort_inventory_digest=cohort_digest,
        cohort_manifest_digest=manifest.canonical_file_digest,
    )
    verify_backup_inventory(
        backup,
        source,
        workspace_root=workspace_root,
        input_paths=(
            source_inventory_path,
            cohort_inventory_path,
            cohort_manifest_path,
            backup_manifest_path,
        ),
        output_path=output_path,
    )
    result, aggregate_digests = reconcile_inventory_conservation(source, cohort)
    request = ReconciliationRequestV1(
        RECONCILIATION_VERIFIER_V1,
        source_digest,
        cohort_digest,
        manifest.canonical_file_digest,
        backup_digest,
    )
    receipt = reconciliation_receipt_mapping(request, result, aggregate_digests)
    publish_canonical_json_atomic(output_path, receipt)
    return receipt


def _require_new_isolated_restore_target(
    raw_path: str | os.PathLike[str],
    *,
    source_root: Path,
    backup_root: Path,
    protected_paths: Iterable[str | os.PathLike[str]],
) -> Path:
    target = _canonical_absolute_path(raw_path, "restore_target", allow_missing_leaf=True)
    try:
        target.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ReconciliationError(f"cannot stat restore_target: {exc}") from exc
    else:
        raise ReconciliationError("restore_target must not already exist")
    for label, other in (("source_root", source_root), ("backup_root", backup_root)):
        if _path_is_related(target, other):
            raise ReconciliationError(f"restore_target must be isolated from {label}")
    for index, raw_protected in enumerate(protected_paths):
        protected = _canonical_absolute_path(
            raw_protected, f"protected_paths[{index}]", allow_missing_leaf=True
        )
        if _path_is_related(target, protected):
            raise ReconciliationError("restore_target must be isolated from inputs and outputs")
    return target


def _assert_new_receipt_path(raw_path: str | os.PathLike[str]) -> None:
    path = _canonical_absolute_path(raw_path, "receipt", allow_missing_leaf=True)
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReconciliationError(f"cannot stat receipt: {exc}") from exc
    raise ReconciliationError("receipt collision")


def _remove_created_restore_state(created: list[tuple[Path, tuple[int, int], bool]]) -> None:
    """Remove only known invocation-created inodes, in child-before-parent order."""
    for path, identity, is_directory in reversed(created):
        try:
            info = path.lstat()
            if (info.st_dev, info.st_ino) != identity:
                continue
            if is_directory:
                path.rmdir()
            else:
                path.unlink()
        except FileNotFoundError:
            continue
        except OSError:
            # A raced or externally-modified pathname is never ours to remove.
            continue


def _mkdir_created(path: Path, created: list[tuple[Path, tuple[int, int], bool]]) -> None:
    try:
        path.mkdir(mode=0o700)
        info = path.lstat()
    except OSError as exc:
        raise ReconciliationError(f"cannot create isolated restore directory: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ReconciliationError("created restore directory is not a directory")
    created.append((path, (info.st_dev, info.st_ino), True))
    _fsync_directory(path.parent)


def _copy_verified_backup_file(
    source: Path,
    destination: Path,
    expected: BackupFileV1,
    created: list[tuple[Path, tuple[int, int], bool]],
) -> None:
    before = _require_regular_file(source, f"backup file {expected.relative_path}")
    if before.st_nlink != 1:
        raise ReconciliationError("backup file must not be hard-linked during restore")
    read_fd: int | None = None
    write_fd: int | None = None
    try:
        read_fd = _open_readonly_no_follow(source, f"backup file {expected.relative_path}")
        opened = os.fstat(read_fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or _stat_identity(opened) != _stat_identity(before):
            raise ReconciliationError("backup file changed before restore copy")
        write_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        output = os.fstat(write_fd)
        created.append((destination, (output.st_dev, output.st_ino), False))
        digest = sha256()
        total = 0
        while True:
            chunk = os.read(read_fd, _READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            _write_all(write_fd, chunk)
        os.fsync(write_fd)
        if total != int(expected.size) or digest.hexdigest() != expected.sha256:
            raise ReconciliationError("backup file changed or did not match manifest during restore")
        after = _require_regular_file(source, f"backup file {expected.relative_path}")
        if after.st_nlink != 1 or _stat_identity(after) != _stat_identity(before):
            raise ReconciliationError("backup file changed during restore copy")
    except OSError as exc:
        raise ReconciliationError(f"cannot restore verified backup file: {exc}") from exc
    finally:
        if write_fd is not None:
            os.close(write_fd)
        if read_fd is not None:
            os.close(read_fd)


def restore_verified_backup_inventory(
    backup: BackupManifestV1,
    files: tuple[BackupFileV1, ...],
    restore_target: Path,
) -> tuple[str, list[tuple[Path, tuple[int, int], bool]]]:
    """Restore a pre-verified backup to a new directory and hash-bind the result."""
    created: list[tuple[Path, tuple[int, int], bool]] = []
    try:
        _mkdir_created(restore_target, created)
        known_dirs: set[Path] = {restore_target}
        for entry in files:
            relative = Path(entry.relative_path)
            current = restore_target
            for component in relative.parts[:-1]:
                current /= component
                if current not in known_dirs:
                    _mkdir_created(current, created)
                    known_dirs.add(current)
            destination = restore_target / relative
            _copy_verified_backup_file(backup.backup_root / relative, destination, entry, created)
            _fsync_directory(destination.parent)
        # The source tree is re-inventoried after copying so a mid-copy change fails.
        actual = _scan_backup_tree(backup.backup_root)
        if actual != files:
            raise ReconciliationError("backup inventory changed during restore")
        restored = _scan_backup_tree(restore_target)
        if restored != files:
            raise ReconciliationError("restored inventory does not exactly match verified backup")
        _fsync_directory(restore_target)
        return sha256(canonical_bytes({
            "restore_target_identity_sha256": sha256(canonical_bytes({"absolute_path": str(restore_target)})).hexdigest(),
            "files": [entry.to_mapping() for entry in restored],
        })).hexdigest(), created
    except Exception:
        _remove_created_restore_state(created)
        raise


def _load_recall_sample(path: str | os.PathLike[str], workspace_ref: str) -> tuple[tuple[RecallSnapshotRequestV2, ...], str]:
    data, file_digest = _load_canonical_object(path, "recall sample")
    values = _strict_mapping(data, {"recall_sample_version", "requests"}, "recall sample")
    if values["recall_sample_version"] != RECALL_SAMPLE_V1 or not isinstance(values["requests"], list) or not values["requests"]:
        raise ReconciliationError("recall sample must contain a non-empty supported request list")
    requests: list[RecallSnapshotRequestV2] = []
    for index, item in enumerate(values["requests"]):
        try:
            request = RecallSnapshotRequestV2.from_mapping(item)
        except Exception as exc:
            raise ReconciliationError(f"invalid recall sample request {index}: {exc}") from exc
        if request.workspace_ref != workspace_ref:
            raise ReconciliationError("recall sample request workspace_ref must match cohort manifest")
        requests.append(request)
    encoded = tuple(canonical_bytes(request.to_mapping()) for request in requests)
    if encoded != tuple(sorted(encoded)) or len(set(encoded)) != len(encoded):
        raise ReconciliationError("recall sample requests must be canonically ordered and unique")
    return tuple(requests), file_digest


def _validated_snapshot_for_request(
    acquisition: Any,
    request: RecallSnapshotRequestV2,
    authority: RecallTrustAuthorityV2,
):
    if not isinstance(acquisition, ValidatedRecallSnapshotAcquisitionV2):
        raise ReconciliationError("recall port returned a non-validated acquisition")
    if acquisition.request != request:
        raise ReconciliationError("recall acquisition request mismatch")
    try:
        snapshot = validate_recall_snapshot_acquisition(request, acquisition.snapshot, authority)
    except Exception as exc:
        raise ReconciliationError(f"recall acquisition failed independent validation: {exc}") from exc
    if not snapshot.candidates or len(snapshot.citations) != len(snapshot.candidates):
        raise ReconciliationError("recall snapshot must display cited candidates")
    return snapshot


def deterministic_recall_digest(
    requests: tuple[RecallSnapshotRequestV2, ...],
    *,
    trust_authority: RecallTrustAuthorityV2,
    recall_snapshots: AtomicRecallSnapshotPort,
) -> str:
    if not isinstance(trust_authority, RecallTrustAuthorityV2):
        raise ReconciliationError("a minted RecallTrustAuthorityV2 is required")
    if not isinstance(recall_snapshots, AtomicRecallSnapshotPort):
        raise ReconciliationError("an AtomicRecallSnapshotPort is required")
    rows: list[dict[str, Any]] = []
    for request in requests:
        first = _validated_snapshot_for_request(
            recall_snapshots.acquire_recall_snapshot(request), request, trust_authority
        )
        second = _validated_snapshot_for_request(
            recall_snapshots.acquire_recall_snapshot(request), request, trust_authority
        )
        if first.to_mapping() != second.to_mapping() or first.snapshot_digest != second.snapshot_digest:
            raise ReconciliationError("recall port returned alternating snapshots")
        rows.append({
            "request_digest": request.request_digest,
            "snapshot_digest": first.snapshot_digest,
            "candidates": [
                {"candidate_ref": candidate.candidate_ref, "revision_ref": candidate.revision_ref, "content_digest": candidate.content_digest}
                for candidate in first.candidates
            ],
            "citations": [
                {"candidate_ref": citation.candidate_ref, "citation_digest": citation.citation_digest, "evidence_digest": citation.evidence.evidence_digest}
                for citation in first.citations
            ],
        })
    return sha256(canonical_bytes({"requests": rows})).hexdigest()


def _require_minted_trust_authority(authority: Any) -> RecallTrustAuthorityV2:
    """Reject nominally forged wrappers before restore; Core owns actual trust checks."""
    if not isinstance(authority, RecallTrustAuthorityV2):
        raise ReconciliationError("a minted RecallTrustAuthorityV2 is required")
    try:
        authority._now()
    except Exception as exc:
        raise ReconciliationError("a usable minted RecallTrustAuthorityV2 is required") from exc
    return authority


def _run_authorized_verify(args: argparse.Namespace, *, trust_authority: RecallTrustAuthorityV2, recall_snapshots: AtomicRecallSnapshotPort) -> int:
    input_paths = (args.source_inventory, args.cohort_inventory, args.cohort_manifest, args.backup_manifest)
    source, source_digest = load_source_inventory_document(args.source_inventory)
    cohort, cohort_digest = load_cohort_inventory_document(args.cohort_inventory)
    manifest = parse_and_bind_cohort_manifest(args.cohort_manifest, cohort)
    backup, backup_digest = load_backup_manifest_document(args.backup_manifest, source_inventory_digest=source_digest, cohort_inventory_digest=cohort_digest, cohort_manifest_digest=manifest.canonical_file_digest)
    # All offline gates complete before the target is made or the port is called.
    files = verify_backup_inventory(backup, source, restore_path=args.restore_target, input_paths=(*input_paths, args.recall_sample), output_path=args.receipt)
    result, aggregate_digests = reconcile_inventory_conservation(source, cohort)
    if result.result != "PASS" or result.no_import or result.findings:
        raise ReconciliationError("conservation is quarantined or non-import")
    _assert_new_receipt_path(args.receipt)
    target = _require_new_isolated_restore_target(args.restore_target, source_root=source.source_root, backup_root=backup.backup_root, protected_paths=(*input_paths, args.recall_sample, args.receipt))
    requests, sample_digest = _load_recall_sample(args.recall_sample, manifest.manifest.workspace_ref)
    # Validate all trusted dependencies before any restore mutation.
    authority = _require_minted_trust_authority(trust_authority)
    if not isinstance(recall_snapshots, AtomicRecallSnapshotPort):
        raise ReconciliationError("authorized verify requires minted authority and AtomicRecallSnapshotPort")
    created: list[tuple[Path, tuple[int, int], bool]] = []
    try:
        restore_digest, created = restore_verified_backup_inventory(backup, files, target)
        recall_digest = deterministic_recall_digest(requests, trust_authority=authority, recall_snapshots=recall_snapshots)
        request = ReconciliationRequestV1(RECONCILIATION_VERIFIER_V1, source_digest, cohort_digest, manifest.canonical_file_digest, backup_digest)
        receipt = reconciliation_receipt_mapping(request, result, aggregate_digests, verification_mode=RESTORE_RECALL_VERIFIED, recall_sample_digest=sample_digest, isolated_restore_target_digest=restore_digest, deterministic_recall_digest=recall_digest)
        publish_canonical_json_atomic(args.receipt, receipt)
    except Exception:
        _remove_created_restore_state(created)
        raise
    return 0


def _cmd_verify(_: argparse.Namespace) -> int:
    print(
        "FAIL: DEPLOYMENT_AUTHORITY_ABSENT",
        file=sys.stderr,
    )
    return 2


def _cmd_conserve(args: argparse.Namespace) -> int:
    receipt = conserve_documents(
        source_inventory_path=args.source_inventory,
        cohort_inventory_path=args.cohort_inventory,
        cohort_manifest_path=args.cohort_manifest,
        backup_manifest_path=args.backup_manifest,
        output_path=args.output,
        workspace_root=args.workspace_root,
    )
    result = receipt["result"]
    if result["result"] != "PASS" or result["no_import"]:
        # Preserve the atomically published, hash-only quarantine receipt for
        # audit while making the public process boundary unambiguously fail.
        print("FAIL: CONSERVATION_REJECTED", file=sys.stderr)
        return 2
    # The result is intentionally a digest/count-only receipt, never an import grant.
    print(json.dumps({"result": receipt["result"]["result"], "output": args.output}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline Second Brain reconciliation validators."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    verify = subcommands.add_parser(
        "verify",
        help="authority-injected restore and deterministic recall verification",
    )
    verify.add_argument("--source-inventory", required=True)
    verify.add_argument("--cohort-inventory", required=True)
    verify.add_argument("--cohort-manifest", required=True)
    verify.add_argument("--backup-manifest", required=True)
    verify.add_argument("--restore-target", required=True)
    verify.add_argument("--recall-sample", required=True)
    verify.add_argument("--receipt", required=True)
    verify.set_defaults(handler=_cmd_verify)
    conserve = subcommands.add_parser(
        "conserve",
        help="validate Slice A artifacts and atomically publish a non-live reconciliation receipt",
    )
    conserve.add_argument("--source-inventory", required=True)
    conserve.add_argument("--cohort-inventory", required=True)
    conserve.add_argument("--cohort-manifest", required=True)
    conserve.add_argument("--backup-manifest", required=True)
    conserve.add_argument("--output", required=True)
    conserve.add_argument("--workspace-root")
    conserve.set_defaults(handler=_cmd_conserve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return args.handler(args)
    except (ReconciliationError, ValueError):
        # Validator and adapter messages can carry paths, native identifiers,
        # or details copied from untrusted evidence.  Public CLI diagnostics
        # must remain a stable, opaque contract.
        print("FAIL: RECONCILIATION_REJECTED", file=sys.stderr)
        return 2
    except Exception:
        print("FAIL: RECONCILIATION_INTERNAL_REJECTED", file=sys.stderr)
        return 2


def run_with_authority(
    argv: list[str] | None,
    *,
    trust_authority: RecallTrustAuthorityV2,
    recall_snapshots: AtomicRecallSnapshotPort,
) -> int:
    """Internal composition seam; the public CLI never receives trust material."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command != "verify":
            raise ReconciliationError("authority composition only permits verify")
        return _run_authorized_verify(
            args, trust_authority=trust_authority, recall_snapshots=recall_snapshots
        )
    except SystemExit as exc:
        # argparse owns help/usage rendering, while the composition seam owns its rc.
        return int(exc.code) if isinstance(exc.code, int) else 2
    except Exception as exc:
        # Adapter failures can contain raw payloads, paths, or secrets.  The
        # authority seam is deliberately opaque at this boundary.
        print("FAIL: AUTHORIZED_VERIFY_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
