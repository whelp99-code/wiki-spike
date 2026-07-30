"""DB-03 migration-source evidence: the bundle a per-source GO must bind.

DB-03 resolves one migration source at a time, and each `GO` demands five
independent things: a read-only export fixture that cannot mutate the source, a
pinned schema/version with identity and revision mapping, watermark evidence
covering overlap and restart, deletion and history samples that distinguish
tombstones from retained history from unavailable history *without inference*,
and signed evidence digests.

`MigrationSourceEvidenceV1` is exactly that bundle, and its `evidence_digest` is
the value a DB-03 record's `evidence_digest` takes.

The unified-db inventory stopped at `STOP_PENDING_IMMUTABLE_SNAPSHOT_AND_DIFF`
because an active source run was observed, so no immutable package could be
derived. That is why every component here binds one `MigrationSnapshotV1` whose
before/after source-root digests must be equal: a snapshot taken while writers
were still running is not evidence, and this module refuses to represent one.

Nothing here attests. Owner and Security attestations, the snapshot itself, and
the zero-write proof come from human processes; the contracts take their digests
and refuse to invent them.

Evidence is body-free by construction: every field is a digest, a canonical
decimal count, a closed enumeration, or a bounded identifier token. The
identifier bound is an accident guard, not a security boundary. It stops a
record body from leaking into a metadata field, because real bodies carry
spaces, punctuation or non-ASCII and are refused; it does not stop an operator
who deliberately hyphen-joins an excerpt into 128 identifier characters. The
defence against that is review of the operator's own evidence, not this regex,
and it is stated here so no later reader mistakes the check for more than it is.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .errors import InvalidContractValue
from .second_brain_contracts import ResolvedScopeV1
from .second_brain_ledger_contracts import canonical_ledger_digest, canonical_ledger_instant

MIGRATION_SNAPSHOT_V1 = "second-brain-migration-snapshot-v1"
MIGRATION_EXPORT_PROFILE_V1 = "second-brain-migration-export-profile-v1"
MIGRATION_UNIQUENESS_DIFF_V1 = "second-brain-migration-uniqueness-diff-v1"
MIGRATION_HISTORY_TREATMENT_V1 = "second-brain-migration-history-treatment-v1"
MIGRATION_SOURCE_EVIDENCE_V1 = "second-brain-migration-source-evidence-v1"

#: DB-03's canonical scope inventory. Each name is independently resolved.
MIGRATION_SOURCE_NAMES = ("legacy Mem0/RAG", "me-wiki", "unified-db")

#: Export methods that cannot mutate the source by construction.
READ_ONLY_EXPORT_METHODS = (
    "read-only-transaction",
    "read-only-file-copy",
    "read-only-api-export",
)

#: How the source represents a revision of the same native identity.
REVISION_SEMANTICS = ("explicit-revision-column", "content-hash-revision")

#: Cursor restart behaviour that is sufficient for reconciliation. A source that
#: cannot state which one it has has not produced watermark evidence.
OVERLAP_BEHAVIORS = ("replay-overlap", "exactly-once-cursor")

#: How the source spells deletion. "absent" is honest and common; it forbids
#: claiming tombstone samples rather than permitting inferred ones.
TOMBSTONE_REPRESENTATIONS = (
    "explicit-tombstone-column",
    "explicit-tombstone-event",
    "absent",
)

#: What history the source can prove it retains.
HISTORY_AVAILABILITIES = ("complete", "partial-with-proof", "unavailable")

_HEX64 = frozenset("0123456789abcdef")
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}")
_DECIMAL = re.compile(r"0|[1-9][0-9]*")
_MAX_COUNT_DIGITS = 20


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(ch not in _HEX64 for ch in value):
        raise InvalidContractValue(f"{field} must be a lowercase sha256 hex digest")
    return value


def _ref(value: Any, field: str, prefix: str) -> str:
    """A prefixed opaque identity, restricted to identifier characters.

    The charset is not decoration: without it a 256-character ref is a place to
    park a filesystem path or a record excerpt, which this module's body-free
    promise forbids.
    """
    if not isinstance(value, str) or not value.startswith(prefix + ":"):
        raise InvalidContractValue(f"{field} must be a {prefix}: ref")
    if _TOKEN.fullmatch(value[len(prefix) + 1:]) is None:
        raise InvalidContractValue(
            f"{field} must be {prefix}: followed by at most 128 identifier characters"
        )
    return value


def _strict(data: Any, fields: set[str]) -> dict[str, Any]:
    if not isinstance(data, Mapping) or any(not isinstance(k, str) for k in data):
        raise InvalidContractValue("contract must be an object with string keys")
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown or missing:
        raise InvalidContractValue(
            f"contract fields invalid unknown={sorted(unknown)} missing={sorted(missing)}"
        )
    return {key: data[key] for key in fields}


def _closed(value: Any, allowed: Sequence[str], field: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise InvalidContractValue(f"{field} must be one of {list(allowed)}")
    return value


def _true(value: Any, field: str) -> bool:
    if value is not True:
        raise InvalidContractValue(f"{field} must be true")
    return True


def _false(value: Any, field: str) -> bool:
    if value is not False:
        raise InvalidContractValue(f"{field} must be false")
    return False


def _text(value: Any, field: str) -> str:
    """A short opaque token: a schema version, a column name, a cursor name.

    Bounded and charset-restricted so a record body, an address or a path cannot
    leak in by accident: real bodies carry spaces, punctuation or non-ASCII. The
    module docstring explains why this is an accident guard, not a boundary
    against an operator who deliberately encodes an excerpt as identifiers.
    """
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise InvalidContractValue(
            f"{field} must be at most 128 identifier characters (A-Z a-z 0-9 . _ + / -)"
        )
    return value


def _count(value: Any, field: str) -> str:
    """Canonical decimal string, the spelling this repository's ledger counters use.

    ``str.isdigit`` is deliberately not used: it is true for non-ASCII digit
    codepoints, which would give one numeric value two digest-bound encodings,
    and true for characters ``int`` cannot parse at all. The length bound keeps
    ``int`` below its own digit limit so a count can never raise out of a
    contract that must fail closed by type.
    """
    if not isinstance(value, str) or len(value) > _MAX_COUNT_DIGITS or _DECIMAL.fullmatch(value) is None:
        raise InvalidContractValue(
            f"{field} must be a canonical decimal string of at most {_MAX_COUNT_DIGITS} digits"
        )
    return value


def _positive_count(value: Any, field: str) -> str:
    value = _count(value, field)
    if value == "0":
        raise InvalidContractValue(f"{field} must be greater than zero")
    return value


def _digest_tuple(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise InvalidContractValue(f"{field} must be an array of digests")
    items = tuple(_digest(item, field) for item in value)
    if len(set(items)) != len(items):
        raise InvalidContractValue(f"{field} must be unique")
    return items


def _names(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty array")
    items = tuple(_text(item, field) for item in value)
    if len(set(items)) != len(items):
        raise InvalidContractValue(f"{field} must be unique")
    return items


def _source_name(value: Any, field: str = "source_name") -> str:
    return _closed(value, MIGRATION_SOURCE_NAMES, field)


def _as_utc(canonical: str) -> datetime:
    """Order two already-canonical instants by real time, not by spelling.

    Canonical UTC keeps optional fractional seconds, and "00:00:00.5Z" sorts
    lexicographically before "00:00:00Z" while being the later instant.
    """
    return datetime.fromisoformat(canonical[:-1] + "+00:00").astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class MigrationSnapshotV1:
    """An owner-produced immutable snapshot plus its zero-write proof.

    The zero-write proof is the equality of the source-root digest observed
    before and after the export window. Unequal roots mean writers were not
    quiesced, and `active_run_observed` must be false for the same reason: the
    unified-db inventory refused to derive a package from a live instance.
    """

    FIELDS = {
        "snapshot_version", "source_name", "snapshot_ref", "writers_quiesced_at",
        "snapshot_taken_at", "source_root_digest_before", "source_root_digest_after",
        "active_run_observed", "snapshot_package_digest", "owner_key_ref",
        "owner_attestation_digest", "snapshot_binding_digest",
    }
    snapshot_version: str
    source_name: str
    snapshot_ref: str
    writers_quiesced_at: str
    snapshot_taken_at: str
    source_root_digest_before: str
    source_root_digest_after: str
    active_run_observed: bool
    snapshot_package_digest: str
    owner_key_ref: str
    owner_attestation_digest: str
    snapshot_binding_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationSnapshotV1":
        values = _strict(data, cls.FIELDS)
        if values["snapshot_version"] != MIGRATION_SNAPSHOT_V1:
            raise InvalidContractValue("unsupported migration snapshot version")
        quiesced = canonical_ledger_instant(values["writers_quiesced_at"], "writers_quiesced_at")
        taken = canonical_ledger_instant(values["snapshot_taken_at"], "snapshot_taken_at")
        if _as_utc(taken) < _as_utc(quiesced):
            raise InvalidContractValue("snapshot_taken_at precedes writers_quiesced_at")
        before = _digest(values["source_root_digest_before"], "source_root_digest_before")
        after = _digest(values["source_root_digest_after"], "source_root_digest_after")
        if before != after:
            raise InvalidContractValue(
                "source root changed across the export window; writers were not quiesced "
                "and the snapshot is not a zero-write proof"
            )
        body = {
            "snapshot_version": MIGRATION_SNAPSHOT_V1,
            "source_name": _source_name(values["source_name"]),
            "snapshot_ref": _ref(values["snapshot_ref"], "snapshot_ref", "snapshot"),
            "writers_quiesced_at": quiesced,
            "snapshot_taken_at": taken,
            "source_root_digest_before": before,
            "source_root_digest_after": after,
            "active_run_observed": _false(values["active_run_observed"], "active_run_observed"),
            "snapshot_package_digest": _digest(
                values["snapshot_package_digest"], "snapshot_package_digest"
            ),
            "owner_key_ref": _ref(values["owner_key_ref"], "owner_key_ref", "key"),
            "owner_attestation_digest": _digest(
                values["owner_attestation_digest"], "owner_attestation_digest"
            ),
        }
        digest = _digest(values["snapshot_binding_digest"], "snapshot_binding_digest")
        if digest != canonical_ledger_digest("migration-snapshot-v1", body):
            raise InvalidContractValue("snapshot_binding_digest does not bind its body")
        return cls(**body, snapshot_binding_digest=digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "snapshot_version": self.snapshot_version,
            "source_name": self.source_name,
            "snapshot_ref": self.snapshot_ref,
            "writers_quiesced_at": self.writers_quiesced_at,
            "snapshot_taken_at": self.snapshot_taken_at,
            "source_root_digest_before": self.source_root_digest_before,
            "source_root_digest_after": self.source_root_digest_after,
            "active_run_observed": self.active_run_observed,
            "snapshot_package_digest": self.snapshot_package_digest,
            "owner_key_ref": self.owner_key_ref,
            "owner_attestation_digest": self.owner_attestation_digest,
            "snapshot_binding_digest": self.snapshot_binding_digest,
        }


@dataclass(frozen=True, slots=True)
class MigrationExportProfileV1:
    """The read-only export method, pinned schema, and reconciliation semantics.

    DB-03's strongest requirement is a fixture that *cannot* mutate the source, so
    `write_capability_absent` is not left as a bare assertion: it is carried
    alongside `write_capability_probe_digest`, the evidence that the export
    credential was actually exercised against a write and refused. A read-only
    query run under a credential that still holds write capability is not a
    read-only export, and a claim with no probe behind it is not evidence.
    """

    FIELDS = {
        "profile_version", "source_name", "snapshot_binding_digest", "export_method",
        "write_capability_absent", "write_capability_probe_digest",
        "source_mutation_attempted", "schema_version",
        "schema_digest", "native_identity_fields", "identity_mapping_digest",
        "revision_semantics", "revision_mapping_digest", "watermark_cursor_field",
        "overlap_behavior", "restart_evidence_digest", "page_size_limit",
        "retention_days", "source_fixture_digest", "profile_digest",
    }
    profile_version: str
    source_name: str
    snapshot_binding_digest: str
    export_method: str
    write_capability_absent: bool
    write_capability_probe_digest: str
    source_mutation_attempted: bool
    schema_version: str
    schema_digest: str
    native_identity_fields: tuple[str, ...]
    identity_mapping_digest: str
    revision_semantics: str
    revision_mapping_digest: str
    watermark_cursor_field: str
    overlap_behavior: str
    restart_evidence_digest: str
    page_size_limit: str
    retention_days: str
    source_fixture_digest: str
    profile_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationExportProfileV1":
        values = _strict(data, cls.FIELDS)
        if values["profile_version"] != MIGRATION_EXPORT_PROFILE_V1:
            raise InvalidContractValue("unsupported migration export profile version")
        body = {
            "profile_version": MIGRATION_EXPORT_PROFILE_V1,
            "source_name": _source_name(values["source_name"]),
            "snapshot_binding_digest": _digest(
                values["snapshot_binding_digest"], "snapshot_binding_digest"
            ),
            "export_method": _closed(
                values["export_method"], READ_ONLY_EXPORT_METHODS, "export_method"
            ),
            "write_capability_absent": _true(
                values["write_capability_absent"], "write_capability_absent"
            ),
            "write_capability_probe_digest": _digest(
                values["write_capability_probe_digest"], "write_capability_probe_digest"
            ),
            "source_mutation_attempted": _false(
                values["source_mutation_attempted"], "source_mutation_attempted"
            ),
            "schema_version": _text(values["schema_version"], "schema_version"),
            "schema_digest": _digest(values["schema_digest"], "schema_digest"),
            "native_identity_fields": list(
                _names(values["native_identity_fields"], "native_identity_fields")
            ),
            "identity_mapping_digest": _digest(
                values["identity_mapping_digest"], "identity_mapping_digest"
            ),
            "revision_semantics": _closed(
                values["revision_semantics"], REVISION_SEMANTICS, "revision_semantics"
            ),
            "revision_mapping_digest": _digest(
                values["revision_mapping_digest"], "revision_mapping_digest"
            ),
            "watermark_cursor_field": _text(
                values["watermark_cursor_field"], "watermark_cursor_field"
            ),
            "overlap_behavior": _closed(
                values["overlap_behavior"], OVERLAP_BEHAVIORS, "overlap_behavior"
            ),
            "restart_evidence_digest": _digest(
                values["restart_evidence_digest"], "restart_evidence_digest"
            ),
            "page_size_limit": _positive_count(values["page_size_limit"], "page_size_limit"),
            "retention_days": _count(values["retention_days"], "retention_days"),
            "source_fixture_digest": _digest(
                values["source_fixture_digest"], "source_fixture_digest"
            ),
        }
        evidence_digests = [
            body[field] for field in (
                "schema_digest", "identity_mapping_digest", "revision_mapping_digest",
                "restart_evidence_digest", "write_capability_probe_digest",
                "source_fixture_digest",
            )
        ]
        if len(set(evidence_digests)) != len(evidence_digests):
            raise InvalidContractValue(
                "schema, identity mapping, revision mapping, restart, write-capability probe "
                "and fixture evidence must be six distinct documents"
            )
        digest = _digest(values["profile_digest"], "profile_digest")
        if digest != canonical_ledger_digest("migration-export-profile-v1", body):
            raise InvalidContractValue("profile_digest does not bind its body")
        return cls(
            **{**body, "native_identity_fields": tuple(body["native_identity_fields"])},
            profile_digest=digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "profile_version": self.profile_version,
            "source_name": self.source_name,
            "snapshot_binding_digest": self.snapshot_binding_digest,
            "export_method": self.export_method,
            "write_capability_absent": self.write_capability_absent,
            "write_capability_probe_digest": self.write_capability_probe_digest,
            "source_mutation_attempted": self.source_mutation_attempted,
            "schema_version": self.schema_version,
            "schema_digest": self.schema_digest,
            "native_identity_fields": list(self.native_identity_fields),
            "identity_mapping_digest": self.identity_mapping_digest,
            "revision_semantics": self.revision_semantics,
            "revision_mapping_digest": self.revision_mapping_digest,
            "watermark_cursor_field": self.watermark_cursor_field,
            "overlap_behavior": self.overlap_behavior,
            "restart_evidence_digest": self.restart_evidence_digest,
            "page_size_limit": self.page_size_limit,
            "retention_days": self.retention_days,
            "source_fixture_digest": self.source_fixture_digest,
            "profile_digest": self.profile_digest,
        }


@dataclass(frozen=True, slots=True)
class MigrationUniquenessDiffV1:
    """Body-free per-source uniqueness diff against the supported canonical sources.

    The unified-db inventory left `candidateUnique` unresolved because uniqueness
    had never been proven. This is the artifact that resolves it: candidate item
    digests minus the canonical corpus, counted and enumerated as digests only.
    """

    FIELDS = {
        "diff_version", "source_name", "snapshot_binding_digest", "canonical_corpus_digest",
        "comparison_method", "candidate_item_count", "duplicate_item_count",
        "unique_item_count", "unique_item_digests", "diff_digest",
    }
    diff_version: str
    source_name: str
    snapshot_binding_digest: str
    canonical_corpus_digest: str
    comparison_method: str
    candidate_item_count: str
    duplicate_item_count: str
    unique_item_count: str
    unique_item_digests: tuple[str, ...]
    diff_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationUniquenessDiffV1":
        values = _strict(data, cls.FIELDS)
        if values["diff_version"] != MIGRATION_UNIQUENESS_DIFF_V1:
            raise InvalidContractValue("unsupported migration uniqueness diff version")
        unique = _digest_tuple(values["unique_item_digests"], "unique_item_digests")
        candidate_count = _positive_count(values["candidate_item_count"], "candidate_item_count")
        duplicate_count = _count(values["duplicate_item_count"], "duplicate_item_count")
        unique_count = _count(values["unique_item_count"], "unique_item_count")
        if len(unique) != int(unique_count):
            raise InvalidContractValue("unique_item_count does not match unique_item_digests")
        if int(unique_count) + int(duplicate_count) != int(candidate_count):
            raise InvalidContractValue(
                "unique and duplicate counts must partition the candidate count"
            )
        body = {
            "diff_version": MIGRATION_UNIQUENESS_DIFF_V1,
            "source_name": _source_name(values["source_name"]),
            "snapshot_binding_digest": _digest(
                values["snapshot_binding_digest"], "snapshot_binding_digest"
            ),
            "canonical_corpus_digest": _digest(
                values["canonical_corpus_digest"], "canonical_corpus_digest"
            ),
            "comparison_method": _closed(
                values["comparison_method"],
                ("content-digest-set-difference",),
                "comparison_method",
            ),
            "candidate_item_count": candidate_count,
            "duplicate_item_count": duplicate_count,
            "unique_item_count": unique_count,
            "unique_item_digests": list(unique),
        }
        digest = _digest(values["diff_digest"], "diff_digest")
        if digest != canonical_ledger_digest("migration-uniqueness-diff-v1", body):
            raise InvalidContractValue("diff_digest does not bind its body")
        return cls(
            **{**body, "unique_item_digests": unique},
            diff_digest=digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "diff_version": self.diff_version,
            "source_name": self.source_name,
            "snapshot_binding_digest": self.snapshot_binding_digest,
            "canonical_corpus_digest": self.canonical_corpus_digest,
            "comparison_method": self.comparison_method,
            "candidate_item_count": self.candidate_item_count,
            "duplicate_item_count": self.duplicate_item_count,
            "unique_item_count": self.unique_item_count,
            "unique_item_digests": list(self.unique_item_digests),
            "diff_digest": self.diff_digest,
        }


@dataclass(frozen=True, slots=True)
class MigrationHistoryTreatmentV1:
    """Deletion and history treatment that distinguishes three states, never infers.

    Absence is not deletion. A source with no tombstone representation cannot
    produce tombstone samples, and history it cannot prove it retained must be
    recorded as unavailable rather than silently treated as deleted.
    """

    FIELDS = {
        "treatment_version", "source_name", "snapshot_binding_digest",
        "tombstone_representation", "history_availability", "absence_is_not_deletion",
        "tombstone_sample_digests", "retained_history_sample_digests",
        "unavailable_history_sample_digests", "treatment_digest",
    }
    treatment_version: str
    source_name: str
    snapshot_binding_digest: str
    tombstone_representation: str
    history_availability: str
    absence_is_not_deletion: bool
    tombstone_sample_digests: tuple[str, ...]
    retained_history_sample_digests: tuple[str, ...]
    unavailable_history_sample_digests: tuple[str, ...]
    treatment_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationHistoryTreatmentV1":
        values = _strict(data, cls.FIELDS)
        if values["treatment_version"] != MIGRATION_HISTORY_TREATMENT_V1:
            raise InvalidContractValue("unsupported migration history treatment version")
        representation = _closed(
            values["tombstone_representation"], TOMBSTONE_REPRESENTATIONS, "tombstone_representation"
        )
        availability = _closed(
            values["history_availability"], HISTORY_AVAILABILITIES, "history_availability"
        )
        tombstones = _digest_tuple(
            values["tombstone_sample_digests"], "tombstone_sample_digests"
        )
        retained = _digest_tuple(
            values["retained_history_sample_digests"], "retained_history_sample_digests"
        )
        unavailable = _digest_tuple(
            values["unavailable_history_sample_digests"],
            "unavailable_history_sample_digests",
        )
        if representation == "absent" and tombstones:
            raise InvalidContractValue(
                "a source with no tombstone representation cannot produce tombstone samples; "
                "absence is not deletion"
            )
        if representation != "absent" and not tombstones:
            raise InvalidContractValue(
                "a declared tombstone representation requires at least one tombstone sample"
            )
        if availability == "unavailable":
            if retained:
                raise InvalidContractValue(
                    "unavailable history cannot also present retained history samples"
                )
            if not unavailable:
                raise InvalidContractValue(
                    "unavailable history requires at least one unavailable sample"
                )
        if availability == "complete":
            if unavailable:
                raise InvalidContractValue(
                    "complete history cannot also present unavailable samples"
                )
            if not retained:
                raise InvalidContractValue(
                    "complete history requires at least one retained history sample"
                )
        if availability == "partial-with-proof" and not (retained and unavailable):
            raise InvalidContractValue(
                "partial history must present both retained and unavailable samples"
            )
        for left, right, label in (
            (tombstones, retained, "tombstone and retained"),
            (tombstones, unavailable, "tombstone and unavailable"),
            (retained, unavailable, "retained and unavailable"),
        ):
            if set(left) & set(right):
                raise InvalidContractValue(
                    f"{label} history samples overlap; one record cannot be in two states"
                )
        body = {
            "treatment_version": MIGRATION_HISTORY_TREATMENT_V1,
            "source_name": _source_name(values["source_name"]),
            "snapshot_binding_digest": _digest(
                values["snapshot_binding_digest"], "snapshot_binding_digest"
            ),
            "tombstone_representation": representation,
            "history_availability": availability,
            "absence_is_not_deletion": _true(
                values["absence_is_not_deletion"], "absence_is_not_deletion"
            ),
            "tombstone_sample_digests": list(tombstones),
            "retained_history_sample_digests": list(retained),
            "unavailable_history_sample_digests": list(unavailable),
        }
        digest = _digest(values["treatment_digest"], "treatment_digest")
        if digest != canonical_ledger_digest("migration-history-treatment-v1", body):
            raise InvalidContractValue("treatment_digest does not bind its body")
        return cls(
            **{
                **body,
                "tombstone_sample_digests": tombstones,
                "retained_history_sample_digests": retained,
                "unavailable_history_sample_digests": unavailable,
            },
            treatment_digest=digest,
        )

    def to_mapping(self) -> dict[str, Any]:
        return {
            "treatment_version": self.treatment_version,
            "source_name": self.source_name,
            "snapshot_binding_digest": self.snapshot_binding_digest,
            "tombstone_representation": self.tombstone_representation,
            "history_availability": self.history_availability,
            "absence_is_not_deletion": self.absence_is_not_deletion,
            "tombstone_sample_digests": list(self.tombstone_sample_digests),
            "retained_history_sample_digests": list(self.retained_history_sample_digests),
            "unavailable_history_sample_digests": list(self.unavailable_history_sample_digests),
            "treatment_digest": self.treatment_digest,
        }


@dataclass(frozen=True, slots=True)
class MigrationSourceEvidenceV1:
    """The per-source bundle whose `evidence_digest` a DB-03 record must bind."""

    FIELDS = {
        "evidence_version", "source_name", "workspace_ref", "snapshot_binding_digest",
        "export_profile_digest", "uniqueness_diff_digest", "history_treatment_digest",
        "owner_attestation_digest", "security_review_digest", "evidence_digest",
    }
    evidence_version: str
    source_name: str
    workspace_ref: str
    snapshot_binding_digest: str
    export_profile_digest: str
    uniqueness_diff_digest: str
    history_treatment_digest: str
    owner_attestation_digest: str
    security_review_digest: str
    evidence_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MigrationSourceEvidenceV1":
        values = _strict(data, cls.FIELDS)
        if values["evidence_version"] != MIGRATION_SOURCE_EVIDENCE_V1:
            raise InvalidContractValue("unsupported migration source evidence version")
        body = {
            "evidence_version": MIGRATION_SOURCE_EVIDENCE_V1,
            "source_name": _source_name(values["source_name"]),
            "workspace_ref": _ref(values["workspace_ref"], "workspace_ref", "workspace"),
            "snapshot_binding_digest": _digest(
                values["snapshot_binding_digest"], "snapshot_binding_digest"
            ),
            "export_profile_digest": _digest(
                values["export_profile_digest"], "export_profile_digest"
            ),
            "uniqueness_diff_digest": _digest(
                values["uniqueness_diff_digest"], "uniqueness_diff_digest"
            ),
            "history_treatment_digest": _digest(
                values["history_treatment_digest"], "history_treatment_digest"
            ),
            "owner_attestation_digest": _digest(
                values["owner_attestation_digest"], "owner_attestation_digest"
            ),
            "security_review_digest": _digest(
                values["security_review_digest"], "security_review_digest"
            ),
        }
        if body["owner_attestation_digest"] == body["security_review_digest"]:
            raise InvalidContractValue(
                "owner attestation and Security review must be separate documents; "
                "DB-03 is owner Migration, approver Security"
            )
        bound_digests = [
            body[field] for field in (
                "snapshot_binding_digest", "export_profile_digest", "uniqueness_diff_digest",
                "history_treatment_digest", "owner_attestation_digest", "security_review_digest",
            )
        ]
        if len(set(bound_digests)) != len(bound_digests):
            raise InvalidContractValue(
                "the four components and the two attestations must be six distinct artifacts"
            )
        digest = _digest(values["evidence_digest"], "evidence_digest")
        if digest != canonical_ledger_digest("migration-source-evidence-v1", body):
            raise InvalidContractValue("evidence_digest does not bind its body")
        return cls(**body, evidence_digest=digest)

    def to_mapping(self) -> dict[str, Any]:
        return {
            "evidence_version": self.evidence_version,
            "source_name": self.source_name,
            "workspace_ref": self.workspace_ref,
            "snapshot_binding_digest": self.snapshot_binding_digest,
            "export_profile_digest": self.export_profile_digest,
            "uniqueness_diff_digest": self.uniqueness_diff_digest,
            "history_treatment_digest": self.history_treatment_digest,
            "owner_attestation_digest": self.owner_attestation_digest,
            "security_review_digest": self.security_review_digest,
            "evidence_digest": self.evidence_digest,
        }


def assert_migration_evidence_bundle_coherent(
    evidence: MigrationSourceEvidenceV1,
    snapshot: MigrationSnapshotV1,
    profile: MigrationExportProfileV1,
    diff: MigrationUniquenessDiffV1,
    treatment: MigrationHistoryTreatmentV1,
) -> None:
    """Fail closed unless all four components describe one source and one snapshot.

    A bundle assembled from components taken across different sources or
    different snapshots proves nothing about either.
    """
    names = {
        snapshot.source_name,
        profile.source_name,
        diff.source_name,
        treatment.source_name,
    }
    if names != {evidence.source_name}:
        raise InvalidContractValue("every evidence component must bind the same source name")
    if snapshot.snapshot_binding_digest != evidence.snapshot_binding_digest:
        raise InvalidContractValue("evidence does not bind the supplied snapshot")
    for component, label in (
        (profile.snapshot_binding_digest, "export profile"),
        (diff.snapshot_binding_digest, "uniqueness diff"),
        (treatment.snapshot_binding_digest, "history treatment"),
    ):
        if component != snapshot.snapshot_binding_digest:
            raise InvalidContractValue(f"{label} binds a different snapshot")
    if profile.profile_digest != evidence.export_profile_digest:
        raise InvalidContractValue("evidence does not bind the supplied export profile")
    if diff.diff_digest != evidence.uniqueness_diff_digest:
        raise InvalidContractValue("evidence does not bind the supplied uniqueness diff")
    if treatment.treatment_digest != evidence.history_treatment_digest:
        raise InvalidContractValue("evidence does not bind the supplied history treatment")
    if snapshot.owner_attestation_digest != evidence.owner_attestation_digest:
        raise InvalidContractValue(
            "evidence owner_attestation_digest must equal the snapshot owner attestation"
        )


def assert_migration_source_registrable(
    evidence: MigrationSourceEvidenceV1,
    scope: ResolvedScopeV1,
) -> None:
    """A migration source is a read-only input, never a serving authority.

    Registration requires a GO in the resolved scope. It also requires that the
    source has not been quietly promoted into a live capture profile, an
    external model route, or an egress destination.
    """
    name = evidence.source_name
    if name in dict(scope.disabled_migration_sources):
        raise InvalidContractValue(f"migration source is NO_GO in the resolved scope: {name}")
    if name not in set(scope.enabled_migration_sources):
        raise InvalidContractValue(
            f"migration source is not enabled by a signed DB-03 GO: {name}"
        )
    for collection, label in (
        (scope.enabled_source_profiles, "live capture source profile"),
        (scope.enabled_external_model_routes, "external model route"),
        (scope.egress_destinations, "egress destination"),
    ):
        if name in set(collection):
            raise InvalidContractValue(
                f"a migration source must never also be a {label}: {name}"
            )


__all__ = [
    "MIGRATION_SNAPSHOT_V1",
    "MIGRATION_EXPORT_PROFILE_V1",
    "MIGRATION_UNIQUENESS_DIFF_V1",
    "MIGRATION_HISTORY_TREATMENT_V1",
    "MIGRATION_SOURCE_EVIDENCE_V1",
    "MIGRATION_SOURCE_NAMES",
    "READ_ONLY_EXPORT_METHODS",
    "REVISION_SEMANTICS",
    "OVERLAP_BEHAVIORS",
    "TOMBSTONE_REPRESENTATIONS",
    "HISTORY_AVAILABILITIES",
    "MigrationSnapshotV1",
    "MigrationExportProfileV1",
    "MigrationUniquenessDiffV1",
    "MigrationHistoryTreatmentV1",
    "MigrationSourceEvidenceV1",
    "assert_migration_evidence_bundle_coherent",
    "assert_migration_source_registrable",
]
