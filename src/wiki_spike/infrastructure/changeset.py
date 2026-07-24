"""Gate 3 change-set contracts for the Encrypted Single-Memory Lifecycle.

Implements ``StateDeltaV1``, ``ExpectedActiveRevisionV1`` projection, and
``EncryptedAcceptedChangeSetV1`` construction per the frozen schemas
``schemas/encrypted-lifecycle/state-delta-v1.schema.json`` and
``schemas/encrypted-lifecycle/encrypted-accepted-changeset-v1.schema.json``.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure only.
"""
from __future__ import annotations

import hashlib
import struct
from typing import Mapping, Sequence

from wiki_spike.memory_core.contracts import canonical_bytes

CONTRACT_VERSION = "wiki-encrypted-accepted-change-set-v1"

_DELTA_ID_PREFIX = b"wiki.state-delta.v1\x00"
_CHANGES_ROOT_PREFIX = b"wiki.changes-root.v1"
_CHANGESET_ID_PREFIX = b"wiki.encrypted-accepted-change-set.v1"

_DELTA_FIELDS = (
    "delta_version",
    "operation",
    "object_kind",
    "object_id",
    "revision_id",
    "expected_active_revision_id",
    "envelope_ref",
    "assertion_id",
    "evidence_edge_id",
    "evidence_fragment_ref",
    "deletion_command_id",
    "scope_digest",
    "reason_code",
)

_EXPECTED_ACTIVE_KEYS = (
    "object_kind",
    "object_id",
    "assertion_id",
    "evidence_edge_id",
    "evidence_fragment_ref",
    "expected_active_revision_id",
)


class ChangeSetError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# StateDeltaV1
# ---------------------------------------------------------------------------


def compute_delta_id(fields: Mapping) -> str:
    """``delta_id = SHA-256(b"wiki.state-delta.v1\\0" || canonical_json(fields except delta_id))``."""
    body = {k: fields[k] for k in _DELTA_FIELDS}
    return hashlib.sha256(_DELTA_ID_PREFIX + canonical_bytes(body)).hexdigest()


def build_state_delta(
    *,
    operation: str,
    object_kind: str,
    object_id: str,
    revision_id: str | None = None,
    expected_active_revision_id: str | None = None,
    envelope_ref: str | None = None,
    assertion_id: str | None = None,
    evidence_edge_id: str | None = None,
    evidence_fragment_ref: str | None = None,
    deletion_command_id: str | None = None,
    scope_digest: str | None = None,
    reason_code: str | None = None,
) -> dict:
    fields = {
        "delta_version": "1",
        "operation": operation,
        "object_kind": object_kind,
        "object_id": object_id,
        "revision_id": revision_id,
        "expected_active_revision_id": expected_active_revision_id,
        "envelope_ref": envelope_ref,
        "assertion_id": assertion_id,
        "evidence_edge_id": evidence_edge_id,
        "evidence_fragment_ref": evidence_fragment_ref,
        "deletion_command_id": deletion_command_id,
        "scope_digest": scope_digest,
        "reason_code": reason_code,
    }
    delta_id = compute_delta_id(fields)
    return {"delta_id": delta_id, **fields}


# ---------------------------------------------------------------------------
# ExpectedActiveRevisionV1 projection
# ---------------------------------------------------------------------------


def extract_expected_active_revision(delta: Mapping) -> dict:
    return {k: delta[k] for k in _EXPECTED_ACTIVE_KEYS}


def _ear_sort_key(ear: Mapping) -> tuple[bytes, bytes]:
    return (ear["object_kind"].encode(), bytes.fromhex(ear["object_id"]))


def project_expected_active_revisions(deltas: Sequence[Mapping]) -> list[dict]:
    """Sorted-unique projection with conflict detection."""
    ears: list[dict] = []
    seen: dict[tuple[bytes, bytes], dict] = {}
    for delta in deltas:
        ear = extract_expected_active_revision(delta)
        key = _ear_sort_key(ear)
        if key in seen:
            if seen[key] != ear:
                raise ChangeSetError(
                    "conflicting_expected_active_revision",
                    f"duplicate target ({ear['object_kind']}, {ear['object_id']}) "
                    f"with unequal expectation",
                )
        else:
            seen[key] = ear
            ears.append(ear)
    ears.sort(key=_ear_sort_key)
    return ears


# ---------------------------------------------------------------------------
# changes_root
# ---------------------------------------------------------------------------


def compute_changes_root(deltas: Sequence[Mapping]) -> str:
    """``changes_root = SHA-256("wiki.changes-root.v1" || length-delimited
    canonical delta bytes in canonical order)``.

    Deltas are sorted by their ``delta_id`` (hex string sort = byte sort
    for lowercase hex64) before framing.
    """
    sorted_deltas = sorted(deltas, key=lambda d: d["delta_id"])
    h = hashlib.sha256(_CHANGES_ROOT_PREFIX)
    for delta in sorted_deltas:
        body = canonical_bytes(delta)
        h.update(struct.pack(">Q", len(body)))
        h.update(body)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# EncryptedAcceptedChangeSetV1
# ---------------------------------------------------------------------------


def build_encrypted_accepted_changeset(
    *,
    workspace_id: str,
    parent_generation_id: str | None,
    command_ids: Sequence[str],
    deltas: Sequence[Mapping],
) -> dict:
    ears = project_expected_active_revisions(deltas)
    changes_root = compute_changes_root(deltas)
    sorted_command_ids = sorted(set(command_ids))
    sorted_deltas = sorted(deltas, key=lambda d: d["delta_id"])

    body = {
        "contract_version": CONTRACT_VERSION,
        "workspace_id": workspace_id,
        "parent_generation_id": parent_generation_id,
        "expected_active_revisions": ears,
        "command_ids": sorted_command_ids,
        "deltas": sorted_deltas,
        "changes_root": changes_root,
    }
    changeset_id = hashlib.sha256(
        _CHANGESET_ID_PREFIX + canonical_bytes(body)
    ).hexdigest()
    return {"changeset_id": changeset_id, **body}
