"""Frozen identity message builders for the Encrypted Single-Memory Lifecycle.

Produces the five HMAC identity message shapes defined by
``schemas/encrypted-lifecycle/identity-message-v1.schema.json`` and
computes their digests via :func:`crypto.identity_hmac_hex`.  Every
builder returns ``(message_dict, hex_digest)`` so callers can persist
both the canonical message and its computed identity.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure only.
"""
from __future__ import annotations

from typing import Mapping, Sequence

from wiki_spike.infrastructure import crypto

# ---------------------------------------------------------------------------
# 1. Command digest  (domain ``wiki.command``, key ``command_digest_key_v1``)
# ---------------------------------------------------------------------------

COMMAND_DOMAIN = "wiki.command"


def command_digest(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    command_kind: str,
    normalized_options: Mapping,
    input_content_digest: str,
    policy_context_digest: str,
) -> tuple[dict, str]:
    message = {
        "domain": COMMAND_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "command_kind": command_kind,
        "normalized_options": dict(normalized_options),
        "input_content_digest": input_content_digest,
        "policy_context_digest": policy_context_digest,
    }
    digest = crypto.identity_hmac_hex(derived_keys, "command_digest_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 2. Manifest digest  (domain ``wiki.command-manifest``,
#    key ``manifest_digest_key_v1``)
# ---------------------------------------------------------------------------

MANIFEST_DOMAIN = "wiki.command-manifest"


def manifest_entry(
    *,
    artifact_role: str,
    ordinal: str,
    artifact_kind: str,
    revision_id: str,
    artifact_semantic_digest: str,
) -> dict:
    return {
        "artifact_role": artifact_role,
        "ordinal": ordinal,
        "artifact_kind": artifact_kind,
        "revision_id": revision_id,
        "artifact_semantic_digest": artifact_semantic_digest,
    }


def manifest_digest(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    command_digest_hex: str,
    entries: Sequence[Mapping],
) -> tuple[dict, str]:
    message = {
        "domain": MANIFEST_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "command_digest": command_digest_hex,
        "entries": [dict(e) for e in entries],
    }
    digest = crypto.identity_hmac_hex(derived_keys, "manifest_digest_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 3. Artifact semantic digest  (domain ``wiki.artifact-semantic``,
#    key ``artifact_identity_key_v1``)
# ---------------------------------------------------------------------------

ARTIFACT_SEMANTIC_DOMAIN = "wiki.artifact-semantic"


def artifact_semantic_digest(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    artifact_kind: str,
    consent_epoch: str,
    semantic_schema: str,
    semantic_plaintext: Mapping,
) -> tuple[dict, str]:
    message = {
        "domain": ARTIFACT_SEMANTIC_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "artifact_kind": artifact_kind,
        "consent_epoch": consent_epoch,
        "semantic_schema": semantic_schema,
        "semantic_plaintext": dict(semantic_plaintext),
    }
    digest = crypto.identity_hmac_hex(derived_keys, "artifact_identity_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 4. Logical object ID  (domain ``wiki.logical-object-id``,
#    key ``object_identity_key_v1``)
# ---------------------------------------------------------------------------

OBJECT_ID_DOMAIN = "wiki.logical-object-id"


def logical_object_id(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    object_kind: str,
    consent_epoch: str,
    subject_key_digest: str,
) -> tuple[dict, str]:
    message = {
        "domain": OBJECT_ID_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "object_kind": object_kind,
        "consent_epoch": consent_epoch,
        "subject_key_digest": subject_key_digest,
    }
    digest = crypto.identity_hmac_hex(derived_keys, "object_identity_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 5. Revision ID  (domain ``wiki.revision-id``,
#    key ``revision_identity_key_v1``)
# ---------------------------------------------------------------------------

REVISION_ID_DOMAIN = "wiki.revision-id"


def revision_id(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    object_kind: str,
    logical_object_id_hex: str,
    consent_epoch: str,
    revision_number: str,
    parent_revision_id: str | None,
    artifact_semantic_digest_hex: str,
) -> tuple[dict, str]:
    message = {
        "domain": REVISION_ID_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "object_kind": object_kind,
        "logical_object_id": logical_object_id_hex,
        "consent_epoch": consent_epoch,
        "revision_number": revision_number,
        "parent_revision_id": parent_revision_id,
        "artifact_semantic_digest": artifact_semantic_digest_hex,
    }
    digest = crypto.identity_hmac_hex(derived_keys, "revision_identity_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 6. Stable subject ref  (domain ``wiki.stable-subject-ref``,
#    key ``stable_subject_key_v1``)
# ---------------------------------------------------------------------------

STABLE_SUBJECT_DOMAIN = "wiki.stable-subject-ref"


def stable_subject_ref(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    project_id: str,
    source_instance_id: str,
    subject_ordinal: str,
) -> tuple[dict, str]:
    message = {
        "domain": STABLE_SUBJECT_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "project_id": project_id,
        "source_instance_id": source_instance_id,
        "subject_ordinal": subject_ordinal,
    }
    digest = crypto.identity_hmac_hex(derived_keys, "stable_subject_key_v1", message)
    return message, digest


# ---------------------------------------------------------------------------
# 7. Locator digest  (domain ``wiki.locator``,
#    key ``locator_identity_key_v1``)
# ---------------------------------------------------------------------------

LOCATOR_DOMAIN = "wiki.locator"


def locator_digest(
    derived_keys: Mapping[str, bytes],
    *,
    workspace_id: str,
    project_id: str,
    source_content_digest: str,
    locator_kind: str,
    locator_start: str | None,
    locator_end: str | None,
    locator_text: str | None,
) -> tuple[dict, str]:
    message = {
        "domain": LOCATOR_DOMAIN,
        "version": "1",
        "key_version": "1",
        "workspace_id": workspace_id,
        "project_id": project_id,
        "source_content_digest": source_content_digest,
        "locator_kind": locator_kind,
        "locator_start": locator_start,
        "locator_end": locator_end,
        "locator_text": locator_text,
    }
    digest = crypto.identity_hmac_hex(derived_keys, "locator_identity_key_v1", message)
    return message, digest
