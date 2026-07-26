"""Encrypted lifecycle input normalization and command construction.

Implements ``normalize_lifecycle_input_v1`` (Stage 8 §Input and body rules)
and REMEMBER/APPROVE/REJECT command option builders.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure only.
"""
from __future__ import annotations

import hashlib
import unicodedata

MAX_NORMALIZED_BODY = 1_048_576


class InputNormalizationError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_lifecycle_input_v1(raw: bytes) -> bytes:
    """Normalize source bytes per the frozen Stage 8 input rules.

    Rejects UTF-8 BOM, invalid UTF-8, NUL, surrogates, and noncharacters.
    Converts CRLF then CR to LF.  NFC-normalizes.  Preserves all other
    whitespace and terminal-newline presence.  Emits UTF-8.  Never trims,
    parses JSON, infers MIME, or includes a path.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raise InputNormalizationError("bom_rejected", "UTF-8 BOM is not permitted")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise InputNormalizationError("invalid_utf8", f"invalid UTF-8: {exc}") from exc

    if "\x00" in text:
        raise InputNormalizationError("nul_rejected", "NUL character is not permitted")

    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise InputNormalizationError("surrogate_rejected", "surrogate code points are not permitted")
        if cp in (0xFFFE, 0xFFFF) or (
            cp >= 0xFDD0 and cp <= 0xFDEF
        ) or (
            cp >= 0x1FFFE and (cp & 0xFFFF) in (0xFFFE, 0xFFFF)
        ):
            raise InputNormalizationError("noncharacter_rejected", f"noncharacter U+{cp:04X} is not permitted")

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = unicodedata.normalize("NFC", text)

    result = text.encode("utf-8")
    if len(result) > MAX_NORMALIZED_BODY:
        raise InputNormalizationError(
            "body_too_large",
            f"normalized body {len(result)} bytes exceeds {MAX_NORMALIZED_BODY} limit",
        )
    return result


def input_content_digest(normalized_body: bytes) -> str:
    """``input_content_digest = SHA-256(normalized_body_bytes)`` as lowercase hex64."""
    return hashlib.sha256(normalized_body).hexdigest()


# ---------------------------------------------------------------------------
# Command option builders
# ---------------------------------------------------------------------------

REMEMBER_OPTIONS_SCHEMA = "wiki-remember-options-v1"
APPROVE_OPTIONS_SCHEMA = "wiki-approve-options-v1"
REJECT_OPTIONS_SCHEMA = "wiki-reject-options-v1"


def remember_options(
    *,
    project_id: str,
    source_kind: str,
    input_format: str,
    source_instance_id: str,
    subject_ordinal: str,
    sensitivity: str,
    consent_epoch: str,
    extractor_profile: str,
    new_consent: str = "NO",
    consent_reason: str | None = None,
    prior_object_id: str | None = None,
    prior_consent_epoch: str | None = None,
) -> dict:
    return {
        "schema": REMEMBER_OPTIONS_SCHEMA,
        "command_kind": "REMEMBER",
        "project_id": project_id,
        "source_kind": source_kind,
        "input_format": input_format,
        "source_instance_id": source_instance_id,
        "subject_ordinal": subject_ordinal,
        "sensitivity": sensitivity,
        "consent_epoch": consent_epoch,
        "extractor_profile": extractor_profile,
        "new_consent": new_consent,
        "consent_reason": consent_reason,
        "prior_object_id": prior_object_id,
        "prior_consent_epoch": prior_consent_epoch,
    }


def approve_options(
    *,
    candidate_id: str,
    expected_revision: str,
    reason_code: str,
) -> dict:
    return {
        "schema": APPROVE_OPTIONS_SCHEMA,
        "command_kind": "APPROVE",
        "candidate_id": candidate_id,
        "expected_revision": expected_revision,
        "reason_code": reason_code,
    }


def reject_options(
    *,
    candidate_id: str,
    expected_revision: str,
    reason_code: str,
) -> dict:
    return {
        "schema": REJECT_OPTIONS_SCHEMA,
        "command_kind": "REJECT",
        "candidate_id": candidate_id,
        "expected_revision": expected_revision,
        "reason_code": reason_code,
    }
