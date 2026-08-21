"""Frozen machine-safe contract constants for me-wiki DB-03 body-free evidence.

This module is metadata-only: it owns version strings, digest domains, mapping
semantics, and the closed fixture scenario vocabulary. It contains no I/O and
never reads a source body.
"""
from __future__ import annotations

import re
from enum import StrEnum, unique
from typing import Final

PROFILE_VERSION: Final = "second-brain-me-wiki-source-profile-v1"
FIXTURE_VERSION: Final = "second-brain-me-wiki-mapping-fixture-v1"
EVIDENCE_VERSION: Final = "second-brain-me-wiki-source-evidence-v1"

EVIDENCE_STATE: Final = "CONTRACT_AND_SYNTHETIC_FIXTURE_ONLY"
SOURCE_NAME: Final = "me-wiki"
SOURCE_ROOT: Final = "/Volumes/DevSpace/me-wiki"
DISCOVERY_MANIFEST_DIGEST: Final = (
    "aaf942e7700d6d728cc0bd5f1c9ffcf934dd9900f8130caee25b2743faa2dba8"
)

IDENTITY_MAPPING: Final = "ROOT_RELATIVE_POSIX_PATH"
REVISION_MAPPING: Final = "GIT_BLOB_OID"
WATERMARK_MAPPING: Final = "GIT_HEAD_PLUS_MTIME_NS"
ROW_ORDER: Final = "LEXICAL_CURSOR_ORDER"
OVERLAP_POLICY: Final = "INCLUSIVE_PREVIOUS_WATERMARK"
RESTART_POLICY: Final = "REPLAY_AND_DEDUPE"
PAGINATION: Final = "CANONICAL_DECIMAL_PAGINATION"
RETENTION_HOURS: Final = "2160"
DELETION_POLICY: Final = "GIT_DIFF_TOMBSTONE"
HISTORY_POLICY: Final = "GIT_OBJECT_HISTORY_RETAINED"

PROFILE_DOMAIN: Final = "me-wiki-source-profile-v1"
FIXTURE_DOMAIN: Final = "me-wiki-mapping-fixture-v1"
EVIDENCE_DOMAIN: Final = "me-wiki-source-evidence-v1"
ROW_SET_DOMAIN: Final = "me-wiki-mapping-row-set-v1"
TRACKED_TREE_DOMAIN: Final = "me-wiki-tracked-tree-v1"

OID: Final = re.compile(r"^[0-9a-f]{40}$")
HEAD: Final = re.compile(r"^[0-9a-f]{40}$")
DECIMAL: Final = re.compile(r"^(0|[1-9][0-9]*)$")
DIGEST: Final = re.compile(r"^[0-9a-f]{64}$")
POSIX_PATH: Final = re.compile(
    r"^(?!.*(?:^|/)\.{1,2}(?:/|$))(?!/)(?!.*[:\\])[A-Za-z0-9][A-Za-z0-9._/-]*$"
)


@unique
class FixtureScenario(StrEnum):
    """The four body-free scenarios a me-wiki mapping fixture must cover."""

    CURRENT = "current"
    UPDATED = "updated"
    DELETED_TOMBSTONE = "deleted_tombstone"
    HISTORY_UNAVAILABLE_BEFORE_FLOOR = "history_unavailable_before_floor"


def parse_scenario(value: str) -> FixtureScenario:
    """Parse a scenario string into the closed variant or refuse."""
    match value:
        case "current":
            return FixtureScenario.CURRENT
        case "updated":
            return FixtureScenario.UPDATED
        case "deleted_tombstone":
            return FixtureScenario.DELETED_TOMBSTONE
        case "history_unavailable_before_floor":
            return FixtureScenario.HISTORY_UNAVAILABLE_BEFORE_FLOOR
        case _:
            raise ValueError(f"unknown fixture scenario: {value}")
