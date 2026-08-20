"""Frozen me-wiki source profile contract (body-free git metadata only)."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .me_wiki_source_evidence_contracts import (
    DELETION_POLICY,
    DISCOVERY_MANIFEST_DIGEST,
    HEAD,
    HISTORY_POLICY,
    IDENTITY_MAPPING,
    OVERLAP_POLICY,
    PAGINATION,
    PROFILE_DOMAIN,
    PROFILE_VERSION,
    RESTART_POLICY,
    RETENTION_HOURS,
    REVISION_MAPPING,
    ROW_ORDER,
    SOURCE_NAME,
    SOURCE_ROOT,
    WATERMARK_MAPPING,
)
from .me_wiki_source_evidence_tracked_tree import (
    MeWikiGitTreeV1,
    MeWikiTrackedTreeRow,
    compute_tracked_tree_digest,
)
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import parse_const, parse_decimal, parse_false

__all__ = [
    "MeWikiGitTreeV1",
    "MeWikiSourceProfileV1",
    "MeWikiTrackedTreeRow",
    "compute_tracked_tree_digest",
]

_PROFILE_FIELDS: Final = frozenset(
    {
        "profile_version",
        "source_name",
        "source_root",
        "discovery_manifest_digest",
        "identity_mapping",
        "revision_mapping",
        "watermark_mapping",
        "row_order",
        "overlap_policy",
        "restart_policy",
        "pagination",
        "retention_hours",
        "deletion_policy",
        "history_policy",
        "body_reads",
        "source_mutation",
        "import_requested",
        "serve_requested",
        "promote_requested",
        "git_head",
        "tracked_tree",
        "tracked_tree_digest",
        "tracked_count",
        "fixture_digest",
        "profile_digest",
    }
)


@dataclass(frozen=True, slots=True)
class MeWikiSourceProfileV1:
    profile_version: str
    source_name: str
    source_root: str
    discovery_manifest_digest: str
    identity_mapping: str
    revision_mapping: str
    watermark_mapping: str
    row_order: str
    overlap_policy: str
    restart_policy: str
    pagination: str
    retention_hours: str
    deletion_policy: str
    history_policy: str
    body_reads: str
    source_mutation: bool
    import_requested: bool
    serve_requested: bool
    promote_requested: bool
    git_head: str
    tracked_tree: tuple[MeWikiTrackedTreeRow, ...]
    tracked_tree_digest: str
    tracked_count: str
    fixture_digest: str
    profile_digest: str

    @classmethod
    def create(
        cls, source_root: str, git_tree: MeWikiGitTreeV1, fixture_digest: str
    ) -> MeWikiSourceProfileV1:
        provisional = cls(
            PROFILE_VERSION,
            SOURCE_NAME,
            source_root,
            DISCOVERY_MANIFEST_DIGEST,
            IDENTITY_MAPPING,
            REVISION_MAPPING,
            WATERMARK_MAPPING,
            ROW_ORDER,
            OVERLAP_POLICY,
            RESTART_POLICY,
            PAGINATION,
            RETENTION_HOURS,
            DELETION_POLICY,
            HISTORY_POLICY,
            "0",
            False,
            False,
            False,
            False,
            git_tree.git_head,
            git_tree.rows,
            git_tree.tracked_tree_digest,
            git_tree.tracked_count,
            fixture_digest,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"profile_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> MeWikiSourceProfileV1:
        strict_fields(data, _PROFILE_FIELDS)
        version = parse_string(data["profile_version"], "profile_version")
        if version != PROFILE_VERSION:
            raise UnsupportedContractVersion(f"unsupported profile_version: {version!r}")
        raw_tree = data["tracked_tree"]
        if not isinstance(raw_tree, list):
            raise InvalidContractValue("tracked_tree must be an array")
        rows = tuple(
            MeWikiTrackedTreeRow.from_mapping(item)
            for item in raw_tree
            if isinstance(item, Mapping)
        )
        if len(rows) != len(raw_tree):
            raise InvalidContractValue("every tracked_tree entry must be an object")
        paths = tuple(row.relative_path for row in rows)
        if paths != tuple(sorted(paths)):
            raise InvalidContractValue("tracked_tree must be lexically sorted and unique")
        profile = cls(
            version,
            parse_const(data["source_name"], "source_name", SOURCE_NAME),
            parse_const(data["source_root"], "source_root", SOURCE_ROOT),
            parse_const(
                data["discovery_manifest_digest"],
                "discovery_manifest_digest",
                DISCOVERY_MANIFEST_DIGEST,
            ),
            parse_const(data["identity_mapping"], "identity_mapping", IDENTITY_MAPPING),
            parse_const(data["revision_mapping"], "revision_mapping", REVISION_MAPPING),
            parse_const(data["watermark_mapping"], "watermark_mapping", WATERMARK_MAPPING),
            parse_const(data["row_order"], "row_order", ROW_ORDER),
            parse_const(data["overlap_policy"], "overlap_policy", OVERLAP_POLICY),
            parse_const(data["restart_policy"], "restart_policy", RESTART_POLICY),
            parse_const(data["pagination"], "pagination", PAGINATION),
            parse_const(data["retention_hours"], "retention_hours", RETENTION_HOURS),
            parse_const(data["deletion_policy"], "deletion_policy", DELETION_POLICY),
            parse_const(data["history_policy"], "history_policy", HISTORY_POLICY),
            parse_const(data["body_reads"], "body_reads", "0"),
            parse_false(data["source_mutation"], "source_mutation"),
            parse_false(data["import_requested"], "import_requested"),
            parse_false(data["serve_requested"], "serve_requested"),
            parse_false(data["promote_requested"], "promote_requested"),
            parse_string(data["git_head"], "git_head"),
            rows,
            parse_digest(data["tracked_tree_digest"], "tracked_tree_digest"),
            parse_decimal(data["tracked_count"], "tracked_count"),
            parse_digest(data["fixture_digest"], "fixture_digest"),
            parse_digest(data["profile_digest"], "profile_digest"),
        )
        if HEAD.fullmatch(profile.git_head) is None:
            raise InvalidContractValue("git_head must be a lowercase 40-hex commit OID")
        if profile.tracked_tree_digest != compute_tracked_tree_digest(rows):
            raise InvalidContractValue("tracked_tree_digest does not bind tracked_tree")
        if profile.tracked_count != str(len(rows)):
            raise InvalidContractValue("tracked_count does not match tracked_tree")
        if profile.profile_digest != profile.computed_digest():
            raise InvalidContractValue("profile_digest does not bind profile fields")
        return profile

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["profile_digest"]
        return canonical_ledger_digest(PROFILE_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "profile_version": self.profile_version,
            "source_name": self.source_name,
            "source_root": self.source_root,
            "discovery_manifest_digest": self.discovery_manifest_digest,
            "identity_mapping": self.identity_mapping,
            "revision_mapping": self.revision_mapping,
            "watermark_mapping": self.watermark_mapping,
            "row_order": self.row_order,
            "overlap_policy": self.overlap_policy,
            "restart_policy": self.restart_policy,
            "pagination": self.pagination,
            "retention_hours": self.retention_hours,
            "deletion_policy": self.deletion_policy,
            "history_policy": self.history_policy,
            "body_reads": self.body_reads,
            "source_mutation": self.source_mutation,
            "import_requested": self.import_requested,
            "serve_requested": self.serve_requested,
            "promote_requested": self.promote_requested,
            "git_head": self.git_head,
            "tracked_tree": [row.to_mapping() for row in self.tracked_tree],
            "tracked_tree_digest": self.tracked_tree_digest,
            "tracked_count": self.tracked_count,
            "fixture_digest": self.fixture_digest,
            "profile_digest": self.profile_digest,
        }
