"""Body-free git tracked-tree row and digest binding for the me-wiki profile."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue
from .me_wiki_source_evidence_contracts import (
    HEAD,
    TRACKED_TREE_DOMAIN,
)
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_string, strict_fields
from .unified_db_snapshot_export import parse_decimal

_TRACKED_ROW_FIELDS: Final = frozenset({"mode", "oid", "stage", "relative_path"})


@dataclass(frozen=True, slots=True)
class MeWikiTrackedTreeRow:
    """One git tracked-file row: mode, blob OID, stage, path. No body read."""

    mode: str
    oid: str
    stage: str
    relative_path: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> MeWikiTrackedTreeRow:
        strict_fields(data, _TRACKED_ROW_FIELDS)
        oid = parse_string(data["oid"], "oid")
        if HEAD.fullmatch(oid) is None:
            raise InvalidContractValue("oid must be a lowercase 40-hex git blob OID")
        path = parse_string(data["relative_path"], "relative_path")
        if not path or path.startswith("/") or "\\" in path or any(
            part in {"", ".", ".."} for part in path.split("/")
        ):
            raise InvalidContractValue(
                "relative_path must be a canonical relative POSIX path"
            )
        return cls(
            parse_string(data["mode"], "mode"),
            oid,
            parse_decimal(data["stage"], "stage"),
            path,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "mode": self.mode,
            "oid": self.oid,
            "stage": self.stage,
            "relative_path": self.relative_path,
        }


def compute_tracked_tree_digest(rows: tuple[MeWikiTrackedTreeRow, ...]) -> str:
    """Bind the sorted tracked-tree metadata without ever reading a body."""
    return canonical_ledger_digest(
        TRACKED_TREE_DOMAIN,
        {"rows": [row.to_mapping() for row in rows]},
    )


@dataclass(frozen=True, slots=True)
class MeWikiGitTreeV1:
    """Current git HEAD and the sorted tracked-tree rows it selects."""

    git_head: str
    rows: tuple[MeWikiTrackedTreeRow, ...]

    @property
    def tracked_tree_digest(self) -> str:
        return compute_tracked_tree_digest(self.rows)

    @property
    def tracked_count(self) -> str:
        return str(len(self.rows))
