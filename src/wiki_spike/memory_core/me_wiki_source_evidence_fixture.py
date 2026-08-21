"""Synthetic me-wiki mapping fixture bound only to git metadata."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .me_wiki_source_evidence_contracts import (
    FIXTURE_DOMAIN,
    FIXTURE_VERSION,
    HEAD,
    FixtureScenario,
)
from .me_wiki_source_evidence_entry import (
    MeWikiMappingEntry,
    row_set_digest,
)
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields

__all__ = [
    "MeWikiMappingEntry",
    "MeWikiMappingFixtureV1",
    "build_synthetic_fixture",
    "row_set_digest",
]

_FIXTURE_FIELDS: Final = frozenset(
    {
        "fixture_version",
        "source_name",
        "entries",
        "row_set_digest",
        "fixture_digest",
    }
)


@dataclass(frozen=True, slots=True)
class MeWikiMappingFixtureV1:
    fixture_version: str
    source_name: str
    entries: tuple[MeWikiMappingEntry, ...]
    row_set_digest: str
    fixture_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> MeWikiMappingFixtureV1:
        strict_fields(data, _FIXTURE_FIELDS)
        version = parse_string(data["fixture_version"], "fixture_version")
        if version != FIXTURE_VERSION:
            raise UnsupportedContractVersion(f"unsupported fixture_version: {version!r}")
        source_name = parse_string(data["source_name"], "source_name")
        if source_name != "me-wiki":
            raise InvalidContractValue("source_name must be me-wiki")
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise InvalidContractValue("entries must be an array")
        entries = tuple(
            MeWikiMappingEntry.from_mapping(item)
            for item in raw_entries
            if isinstance(item, Mapping)
        )
        if len(entries) != len(raw_entries):
            raise InvalidContractValue("every fixture entry must be an object")
        scenarios = tuple(entry.scenario for entry in entries)
        if sorted(scenarios, key=lambda scenario: scenario.value) != sorted(
            FixtureScenario, key=lambda scenario: scenario.value
        ):
            raise InvalidContractValue("fixture must cover all four scenarios exactly once")
        ids = tuple(entry.native_id for entry in entries)
        if len(set(ids)) != len(ids):
            raise InvalidContractValue("native ids must be unique")
        if ids != tuple(sorted(ids)):
            raise InvalidContractValue("native ids must be unique and lexically sorted")
        parsed = cls(
            version,
            source_name,
            entries,
            parse_digest(data["row_set_digest"], "row_set_digest"),
            parse_digest(data["fixture_digest"], "fixture_digest"),
        )
        if parsed.row_set_digest != row_set_digest(entries):
            raise InvalidContractValue("row_set_digest does not bind fixture entries")
        if parsed.fixture_digest != parsed.computed_digest():
            raise InvalidContractValue("fixture_digest does not bind fixture fields")
        return parsed

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["fixture_digest"]
        return canonical_ledger_digest(FIXTURE_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "fixture_version": self.fixture_version,
            "source_name": self.source_name,
            "entries": [entry.to_mapping() for entry in self.entries],
            "row_set_digest": self.row_set_digest,
            "fixture_digest": self.fixture_digest,
        }


def build_synthetic_fixture(git_head: str) -> MeWikiMappingFixtureV1:
    """Build the four-scenario synthetic fixture derived from the git HEAD."""
    if HEAD.fullmatch(git_head) is None:
        raise InvalidContractValue("git_head must be a lowercase 40-hex commit OID")
    head = git_head
    rows = (
        MeWikiMappingEntry(
            FixtureScenario.CURRENT,
            "AGENT_RULES.md",
            head[:39] + "0",
            None,
            "1786341832836628064",
            None,
            False,
            True,
        ),
        MeWikiMappingEntry(
            FixtureScenario.UPDATED,
            "INDEX.md",
            head[:39] + "1",
            head[:39] + "9",
            "1786341832836628065",
            "1786341832836628060",
            False,
            True,
        ),
        MeWikiMappingEntry(
            FixtureScenario.DELETED_TOMBSTONE,
            "ops/repo-cleanup.md",
            None,
            head[:39] + "2",
            "1786341832836628066",
            "1786341832836628061",
            True,
            True,
        ),
        MeWikiMappingEntry(
            FixtureScenario.HISTORY_UNAVAILABLE_BEFORE_FLOOR,
            "voice/_template.md",
            head[:39] + "3",
            None,
            "1786341832836628067",
            None,
            False,
            False,
        ),
    )
    provisional = MeWikiMappingFixtureV1(
        FIXTURE_VERSION,
        "me-wiki",
        rows,
        "0" * 64,
        "0" * 64,
    )
    body = provisional.to_mapping()
    body["row_set_digest"] = row_set_digest(rows)
    body["fixture_digest"] = canonical_ledger_digest(
        FIXTURE_DOMAIN,
        {key: value for key, value in body.items() if key != "fixture_digest"},
    )
    return MeWikiMappingFixtureV1.from_mapping(body)
