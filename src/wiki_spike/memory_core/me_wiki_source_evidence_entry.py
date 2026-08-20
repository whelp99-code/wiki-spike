"""Frozen me-wiki mapping entry and row-set digest."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, assert_never

from .contracts import JsonValue
from .errors import InvalidContractValue
from .me_wiki_source_evidence_contracts import (
    HEAD,
    ROW_SET_DOMAIN,
    FixtureScenario,
    parse_scenario,
)
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_string, strict_fields
from .unified_db_snapshot_export import parse_decimal

_ENTRY_FIELDS: Final = frozenset(
    {
        "scenario",
        "native_id",
        "revision",
        "previous_revision",
        "watermark",
        "previous_watermark",
        "tombstone",
        "history_retained",
    }
)


@dataclass(frozen=True, slots=True)
class MeWikiMappingEntry:
    """One synthetic mapping row. Native IDs are root-relative POSIX paths."""

    scenario: FixtureScenario
    native_id: str
    revision: str | None
    previous_revision: str | None
    watermark: str
    previous_watermark: str | None
    tombstone: bool
    history_retained: bool

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> MeWikiMappingEntry:
        strict_fields(data, _ENTRY_FIELDS)
        scenario = parse_scenario(parse_string(data["scenario"], "scenario"))
        native_id = parse_string(data["native_id"], "native_id")
        if not native_id or native_id.startswith("/") or "\\" in native_id or any(
            part in {"", ".", ".."} for part in native_id.split("/")
        ):
            raise InvalidContractValue(
                "native_id must be a canonical relative POSIX path"
            )
        revision = data["revision"]
        previous_revision = data["previous_revision"]
        revision = None if revision is None else _oid(revision, "revision")
        previous_revision = (
            None
            if previous_revision is None
            else _oid(previous_revision, "previous_revision")
        )
        previous_watermark = data["previous_watermark"]
        previous_watermark = (
            None
            if previous_watermark is None
            else parse_decimal(previous_watermark, "previous_watermark")
        )
        tombstone = _boolean(data["tombstone"], "tombstone")
        history_retained = _boolean(data["history_retained"], "history_retained")
        entry = cls(
            scenario,
            native_id,
            revision,
            previous_revision,
            parse_decimal(data["watermark"], "watermark"),
            previous_watermark,
            tombstone,
            history_retained,
        )
        _assert_scenario_invariants(entry)
        return entry

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "scenario": self.scenario.value,
            "native_id": self.native_id,
            "revision": self.revision,
            "previous_revision": self.previous_revision,
            "watermark": self.watermark,
            "previous_watermark": self.previous_watermark,
            "tombstone": self.tombstone,
            "history_retained": self.history_retained,
        }


def _oid(value: JsonValue, field: str) -> str:
    parsed = parse_string(value, field)
    if HEAD.fullmatch(parsed) is None:
        raise InvalidContractValue(f"{field} must be a lowercase 40-hex git OID")
    return parsed


def _boolean(value: JsonValue, field: str) -> bool:
    if not isinstance(value, bool):
        raise InvalidContractValue(f"{field} must be a boolean")
    return value


def _assert_scenario_invariants(entry: MeWikiMappingEntry) -> None:
    scenario = entry.scenario
    match scenario:
        case FixtureScenario.CURRENT:
            if entry.tombstone or entry.history_retained is False:
                raise InvalidContractValue("current row must not tombstone and must retain history")
            if entry.revision is None or entry.previous_revision is not None:
                raise InvalidContractValue("current row requires revision and no previous revision")
            if entry.previous_watermark is not None:
                raise InvalidContractValue("current row must have no previous watermark")
        case FixtureScenario.UPDATED:
            if entry.tombstone or entry.history_retained is False:
                raise InvalidContractValue("updated row must not tombstone and must retain history")
            if entry.revision is None or entry.previous_revision is None:
                raise InvalidContractValue("updated row requires revision and previous revision")
            if entry.previous_watermark is None:
                raise InvalidContractValue("updated row requires previous watermark")
            if int(entry.watermark) <= int(entry.previous_watermark):
                raise InvalidContractValue("updated row watermark must exceed previous watermark")
        case FixtureScenario.DELETED_TOMBSTONE:
            if entry.tombstone is False or entry.history_retained is False:
                raise InvalidContractValue("tombstone row must tombstone and retain history")
            if entry.revision is not None:
                raise InvalidContractValue("tombstone row must have null revision")
            if entry.previous_revision is None or entry.previous_watermark is None:
                raise InvalidContractValue("tombstone row requires previous revision and watermark")
        case FixtureScenario.HISTORY_UNAVAILABLE_BEFORE_FLOOR:
            if entry.tombstone or entry.history_retained:
                raise InvalidContractValue("floor row must not tombstone and must not retain history")
            if entry.revision is None or entry.previous_revision is not None:
                raise InvalidContractValue("floor row requires revision and no previous revision")
            if entry.previous_watermark is not None:
                raise InvalidContractValue("floor row must have no previous watermark")
        case _:
            assert_never(scenario)


def row_set_digest(entries: tuple[MeWikiMappingEntry, ...]) -> str:
    body: dict[str, JsonValue] = {
        "entries": [entry.to_mapping() for entry in entries]
    }
    return canonical_ledger_digest(ROW_SET_DOMAIN, body)
