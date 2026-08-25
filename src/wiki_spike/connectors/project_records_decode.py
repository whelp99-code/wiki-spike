"""Parse registered project/JARVIS JSONL into typed scan or quarantine outcomes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import assert_never

from wiki_spike.connectors.project_records import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    ItemId,
    ProjectAcceptedItem,
    ProjectAcceptedScan,
    ProjectCursorV1,
    ProjectId,
    ProjectQuarantineReason,
    ProjectReadResult,
    ProjectRecordKind,
    ProjectStoreQuarantined,
)

type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]
type _LineResult = ProjectAcceptedItem | ProjectQuarantineReason | None
type _HeaderResult = ProjectId | ProjectStoreQuarantined

_DENIED_TYPES: frozenset[str] = frozenset(
    {"approval_action", "auth", "credentials", "dispatch", "live_control", "secret"}
)
_FORBIDDEN_FIELDS: frozenset[str] = frozenset(
    {"access_token", "api_key", "control_action", "launchd_label", "password", "secret"}
)
_META_FIELDS: frozenset[str] = frozenset({"export_version", "source_profile", "type"})
_PROJECT_FIELDS: frozenset[str] = frozenset({"project_id", "type"})
_RECORD_FIELDS: frozenset[str] = frozenset({"id", "parent_id", "project_id", "revision", "schema", "text", "type"})
_TOWER_FIELDS: frozenset[str] = _RECORD_FIELDS | {"name"}
_TOMBSTONE_FIELDS: frozenset[str] = frozenset({"id", "kind", "project_id", "type"})
_CONFIGURED_SCHEMAS: frozenset[str] = frozenset(
    {"jarvis_control_tower_export_v1", "operational_json_v1", "operational_markdown_v1"}
)


def _text(value: JsonNode) -> str | None:
    return value if isinstance(value, str) and value and "\x00" not in value else None


def _parent(value: JsonNode) -> ItemId | None | ProjectQuarantineReason:
    if value is None:
        return None
    text = _text(value)
    return ProjectQuarantineReason.INVALID_FORMAT if text is None else ItemId(text)


def _kind_for_schema(schema: str) -> ProjectRecordKind | ProjectQuarantineReason:
    match schema:  # noqa: MATCH_OK
        case "operational_markdown_v1":
            return ProjectRecordKind.OPERATIONAL_MARKDOWN
        case "operational_json_v1":
            return ProjectRecordKind.OPERATIONAL_JSON
        case "jarvis_control_tower_export_v1":
            return ProjectRecordKind.CONTROL_TOWER_ARTIFACT
        case _:
            return ProjectQuarantineReason.UNKNOWN_SCHEMA


def _kind_for_tombstone(kind_name: str) -> ProjectRecordKind | ProjectQuarantineReason:
    match kind_name:  # noqa: MATCH_OK
        case "operational_markdown":
            return ProjectRecordKind.OPERATIONAL_MARKDOWN
        case "operational_json":
            return ProjectRecordKind.OPERATIONAL_JSON
        case "control_tower_artifact":
            return ProjectRecordKind.CONTROL_TOWER_ARTIFACT
        case _:
            return ProjectQuarantineReason.UNKNOWN_SCHEMA


def _cursor_mutated(lines: tuple[str, ...], cursor: ProjectCursorV1) -> ProjectStoreQuarantined | None:
    if cursor.next_line < 0 or cursor.next_line > len(lines):
        return ProjectStoreQuarantined(ProjectQuarantineReason.SOURCE_MUTATED)
    prefix = "".join(lines[: cursor.next_line]).encode("utf-8")
    if sha256(prefix).hexdigest() != cursor.prefix_digest:
        return ProjectStoreQuarantined(ProjectQuarantineReason.SOURCE_MUTATED)
    return None


def _object(raw: str) -> dict[str, JsonNode] | ProjectStoreQuarantined:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    return value


def _header(lines: tuple[str, ...]) -> _HeaderResult:
    seen: list[dict[str, JsonNode]] = []
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        parsed = _object(raw)
        if isinstance(parsed, ProjectStoreQuarantined):
            return parsed
        seen.append(parsed)
        if len(seen) == 2:
            break
    if not seen:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    first = seen[0]
    if first.get("type") != "export_meta":
        return ProjectStoreQuarantined(ProjectQuarantineReason.LIVE_CONTROL)
    version = first.get("export_version")
    if not isinstance(version, str):
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    if version != EXPORT_VERSION:
        return ProjectStoreQuarantined(ProjectQuarantineReason.UNSUPPORTED_VERSION)
    if set(first) != _META_FIELDS or first.get("source_profile") != SOURCE_PROFILE:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    if len(seen) < 2:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    second = seen[1]
    project_id = _text(second.get("project_id"))
    if second.get("type") != "project_meta" or project_id is None or set(second) != _PROJECT_FIELDS:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    return ProjectId(project_id)


def _record_item(raw: Mapping[str, JsonNode], project_id: ProjectId) -> _LineResult:
    schema = raw.get("schema")
    if not isinstance(schema, str) or schema not in _CONFIGURED_SCHEMAS:
        return ProjectQuarantineReason.UNKNOWN_SCHEMA
    kind = _kind_for_schema(schema)
    match kind:
        case ProjectQuarantineReason() as reason:
            return reason
        case ProjectRecordKind.CONTROL_TOWER_ARTIFACT:
            required = _TOWER_FIELDS
        case ProjectRecordKind.OPERATIONAL_JSON | ProjectRecordKind.OPERATIONAL_MARKDOWN:
            required = _RECORD_FIELDS
        case unreachable:
            assert_never(unreachable)
    if set(raw) != required:
        return ProjectQuarantineReason.INVALID_FORMAT
    item_id, text, revision = _text(raw["id"]), _text(raw["text"]), _text(raw["revision"])
    parent = _parent(raw["parent_id"])
    name = _text(raw["name"]) if kind is ProjectRecordKind.CONTROL_TOWER_ARTIFACT else None
    if item_id is None or text is None or revision is None or _text(raw["project_id"]) != project_id:
        return ProjectQuarantineReason.INVALID_FORMAT
    if kind is ProjectRecordKind.CONTROL_TOWER_ARTIFACT and name is None:
        return ProjectQuarantineReason.INVALID_FORMAT
    match parent:
        case ProjectQuarantineReason():
            return ProjectQuarantineReason.INVALID_FORMAT
        case None | str():
            return ProjectAcceptedItem(ItemId(item_id), project_id, parent, kind, text, revision, False, name)
        case unreachable:
            assert_never(unreachable)


def _tombstone_item(raw: Mapping[str, JsonNode], project_id: ProjectId) -> _LineResult:
    if set(raw) != _TOMBSTONE_FIELDS:
        return ProjectQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    kind_name = raw["kind"]
    if item_id is None or _text(raw["project_id"]) != project_id or not isinstance(kind_name, str):
        return ProjectQuarantineReason.INVALID_FORMAT
    kind = _kind_for_tombstone(kind_name)
    match kind:
        case ProjectQuarantineReason() as reason:
            return reason
        case ProjectRecordKind():
            return ProjectAcceptedItem(ItemId(item_id), project_id, None, kind, "", item_id, True, None)
        case unreachable:
            assert_never(unreachable)


def _parse_line(raw: JsonNode, project_id: ProjectId) -> _LineResult:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        return ProjectQuarantineReason.INVALID_FORMAT
    record_type = raw.get("type")
    if not isinstance(record_type, str):
        return ProjectQuarantineReason.INVALID_FORMAT
    if record_type in _DENIED_TYPES or set(raw) & _FORBIDDEN_FIELDS:
        return None
    match record_type:  # noqa: MATCH_OK
        case "export_meta" | "project_meta":
            return None
        case "record":
            return _record_item(raw, project_id)
        case "tombstone":
            return _tombstone_item(raw, project_id)
        case _:
            return ProjectQuarantineReason.UNKNOWN_SCHEMA


def parse_project_export(payload: bytes, cursor: ProjectCursorV1 | None) -> ProjectReadResult:
    """Decode one registered project/JARVIS export body. Caller already classified the path."""
    try:
        lines = tuple(payload.decode("utf-8").splitlines(keepends=True))
    except UnicodeDecodeError:
        return ProjectStoreQuarantined(ProjectQuarantineReason.INVALID_FORMAT)
    if cursor is not None:
        mutated = _cursor_mutated(lines, cursor)
        if mutated is not None:
            return mutated
        start = cursor.next_line
    else:
        start = 0
    header = _header(lines)
    match header:
        case ProjectStoreQuarantined():
            return header
        case str() as project_id:
            bound = ProjectId(project_id)
        case unreachable:
            assert_never(unreachable)
    items: list[ProjectAcceptedItem] = []
    for index, line in enumerate(lines):
        raw = line.strip()
        if not raw:
            continue
        parsed = _object(raw)
        if isinstance(parsed, ProjectStoreQuarantined):
            return parsed
        item = _parse_line(parsed, bound)
        match item:
            case None:
                continue
            case ProjectQuarantineReason() as reason:
                return ProjectStoreQuarantined(reason)
            case ProjectAcceptedItem() as accepted:
                if index >= start:
                    items.append(accepted)
            case unreachable:
                assert_never(unreachable)
    return ProjectAcceptedScan(
        EXPORT_VERSION,
        SOURCE_PROFILE,
        bound,
        tuple(items),
        ProjectCursorV1(len(lines), sha256(payload).hexdigest()),
    )
