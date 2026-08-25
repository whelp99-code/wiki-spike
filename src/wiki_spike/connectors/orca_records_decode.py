"""Parse Orca exported-record JSONL into typed scan or quarantine outcomes."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import assert_never

from wiki_spike.connectors.orca_records import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    ItemId,
    OrcaAcceptedItem,
    OrcaAcceptedScan,
    OrcaCursorV1,
    OrcaItemKind,
    OrcaQuarantineReason,
    OrcaReadResult,
    OrcaStoreQuarantined,
    WorktreeId,
)

type JsonNode = str | int | float | bool | None | list[JsonNode] | dict[str, JsonNode]
type _LineResult = OrcaAcceptedItem | OrcaQuarantineReason | None
type _HeaderResult = WorktreeId | OrcaStoreQuarantined

_FORBIDDEN_FIELDS = frozenset({
    "access_token", "api_key", "auth", "browser_profile", "browser_state",
    "credential", "cookie", "password", "pty", "session_token",
})
_DENIED_TYPES = frozenset({"app_db", "auth", "browser_state", "credentials", "live_terminal"})
_COMMENT_FIELDS = frozenset({"id", "parent_id", "text", "type", "worktree_id"})
_ARTIFACT_FIELDS = frozenset({"id", "name", "parent_id", "text", "type", "worktree_id"})
_TOMBSTONE_FIELDS = frozenset({"id", "kind", "type", "worktree_id"})
_META_FIELDS = frozenset({"export_version", "source_profile", "type"})
_WORKTREE_FIELDS = frozenset({"type", "worktree_id"})


def _text(value: JsonNode) -> str | None:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    return None


def _parent(value: JsonNode) -> ItemId | None | OrcaQuarantineReason:
    if value is None:
        return None
    text = _text(value)
    return OrcaQuarantineReason.INVALID_FORMAT if text is None else ItemId(text)


def _cursor_mutated(lines: tuple[str, ...], cursor: OrcaCursorV1) -> OrcaStoreQuarantined | None:
    if cursor.next_line < 0 or cursor.next_line > len(lines):
        return OrcaStoreQuarantined(OrcaQuarantineReason.SOURCE_MUTATED)
    prefix = "".join(lines[: cursor.next_line]).encode("utf-8")
    if sha256(prefix).hexdigest() != cursor.prefix_digest:
        return OrcaStoreQuarantined(OrcaQuarantineReason.SOURCE_MUTATED)
    return None


def _header(lines: tuple[str, ...]) -> _HeaderResult:
    seen: list[dict[str, JsonNode]] = []
    for line in lines:
        raw = line.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
        seen.append(value)
        if len(seen) == 2:
            break
    if not seen:
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    first = seen[0]
    if first.get("type") != "export_meta":
        return OrcaStoreQuarantined(OrcaQuarantineReason.LIVE_APP_STORE)
    version = first.get("export_version")
    if not isinstance(version, str):
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    if version != EXPORT_VERSION:
        return OrcaStoreQuarantined(OrcaQuarantineReason.UNSUPPORTED_VERSION)
    if set(first) != _META_FIELDS or first.get("source_profile") != SOURCE_PROFILE:
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    if len(seen) < 2:
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    second = seen[1]
    worktree_id = _text(second.get("worktree_id"))
    if second.get("type") != "worktree_meta" or worktree_id is None or set(second) != _WORKTREE_FIELDS:
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    return WorktreeId(worktree_id)


def _text_item(raw: Mapping[str, JsonNode], worktree_id: WorktreeId, kind: OrcaItemKind) -> _LineResult:
    if set(raw) != _COMMENT_FIELDS:
        return OrcaQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    text = _text(raw["text"])
    parent = _parent(raw["parent_id"])
    if item_id is None or text is None or _text(raw["worktree_id"]) != worktree_id:
        return OrcaQuarantineReason.INVALID_FORMAT
    match parent:
        case OrcaQuarantineReason():
            return OrcaQuarantineReason.INVALID_FORMAT
        case None | str():
            return OrcaAcceptedItem(ItemId(item_id), worktree_id, parent, kind, text, item_id, False, None)
        case unreachable:
            assert_never(unreachable)


def _artifact_item(raw: Mapping[str, JsonNode], worktree_id: WorktreeId) -> _LineResult:
    if set(raw) != _ARTIFACT_FIELDS:
        return OrcaQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    text = _text(raw["text"])
    name = _text(raw["name"])
    parent = _parent(raw["parent_id"])
    if item_id is None or text is None or name is None or _text(raw["worktree_id"]) != worktree_id:
        return OrcaQuarantineReason.INVALID_FORMAT
    match parent:
        case OrcaQuarantineReason():
            return OrcaQuarantineReason.INVALID_FORMAT
        case None | str():
            return OrcaAcceptedItem(
                ItemId(item_id), worktree_id, parent, OrcaItemKind.ARTIFACT, text, item_id, False, name
            )
        case unreachable:
            assert_never(unreachable)


def _tombstone_item(raw: Mapping[str, JsonNode], worktree_id: WorktreeId) -> _LineResult:
    if set(raw) != _TOMBSTONE_FIELDS:
        return OrcaQuarantineReason.INVALID_FORMAT
    item_id = _text(raw["id"])
    kind_name = raw["kind"]
    if item_id is None or _text(raw["worktree_id"]) != worktree_id or not isinstance(kind_name, str):
        return OrcaQuarantineReason.INVALID_FORMAT
    match kind_name:  # noqa: MATCH_OK
        case "worktree_comment":
            kind = OrcaItemKind.WORKTREE_COMMENT
        case "terminal_summary":
            kind = OrcaItemKind.TERMINAL_SUMMARY
        case "artifact":
            kind = OrcaItemKind.ARTIFACT
        case _:
            return OrcaQuarantineReason.INVALID_FORMAT
    return OrcaAcceptedItem(ItemId(item_id), worktree_id, None, kind, "", item_id, True, None)


def _parse_line(raw: JsonNode, worktree_id: WorktreeId) -> _LineResult:
    if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
        return OrcaQuarantineReason.INVALID_FORMAT
    record_type = raw.get("type")
    if not isinstance(record_type, str):
        return OrcaQuarantineReason.INVALID_FORMAT
    if record_type in _DENIED_TYPES or set(raw) & _FORBIDDEN_FIELDS:
        return None
    match record_type:  # noqa: MATCH_OK
        case "export_meta" | "worktree_meta":
            return None
        case "worktree_comment":
            return _text_item(raw, worktree_id, OrcaItemKind.WORKTREE_COMMENT)
        case "terminal_summary":
            return _text_item(raw, worktree_id, OrcaItemKind.TERMINAL_SUMMARY)
        case "artifact":
            return _artifact_item(raw, worktree_id)
        case "tombstone":
            return _tombstone_item(raw, worktree_id)
        case _:
            return OrcaQuarantineReason.INVALID_FORMAT


def parse_orca_export(payload: bytes, cursor: OrcaCursorV1 | None) -> OrcaReadResult:
    """Decode one public Orca export body. Caller already classified the path."""
    try:
        lines = tuple(payload.decode("utf-8").splitlines(keepends=True))
    except UnicodeDecodeError:
        return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
    if cursor is not None:
        mutated = _cursor_mutated(lines, cursor)
        if mutated is not None:
            return mutated
        start = cursor.next_line
    else:
        start = 0
    header = _header(lines)
    match header:
        case OrcaStoreQuarantined():
            return header
        case str() as worktree_id:
            bound = WorktreeId(worktree_id)
        case unreachable:
            assert_never(unreachable)
    items: list[OrcaAcceptedItem] = []
    for index, line in enumerate(lines):
        raw = line.strip()
        if not raw:
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError:
            return OrcaStoreQuarantined(OrcaQuarantineReason.INVALID_FORMAT)
        parsed = _parse_line(value, bound)
        match parsed:
            case None:
                continue
            case OrcaQuarantineReason() as reason:
                return OrcaStoreQuarantined(reason)
            case OrcaAcceptedItem() as item:
                if index >= start:
                    items.append(item)
            case unreachable:
                assert_never(unreachable)
    return OrcaAcceptedScan(
        EXPORT_VERSION,
        SOURCE_PROFILE,
        bound,
        tuple(items),
        OrcaCursorV1(len(lines), sha256(payload).hexdigest()),
    )
