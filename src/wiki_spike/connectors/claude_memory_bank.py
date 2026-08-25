"""Claude/Memory Bank adapter: registered JSONL, approved markdown, fixture connector."""

from __future__ import annotations

import os
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Final, assert_never

from wiki_spike.connectors.claude_memory_bank_jsonl import decode_jsonl_file, load_object, read_export_bytes
from wiki_spike.connectors.claude_memory_bank_models import (
    EXPORT_VERSION,
    MEMORY_BANK_VERSION,
    SOURCE_PROFILE,
    ClaudeAcceptedItem,
    ClaudeAcceptedScan,
    ClaudeCitationV1,
    ClaudeCursorV1,
    ClaudeItemKind,
    ClaudeQuarantineReason,
    ClaudeReadResult,
    ClaudeScopeDisabled,
    ClaudeStoreQuarantined,
    ItemId,
    JsonNode,
    MemoryId,
    ProjectId,
    SessionId,
    json_text,
    memory_citation,
    quarantine,
    with_tombstones,
)

from . import FixtureConnectorReader

_LIVE_NAMES: Final = frozenset({".credentials", "auth.json", "cookies", "cookies.json", "credentials", "credentials.json"})
_LIVE_SUFFIXES: Final = frozenset({".db", ".sqlite"})
_FRONTMATTER: Final = "---\n"


class ClaudeMemoryBankFixtureConnector(FixtureConnectorReader):
    """Stage-2 fixture reader for the closed Claude/Memory Bank profile."""


setattr(ClaudeMemoryBankFixtureConnector, "source_profile", "Claude/Memory Bank")
setattr(ClaudeMemoryBankFixtureConnector, "source_domain", "claude-memory-bank")


class ClaudeMemoryBankAdapter:
    """Read-only decoder for registered Claude JSONL and approved Memory Bank markdown."""

    def __init__(self, previous: tuple[ItemId, ...] = ()) -> None:
        self._previous = previous

    def read(self, store: Path, *, cursor: ClaudeCursorV1 | None = None, scope_enabled: bool = True) -> ClaudeReadResult:
        if not scope_enabled:
            return ClaudeScopeDisabled()
        if _is_live(store):
            return ClaudeStoreQuarantined(ClaudeQuarantineReason.LIVE_AUTH_STORE)
        if store.is_dir():
            return _read_store(store, cursor, self._previous)
        suffix = store.suffix.casefold()
        if suffix == ".jsonl":
            return decode_jsonl_file(store, cursor, self._previous)
        if suffix == ".md":
            return _decode_memory_file(store, self._previous)
        return ClaudeStoreQuarantined(ClaudeQuarantineReason.LIVE_AUTH_STORE)


def _is_live(path: Path) -> bool:
    name = path.name.casefold()
    if name in _LIVE_NAMES or path.suffix.casefold() in _LIVE_SUFFIXES:
        return True
    if not path.is_dir():
        return False
    try:
        names = {entry.name.casefold() for entry in os.scandir(path)}
    except OSError:
        return True
    return "manifest.json" not in names and bool(names & _LIVE_NAMES)


def _safe_rel(name: str) -> bool:
    return bool(name) and "/" not in name and "\\" not in name and name not in {".", ".."} and not name.startswith(".")


def _decode_memory_file(path: Path, previous: tuple[ItemId, ...]) -> ClaudeReadResult:
    raw = read_export_bytes(path)
    return quarantine(ClaudeQuarantineReason.INVALID_FORMAT) if raw is None else _decode_memory(raw, previous)


def _decode_memory(raw: bytes, previous: tuple[ItemId, ...]) -> ClaudeReadResult:
    try:
        text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    except UnicodeDecodeError:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    fields, body = _split_memory(text)
    if fields is None or not body:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    version = fields.get("export_version")
    if version != MEMORY_BANK_VERSION:
        reason = ClaudeQuarantineReason.UNSUPPORTED_VERSION if version else ClaudeQuarantineReason.INVALID_FORMAT
        return quarantine(reason)
    if fields.get("source_profile") != SOURCE_PROFILE:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    project = fields.get("project_id")
    memory = fields.get("memory_id")
    revision = fields.get("revision")
    if not project or not memory or not revision:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    item = ClaudeAcceptedItem(
        ItemId(memory),
        ProjectId(project),
        None,
        MemoryId(memory),
        None,
        ClaudeItemKind.MEMORY,
        body,
        revision,
        False,
        (memory_citation(ProjectId(project), memory),),
    )
    return ClaudeAcceptedScan(
        MEMORY_BANK_VERSION,
        SOURCE_PROFILE,
        ProjectId(project),
        None,
        with_tombstones([item], previous, (ProjectId(project), None)),
        ClaudeCursorV1(0, sha256(raw).hexdigest()),
    )


def _split_memory(text: str) -> tuple[dict[str, str] | None, str]:
    if not text.startswith(_FRONTMATTER):
        return None, ""
    rest = text[len(_FRONTMATTER) :]
    closer = rest.find("\n---\n")
    if closer < 0:
        return None, ""
    fields: dict[str, str] = {}
    for line in rest[:closer].splitlines():
        if not line.strip():
            continue
        key, sep, value = line.partition(":")
        if not sep or key != key.strip() or not key or " " in key:
            return None, ""
        fields[key] = value.strip()
    return fields, rest[closer + 5 :].strip()


def _read_store(root: Path, cursor: ClaudeCursorV1 | None, previous: tuple[ItemId, ...]) -> ClaudeReadResult:
    manifest_raw = read_export_bytes(root / "manifest.json")
    if manifest_raw is None:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    try:
        manifest = load_object(manifest_raw.decode("utf-8"))
    except UnicodeDecodeError:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    if manifest is None:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    version = manifest.get("export_version")
    if not isinstance(version, str):
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    if version != EXPORT_VERSION:
        return quarantine(ClaudeQuarantineReason.UNSUPPORTED_VERSION)
    if manifest.get("source_profile") != SOURCE_PROFILE:
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    project = json_text(manifest.get("project_id"))
    sessions = manifest.get("sessions")
    memories = manifest.get("memory_bank")
    if project is None or not isinstance(sessions, list) or not isinstance(memories, list):
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    items: list[ClaudeAcceptedItem] = []
    session_id: SessionId | None = None
    last_cursor = ClaudeCursorV1(0, sha256(b"").hexdigest())
    for rel in sessions:
        result = _read_rel(root, rel, lambda path: decode_jsonl_file(path, cursor, ()))
        match result:
            case ClaudeStoreQuarantined() | ClaudeScopeDisabled() as failure:
                return failure
            case ClaudeAcceptedScan() as scan:
                items.extend(scan.items)
                session_id = scan.session_id
                last_cursor = scan.cursor
            case unreachable:
                assert_never(unreachable)
    for rel in memories:
        result = _read_rel(root, rel, lambda path: _decode_memory_file(path, ()))
        match result:
            case ClaudeStoreQuarantined() | ClaudeScopeDisabled() as failure:
                return failure
            case ClaudeAcceptedScan() as scan:
                items.extend(scan.items)
            case unreachable:
                assert_never(unreachable)
    accepted = with_tombstones(items, previous, (ProjectId(project), session_id)) if cursor is None else tuple(items)
    return ClaudeAcceptedScan(EXPORT_VERSION, SOURCE_PROFILE, ProjectId(project), session_id, accepted, last_cursor)


def _read_rel(root: Path, rel: JsonNode, reader: Callable[[Path], ClaudeReadResult]) -> ClaudeReadResult:
    if not isinstance(rel, str) or not _safe_rel(rel):
        return quarantine(ClaudeQuarantineReason.INVALID_FORMAT)
    return reader(root / rel)


__all__ = [
    "EXPORT_VERSION",
    "MEMORY_BANK_VERSION",
    "ClaudeAcceptedItem",
    "ClaudeAcceptedScan",
    "ClaudeCitationV1",
    "ClaudeCursorV1",
    "ClaudeItemKind",
    "ClaudeMemoryBankAdapter",
    "ClaudeMemoryBankFixtureConnector",
    "ClaudeQuarantineReason",
    "ClaudeReadResult",
    "ClaudeScopeDisabled",
    "ClaudeStoreQuarantined",
    "ItemId",
    "MemoryId",
    "ProjectId",
    "SessionId",
]
