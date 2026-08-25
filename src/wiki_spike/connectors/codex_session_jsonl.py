"""Read-only decoder for a registered Codex JSONL export or store."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Final, assert_never

from wiki_spike.connectors.codex_session_records import (
    PendingItem,
    SessionBound,
    bind_item,
    interpret,
    parse_object,
)
from wiki_spike.connectors.codex_session_types import (
    EXPORT_VERSION,
    SOURCE_PROFILE,
    CodexAcceptedItem,
    CodexAcceptedScan,
    CodexCursorV1,
    CodexQuarantineReason,
    CodexReadResult,
    CodexScopeDisabled,
    CodexStoreQuarantined,
    SessionId,
)

_FORBIDDEN_NAMES: Final = frozenset({"auth.json", "config.toml", "session_index.jsonl"})
_FORBIDDEN_SUFFIXES: Final = (".db", ".sqlite", ".sqlite3")
_MANIFEST_FIELDS: Final = frozenset({"export_version", "sessions", "source_profile"})


class CodexSessionAdapter:
    """Decode an explicitly registered Codex JSONL export or store."""

    source_profile: Final = SOURCE_PROFILE
    source_domain: Final = "codex"

    def read(
        self,
        store: Path,
        *,
        cursor: CodexCursorV1 | None = None,
        scope_enabled: bool = True,
    ) -> CodexReadResult:
        if not scope_enabled:
            return CodexScopeDisabled()
        resolved = _resolve_store(store)
        match resolved:
            case CodexStoreQuarantined():
                return resolved
            case Path():
                return _read_jsonl(resolved, cursor)
            case unreachable:
                assert_never(unreachable)


def _forbidden_name(name: str) -> bool:
    folded = name.casefold()
    return folded in _FORBIDDEN_NAMES or folded.endswith(_FORBIDDEN_SUFFIXES)


def _resolve_store(store: Path) -> Path | CodexStoreQuarantined:
    if _forbidden_name(store.name):
        return CodexStoreQuarantined(CodexQuarantineReason.LIVE_AUTH_STORE)
    if store.is_dir():
        return _resolve_manifest(store)
    if store.is_file() and store.suffix.casefold() == ".jsonl":
        return store
    return CodexStoreQuarantined(CodexQuarantineReason.LIVE_AUTH_STORE)


def _resolve_manifest(store: Path) -> Path | CodexStoreQuarantined:
    manifest_path = store / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        return CodexStoreQuarantined(CodexQuarantineReason.LIVE_AUTH_STORE)
    try:
        loaded = json.loads(manifest_path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return CodexStoreQuarantined(CodexQuarantineReason.UNREADABLE)
    if not isinstance(loaded, dict) or set(loaded) != _MANIFEST_FIELDS:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    version, profile, sessions = loaded["export_version"], loaded["source_profile"], loaded["sessions"]
    if version != EXPORT_VERSION:
        return CodexStoreQuarantined(CodexQuarantineReason.UNSUPPORTED_VERSION)
    if profile != SOURCE_PROFILE or not isinstance(sessions, list) or len(sessions) != 1:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    name = sessions[0]
    if not isinstance(name, str) or "/" in name or name in {".", ".."} or _forbidden_name(name):
        return CodexStoreQuarantined(CodexQuarantineReason.LIVE_AUTH_STORE)
    session = store / name
    if session.is_symlink() or not session.is_file():
        return CodexStoreQuarantined(CodexQuarantineReason.UNREADABLE)
    return session


def _read_jsonl(path: Path, cursor: CodexCursorV1 | None) -> CodexReadResult:
    try:
        raw = path.read_bytes()
    except OSError:
        return CodexStoreQuarantined(CodexQuarantineReason.UNREADABLE)
    lines = raw.splitlines(keepends=True)
    started = _start_index(path.name, lines, cursor)
    match started:
        case CodexStoreQuarantined():
            return started
        case int() as start_line:
            pass
        case unreachable:
            assert_never(unreachable)
    session_id: SessionId | None = None
    parent_session_id: SessionId | None = None
    items: list[CodexAcceptedItem] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        parsed = parse_object(stripped)
        if parsed is None:
            return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
        event = interpret(index, parsed)
        match event:
            case CodexStoreQuarantined():
                return event
            case None:
                continue
            case SessionBound(session_id=bound_session, parent_session_id=bound_parent):
                session_id = bound_session
                parent_session_id = bound_parent
            case PendingItem() as pending:
                if session_id is None or index < start_line:
                    continue
                items.append(bind_item(pending, session_id))
            case unreachable:
                assert_never(unreachable)
    if session_id is None:
        return CodexStoreQuarantined(CodexQuarantineReason.INVALID_FORMAT)
    return CodexAcceptedScan(
        EXPORT_VERSION,
        SOURCE_PROFILE,
        session_id,
        parent_session_id,
        tuple(items),
        CodexCursorV1(path.name, len(lines), sha256(b"".join(lines)).hexdigest()),
    )


def _start_index(
    file_name: str, lines: list[bytes], cursor: CodexCursorV1 | None
) -> int | CodexStoreQuarantined:
    if cursor is None:
        return 0
    if cursor.file_name != file_name or cursor.next_line < 0 or cursor.next_line > len(lines):
        return CodexStoreQuarantined(CodexQuarantineReason.SOURCE_MUTATED)
    prefix = sha256(b"".join(lines[: cursor.next_line])).hexdigest()
    if prefix != cursor.prefix_digest:
        return CodexStoreQuarantined(CodexQuarantineReason.SOURCE_MUTATED)
    return cursor.next_line
