"""Fail-closed JSON object decoder that rejects raw numbers."""
from __future__ import annotations

from .contracts import JsonValue
from .unified_db_snapshot_export import UnifiedDbExportError


class _Cursor:
    text: str
    index: int

    def __init__(self, text: str) -> None:
        self.text = text
        self.index = 0

    def peek(self) -> str:
        if self.index >= len(self.text):
            return ""
        return self.text[self.index]

    def take(self) -> str:
        char = self.peek()
        if not char:
            raise UnifiedDbExportError("JSON ended unexpectedly")
        self.index += 1
        return char

    def skip_ws(self) -> None:
        while self.peek() and self.peek() in " \t\r\n":
            self.index += 1


def decode_json_object(text: str) -> dict[str, JsonValue]:
    cursor = _Cursor(text)
    cursor.skip_ws()
    value = _value(cursor)
    cursor.skip_ws()
    if cursor.peek():
        raise UnifiedDbExportError("JSON has trailing content")
    if not isinstance(value, dict):
        raise UnifiedDbExportError("JSON must be an object")
    return value


def _value(cursor: _Cursor) -> JsonValue:
    cursor.skip_ws()
    char = cursor.peek()
    if char == "{":
        return _object(cursor)
    if char == "[":
        return _array(cursor)
    if char == '"':
        return _string(cursor)
    if char == "t":
        return _literal(cursor, "true", True)
    if char == "f":
        return _literal(cursor, "false", False)
    if char == "n":
        return _literal(cursor, "null", None)
    raise UnifiedDbExportError("raw numbers are forbidden in export JSON")


def _literal(cursor: _Cursor, token: str, value: JsonValue) -> JsonValue:
    for expected in token:
        if cursor.take() != expected:
            raise UnifiedDbExportError("JSON literal is invalid")
    return value


def _object(cursor: _Cursor) -> dict[str, JsonValue]:
    _ = cursor.take()
    parsed: dict[str, JsonValue] = {}
    cursor.skip_ws()
    if cursor.peek() == "}":
        _ = cursor.take()
        return parsed
    while True:
        cursor.skip_ws()
        if cursor.peek() != '"':
            raise UnifiedDbExportError("JSON object key must be a string")
        key = _string(cursor)
        if key in parsed:
            raise UnifiedDbExportError("duplicate JSON object key")
        cursor.skip_ws()
        if cursor.take() != ":":
            raise UnifiedDbExportError("JSON object is missing a colon")
        parsed[key] = _value(cursor)
        cursor.skip_ws()
        nxt = cursor.take()
        if nxt == "}":
            return parsed
        if nxt != ",":
            raise UnifiedDbExportError("JSON object is missing a comma")


def _array(cursor: _Cursor) -> list[JsonValue]:
    _ = cursor.take()
    items: list[JsonValue] = []
    cursor.skip_ws()
    if cursor.peek() == "]":
        _ = cursor.take()
        return items
    while True:
        items.append(_value(cursor))
        cursor.skip_ws()
        nxt = cursor.take()
        if nxt == "]":
            return items
        if nxt != ",":
            raise UnifiedDbExportError("JSON array is missing a comma")


def _string(cursor: _Cursor) -> str:
    if cursor.take() != '"':
        raise UnifiedDbExportError("JSON string is invalid")
    chars: list[str] = []
    escapes = {"\"": "\"", "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
    while True:
        char = cursor.take()
        if char == '"':
            return "".join(chars)
        if char == "\\":
            code = cursor.take()
            if code == "u":
                hexed = "".join(cursor.take() for _ in range(4))
                try:
                    chars.append(chr(int(hexed, 16)))
                except ValueError as exc:
                    raise UnifiedDbExportError("JSON unicode escape is invalid") from exc
                continue
            if code not in escapes:
                raise UnifiedDbExportError("JSON string escape is invalid")
            chars.append(escapes[code])
            continue
        if ord(char) < 32:
            raise UnifiedDbExportError("JSON string has a control character")
        chars.append(char)
