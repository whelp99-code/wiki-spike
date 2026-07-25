"""Evidence-fragment locator validation and excerpt extraction.

Implements the four ``LocatorKind`` variants carried by
``LocatorDigestMessageV1`` / ``EvidenceFragmentSemanticV1`` (see
``identities.py::locator_digest`` and the plan's stage-08 locator contract,
line 144):

- ``BYTE_RANGE``: zero-based, end-exclusive; ``locator_start`` is a UInt63
  decimal string >= 0; ``locator_end`` is a positive decimal string >
  ``locator_start``; ``locator_text`` is null.
- ``LINE_RANGE``: one-based, inclusive; ``locator_start``/``locator_end``
  are positive decimal strings with ``locator_start <= locator_end``;
  ``locator_text`` is null.
- ``JSON_POINTER``: ``locator_start``/``locator_end`` are null;
  ``locator_text`` is a required RFC 6901 JSON Pointer string of 0..1024
  UTF-8 bytes; only the ``~0`` -> ``~`` and ``~1`` -> ``/`` escapes are
  admitted; it evaluates against the parsed normalized input.
- ``WHOLE_SOURCE``: ``locator_start``, ``locator_end``, and
  ``locator_text`` are all null.

Architecture-boundary contract: infrastructure layer; may import only
``wiki_spike.memory_core`` and stdlib/crypto -- never memory_runtime,
applications, connectors, ui, or legacy-storage.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from wiki_spike.memory_core.contracts import canonical_bytes

_UINT_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_UINT63_MAX = 2 ** 63  # exclusive upper bound: values must be strictly less than this
_MAX_POINTER_BYTES = 1024


class LocatorKind(str, Enum):
    BYTE_RANGE = "BYTE_RANGE"
    LINE_RANGE = "LINE_RANGE"
    JSON_POINTER = "JSON_POINTER"
    WHOLE_SOURCE = "WHOLE_SOURCE"


class LocatorError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Locator:
    locator_kind: str
    locator_start: str | None
    locator_end: str | None
    locator_text: str | None

    def to_mapping(self) -> dict[str, str | None]:
        return {
            "locator_kind": self.locator_kind,
            "locator_start": self.locator_start,
            "locator_end": self.locator_end,
            "locator_text": self.locator_text,
        }


def _require_decimal_string(value: Any, *, field: str, min_value: int, max_value_exclusive: int | None) -> int:
    if not isinstance(value, str):
        raise LocatorError("locator.field_not_string", f"{field} must be a decimal string")
    if not _UINT_DECIMAL_RE.match(value):
        raise LocatorError(
            "locator.field_not_decimal",
            f"{field} must match ^(0|[1-9][0-9]*)$, got {value!r}",
        )
    parsed = int(value)
    if parsed < min_value:
        raise LocatorError("locator.field_out_of_range", f"{field} must be >= {min_value}")
    if max_value_exclusive is not None and parsed >= max_value_exclusive:
        raise LocatorError("locator.field_out_of_range", f"{field} must be < {max_value_exclusive}")
    return parsed


def _require_null(value: Any, *, field: str) -> None:
    if value is not None:
        raise LocatorError("locator.field_must_be_null", f"{field} must be null for this locator_kind")


def _require_not_null(value: Any, *, field: str) -> None:
    if value is None:
        raise LocatorError("locator.field_required", f"{field} is required for this locator_kind")


def _validate_json_pointer_text(text: Any) -> str:
    if not isinstance(text, str):
        raise LocatorError("locator.pointer_not_string", "locator_text must be a string")
    byte_len = len(text.encode("utf-8"))
    if byte_len > _MAX_POINTER_BYTES:
        raise LocatorError(
            "locator.pointer_too_long",
            f"locator_text must be 0..1024 UTF-8 bytes, got {byte_len}",
        )
    if text == "":
        return text
    if not text.startswith("/"):
        raise LocatorError("locator.pointer_malformed", "non-empty JSON Pointer must start with '/'")
    # Validate tilde-escape admissibility: every '~' must be followed by '0' or '1'.
    index = 0
    while True:
        index = text.find("~", index)
        if index == -1:
            break
        if index + 1 >= len(text) or text[index + 1] not in ("0", "1"):
            raise LocatorError(
                "locator.pointer_bad_escape",
                "JSON Pointer tilde escapes must be '~0' or '~1'",
            )
        index += 2
    return text


def validate_locator(locator: Mapping[str, Any]) -> None:
    if "locator_kind" not in locator:
        raise LocatorError("locator.kind_missing", "locator_kind is required")
    kind = locator.get("locator_kind")
    start = locator.get("locator_start")
    end = locator.get("locator_end")
    text = locator.get("locator_text")

    if kind == LocatorKind.BYTE_RANGE.value:
        _require_not_null(start, field="locator_start")
        _require_not_null(end, field="locator_end")
        _require_null(text, field="locator_text")
        start_value = _require_decimal_string(
            start, field="locator_start", min_value=0, max_value_exclusive=_UINT63_MAX
        )
        end_value = _require_decimal_string(
            end, field="locator_end", min_value=1, max_value_exclusive=_UINT63_MAX
        )
        if end_value <= start_value:
            raise LocatorError(
                "locator.byte_range_not_increasing",
                "locator_end must be strictly greater than locator_start",
            )
    elif kind == LocatorKind.LINE_RANGE.value:
        _require_not_null(start, field="locator_start")
        _require_not_null(end, field="locator_end")
        _require_null(text, field="locator_text")
        start_value = _require_decimal_string(
            start, field="locator_start", min_value=1, max_value_exclusive=None
        )
        end_value = _require_decimal_string(
            end, field="locator_end", min_value=1, max_value_exclusive=None
        )
        if start_value > end_value:
            raise LocatorError(
                "locator.line_range_not_ordered",
                "locator_start must be <= locator_end",
            )
    elif kind == LocatorKind.JSON_POINTER.value:
        _require_null(start, field="locator_start")
        _require_null(end, field="locator_end")
        _require_not_null(text, field="locator_text")
        _validate_json_pointer_text(text)
    elif kind == LocatorKind.WHOLE_SOURCE.value:
        _require_null(start, field="locator_start")
        _require_null(end, field="locator_end")
        _require_null(text, field="locator_text")
    else:
        raise LocatorError("locator.unknown_kind", f"unknown locator_kind: {kind!r}")


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    tokens = pointer.split("/")[1:]
    current = document
    for raw_token in tokens:
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                raise LocatorError(
                    "locator.pointer_not_found",
                    f"JSON Pointer segment {token!r} not found",
                )
            current = current[token]
        elif isinstance(current, list):
            if token == "-" or not re.match(r"^(0|[1-9][0-9]*)$", token):
                raise LocatorError(
                    "locator.pointer_bad_index",
                    f"JSON Pointer array index {token!r} is invalid",
                )
            idx = int(token)
            if idx >= len(current):
                raise LocatorError(
                    "locator.pointer_not_found",
                    f"JSON Pointer array index {idx} out of range",
                )
            current = current[idx]
        else:
            raise LocatorError(
                "locator.pointer_not_found",
                f"JSON Pointer cannot descend into scalar at segment {token!r}",
            )
    return current


def extract_excerpt(locator: Mapping[str, Any], normalized_body: bytes) -> str:
    validate_locator(locator)
    kind = locator["locator_kind"]

    if kind == LocatorKind.BYTE_RANGE.value:
        start = int(locator["locator_start"])
        end = int(locator["locator_end"])
        if start > len(normalized_body) or end > len(normalized_body):
            raise LocatorError(
                "locator.byte_range_out_of_bounds",
                "locator_start/locator_end exceed normalized_body length",
            )
        chunk = normalized_body[start:end]
        try:
            return chunk.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise LocatorError(
                "locator.byte_range_not_utf8",
                f"byte range does not fall on valid UTF-8 boundaries: {exc}",
            ) from exc

    if kind == LocatorKind.LINE_RANGE.value:
        start = int(locator["locator_start"])
        end = int(locator["locator_end"])
        lines = normalized_body.decode("utf-8").split("\n")
        if start > len(lines) or end > len(lines):
            raise LocatorError(
                "locator.line_range_out_of_bounds",
                "locator_start/locator_end exceed normalized_body line count",
            )
        return "\n".join(lines[start - 1:end])

    if kind == LocatorKind.JSON_POINTER.value:
        try:
            document = json.loads(normalized_body)
        except json.JSONDecodeError as exc:
            raise LocatorError(
                "locator.body_not_json",
                f"normalized_body is not valid JSON: {exc}",
            ) from exc
        resolved = _resolve_json_pointer(document, locator["locator_text"])
        return canonical_bytes(resolved).decode("utf-8")

    if kind == LocatorKind.WHOLE_SOURCE.value:
        return normalized_body.decode("utf-8")

    raise LocatorError("locator.unknown_kind", f"unknown locator_kind: {kind!r}")
