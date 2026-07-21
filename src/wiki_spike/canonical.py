"""Canonicalization profile (v3.3 §3).

Enforces:
- Unicode NFC on every string (keys and values) so NFC/NFD inputs hash equally.
- Raw numbers are FORBIDDEN: numbers/dates/versions/ids must be canonical strings
  (avoids IEEE-754 ambiguity flagged in Codex round 5).
- Deterministic serialization: sorted keys, no insignificant whitespace, UTF-8.

Note (spike limitation): full RFC 8785 JCS orders keys by UTF-16 code units; here we
sort by Unicode code point. These agree for all BMP characters (incl. Hangul), which
covers our identity fields. Non-BMP key ordering is out of scope for the spike.
"""
from __future__ import annotations

import json
import unicodedata
from typing import Any

NFC = "NFC"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be canonicalized deterministically."""


def _norm_str(s: str) -> str:
    return unicodedata.normalize(NFC, s)


def _normalize(value: Any) -> Any:
    # bool must be checked before int (bool is a subclass of int)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        raise CanonicalizationError(
            "raw numbers are forbidden in canonical payloads; encode "
            "numbers/dates/versions/ids as canonical strings"
        )
    if value is None:
        return None
    if isinstance(value, str):
        return _norm_str(value)
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError("object keys must be strings")
            nk = _norm_str(k)
            if nk in out:
                raise CanonicalizationError(
                    f"key collision after NFC normalization: {k!r} collides with an existing key"
                )
            out[nk] = _normalize(v)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    raise CanonicalizationError(f"unsupported type in canonical payload: {type(value)!r}")


def canonical_bytes(value: Any) -> bytes:
    """Return deterministic canonical UTF-8 bytes for a JSON-like value."""
    normalized = _normalize(value)
    return json.dumps(
        normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
