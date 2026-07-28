"""Runtime-local temporal helpers for pinned second-brain recall."""
from __future__ import annotations

from datetime import datetime, timezone


def parse_utc(value: str) -> datetime:
    """Parse a canonical UTC instant without consulting external state."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("instant must be canonical UTC")
    try:
        instant = datetime.fromisoformat(value[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError as exc:
        raise ValueError("instant must be canonical UTC") from exc
    if instant.strftime("%Y-%m-%dT%H:%M:%S") != value[:19]:
        raise ValueError("instant must be canonical UTC")
    return instant


def contains_half_open(start: str, end: str | None, instant: str) -> bool:
    """Return whether *instant* is within [start, end)."""
    point = parse_utc(instant)
    return parse_utc(start) <= point and (end is None or point < parse_utc(end))
