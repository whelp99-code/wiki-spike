"""Strict evidence checks for the macOS persistence profile."""
from __future__ import annotations

import json
from dataclasses import dataclass


class PersistenceProfileAuthorizationError(ValueError):
    """The signed persistence profile cannot authorize serving components."""


type _JsonValue = None | bool | str | list[_JsonValue] | _JsonObject


@dataclass(frozen=True, slots=True)
class _JsonObject:
    pairs: tuple[tuple[str, _JsonValue], ...]


def parse_sqlcipher_artifact(raw: bytes) -> None:
    """Require the exact honest Darwin/arm64 SQLCipher feasibility result."""
    objects: list[_JsonObject] = []

    def parse_object(items: list[tuple[str, _JsonValue]]) -> _JsonObject:
        keys = tuple(key for key, _value in items)
        if len(keys) != len(set(keys)):
            raise PersistenceProfileAuthorizationError(
                "SQLCipher artifact contains duplicate JSON fields"
            )
        parsed = _JsonObject(tuple(items))
        objects.append(parsed)
        return parsed

    try:
        if not isinstance(
            json.loads(raw, object_pairs_hook=parse_object), _JsonObject
        ):
            raise PersistenceProfileAuthorizationError(
                "SQLCipher artifact must be a JSON object"
            )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact must be valid JSON"
        ) from exc
    value = dict(objects[-1].pairs)
    expected: dict[str, _JsonValue] = {
        "schema": "wiki-sqlcipher-feasibility-v1",
        "platform": "darwin/arm64",
        "status": "platform_unavailable",
        "must_verdict": "NOT_RUN",
        "library": None,
        "checks": [],
    }
    if any(
        value.get(field) != expected_value
        for field, expected_value in expected.items()
    ):
        raise PersistenceProfileAuthorizationError(
            "SQLCipher artifact must record darwin/arm64 platform_unavailable and NOT_RUN"
        )
