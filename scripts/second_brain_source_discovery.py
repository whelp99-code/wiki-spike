#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = ["cryptography>=42"]
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      uv run scripts/second_brain_source_discovery.py --request REQUEST --output OUTPUT
# 3. Or make executable and run:
#      chmod +x scripts/second_brain_source_discovery.py && ./scripts/second_brain_source_discovery.py --request REQUEST --output OUTPUT
# ──────────────────
"""Fixture-safe CLI for closed metadata-only source discovery."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from wiki_spike.memory_core.source_discovery import SourceDiscoveryRequestV1

type JsonValue = None | bool | str | list[JsonValue] | dict[str, JsonValue]

_ = sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


class SourceDiscoveryCliError(ValueError):
    """The CLI input or output boundary refused an operation."""


class _JsonLoads(Protocol):
    def __call__(
        self,
        s: str,
        *,
        object_pairs_hook: Callable[
            [list[tuple[str, JsonValue]]], dict[str, JsonValue]
        ],
        parse_int: Callable[[str], JsonValue],
        parse_float: Callable[[str], JsonValue],
        parse_constant: Callable[[str], JsonValue],
    ) -> JsonValue: ...


class _Arguments(argparse.Namespace):
    """Mutable parse target owned exclusively by argparse."""

    request: Path = Path()
    output: Path = Path()


def _reject_duplicate_keys(
    pairs: list[tuple[str, JsonValue]],
) -> dict[str, JsonValue]:
    parsed: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in parsed:
            raise SourceDiscoveryCliError(f"duplicate request field: {key}")
        parsed[key] = value
    return parsed


def _reject_number(_raw: str) -> JsonValue:
    return "\0raw-number"


def _reject_constant(_raw: str) -> JsonValue:
    return "\0non-finite-number"


def _decode_json(
    loader: _JsonLoads,
    text: str,
    object_pairs_hook: Callable[
        [list[tuple[str, JsonValue]]], dict[str, JsonValue]
    ],
) -> JsonValue:
    return loader(
        text,
        object_pairs_hook=object_pairs_hook,
        parse_int=_reject_number,
        parse_float=_reject_number,
        parse_constant=_reject_constant,
    )


def _load_request(path: Path) -> SourceDiscoveryRequestV1:
    from wiki_spike.memory_core.source_discovery import SourceDiscoveryRequestV1

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SourceDiscoveryCliError("request JSON cannot be read") from exc
    if not text.strip().startswith("{") or not text.strip().endswith("}"):
        raise SourceDiscoveryCliError("request JSON must be an object")
    requests: list[SourceDiscoveryRequestV1] = []

    def parse_request(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        mapping = _reject_duplicate_keys(pairs)
        requests.append(SourceDiscoveryRequestV1.from_mapping(mapping))
        return mapping

    _decoded = _decode_json(json.loads, text, parse_request)
    if len(requests) != 1:
        raise SourceDiscoveryCliError("request JSON must be exactly one object")
    return requests[0]


def _write_atomic_new(path: Path, payload: bytes) -> None:
    if not path.parent.is_dir():
        raise SourceDiscoveryCliError("output parent must be an existing directory")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise SourceDiscoveryCliError("output already exists; overwrite refused") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _arguments() -> _Arguments:
    parser = argparse.ArgumentParser(
        description="Discover approved source metadata without reading source bodies."
    )
    _ = parser.add_argument("--request", required=True, type=Path)
    _ = parser.add_argument("--output", required=True, type=Path)
    arguments = _Arguments()
    _ = parser.parse_args(namespace=arguments)
    return arguments


def _sanitized(message: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in message)


def main() -> int:
    from wiki_spike.applications.source_discovery_service import (
        SourceDiscoveryError,
        discover_source,
    )
    from wiki_spike.memory_core.contracts import canonical_bytes
    from wiki_spike.memory_core.errors import CoreContractError

    arguments = _arguments()
    try:
        request = _load_request(arguments.request)
        manifest = discover_source(request)
        _write_atomic_new(
            arguments.output,
            canonical_bytes(manifest.to_mapping()) + b"\n",
        )
    except json.JSONDecodeError:
        print("source discovery refused: request JSON is invalid", file=sys.stderr)
        return 2
    except OSError:
        print("source discovery refused: filesystem operation failed", file=sys.stderr)
        return 2
    except (CoreContractError, SourceDiscoveryError, SourceDiscoveryCliError) as exc:
        print(f"source discovery refused: {_sanitized(str(exc))}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
