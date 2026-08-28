"""Read-only stdio tools for AI clients using the same encrypted authority.

This transport exposes exactly two operations: ``memory_recall`` and
``memory_source``. It starts no network listener and has no mutation path.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .desktop_service import DEFAULT_DATA_ROOT
from .store import LocalMemoryError, LocalMemoryStore

MAX_RESPONSE_BYTES = 64 * 1024


class ReadOnlyMemoryTools:
    """Machine-facing read-only façade over ``LocalMemoryStore``."""

    def __init__(self, store: LocalMemoryStore) -> None:
        self._store = store

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict) or set(request) != {"tool", "params"}:
            raise LocalMemoryError("request must contain exactly tool and params")
        tool = request["tool"]
        params = request["params"]
        if not isinstance(tool, str) or not isinstance(params, dict):
            raise LocalMemoryError("request tool and params are invalid")
        if tool == "memory_recall":
            return self._recall(params)
        if tool == "memory_source":
            return self._source(params)
        raise LocalMemoryError("only memory_recall and memory_source are available")

    def _recall(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) - {"query", "limit"}:
            raise LocalMemoryError("memory_recall received unsupported parameters")
        query = params.get("query")
        if not isinstance(query, str) or not query.strip():
            raise LocalMemoryError("memory_recall query is required")
        limit_value = params.get("limit", 10)
        if isinstance(limit_value, str) and limit_value.isdecimal():
            limit = int(limit_value)
        elif isinstance(limit_value, int) and not isinstance(limit_value, bool):
            limit = limit_value
        else:
            raise LocalMemoryError("memory_recall limit must be an integer")
        hits = self._store.recall(query, limit=min(max(limit, 1), 20))
        result = {
            "tool": "memory_recall",
            "authority": "ENCRYPTED_LIFECYCLE_CORE",
            "query": query,
            "results": [
                {
                    "memory_id": hit.memory_id,
                    "title": hit.source_name,
                    "content": hit.content,
                    "content_sha256": hit.content_sha256,
                    "updated_at": hit.updated_at,
                    "score": hit.score,
                    "artifact_id": hit.artifact_id,
                    "revision_id": hit.revision_id,
                }
                for hit in hits
            ],
        }
        return _bound_response(result)

    def _source(self, params: dict[str, Any]) -> dict[str, Any]:
        if set(params) != {"memory_id"}:
            raise LocalMemoryError("memory_source requires exactly memory_id")
        memory_id = params.get("memory_id")
        if not isinstance(memory_id, str) or not memory_id:
            raise LocalMemoryError("memory_source memory_id is required")
        hit = self._store.get(memory_id)
        citation = self._store.citation(memory_id)
        result = {
            "tool": "memory_source",
            "authority": "ENCRYPTED_LIFECYCLE_CORE",
            "memory": hit.to_mapping(),
            "citation": citation,
        }
        return _bound_response(result)


def _serialized_size(value: dict[str, Any]) -> int:
    return len(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )


def _bound_response(value: dict[str, Any]) -> dict[str, Any]:
    """Keep machine responses below the existing 64 KiB read contract."""
    if _serialized_size(value) <= MAX_RESPONSE_BYTES:
        return value
    bounded = json.loads(json.dumps(value, ensure_ascii=False))
    if bounded.get("tool") == "memory_recall":
        results = bounded.get("results", [])
        while results and _serialized_size(bounded) > MAX_RESPONSE_BYTES:
            last = results[-1]
            content = last.get("content", "") if isinstance(last, dict) else ""
            if isinstance(content, str) and len(content) > 512:
                last["content"] = content[: max(512, len(content) // 2)]
                last["truncated"] = True
            else:
                results.pop()
        bounded["has_more"] = True
    elif bounded.get("tool") == "memory_source":
        memory = bounded.get("memory", {})
        if isinstance(memory, dict) and isinstance(memory.get("content"), str):
            memory["content"] = memory["content"][:16_384]
            memory["truncated"] = True
    if _serialized_size(bounded) > MAX_RESPONSE_BYTES:
        raise LocalMemoryError("read-only response exceeds the 64 KiB limit")
    return bounded


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiki-memory-read",
        description="read-only local memory tools for AI clients",
    )
    parser.add_argument("--root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--request", help="one JSON request; otherwise read one line from stdin")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    raw = args.request if args.request is not None else sys.stdin.readline()
    try:
        request = json.loads(raw)
        store = LocalMemoryStore(args.root)
        try:
            response = ReadOnlyMemoryTools(store).handle(request)
        finally:
            store.close()
    except (json.JSONDecodeError, LocalMemoryError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {"status": "ERROR", "message": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 2
    print(json.dumps(response, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
