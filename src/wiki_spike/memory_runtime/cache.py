"""P4-12 workspace-scoped deterministic model cache."""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Mapping

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_object, content_id, hex64, nonempty, safe_code

CACHE_ENTRY_VERSION = "phase4-model-cache-entry-v1"


@dataclass(frozen=True)
class CacheEntry:
    cache_entry_version: str
    cache_key: str
    workspace_id: str
    route_id: str
    generation_id: str
    request_digest: str
    response: dict[str, JsonValue]
    response_digest: str

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        route_id: str,
        generation_id: str,
        request_digest: str,
        response: Mapping[str, object],
    ) -> "CacheEntry":
        value = canonical_object(response, "response")
        response_digest = content_id("wiki.runtime.model-response.v1", value)
        identity = {
            "workspace_id": workspace_id,
            "route_id": route_id,
            "generation_id": generation_id,
            "request_digest": request_digest,
        }
        return cls(
            cache_entry_version=CACHE_ENTRY_VERSION,
            cache_key=content_id("wiki.runtime.model-cache-key.v1", identity),
            workspace_id=workspace_id,
            route_id=route_id,
            generation_id=generation_id,
            request_digest=request_digest,
            response=value,
            response_digest=response_digest,
        )

    def __post_init__(self) -> None:
        if self.cache_entry_version != CACHE_ENTRY_VERSION:
            raise InvalidContractValue("unsupported cache entry version")
        nonempty(self.workspace_id, "workspace_id")
        hex64(self.route_id, "route_id")
        nonempty(self.generation_id, "generation_id")
        hex64(self.request_digest, "request_digest")
        if self.response_digest != content_id("wiki.runtime.model-response.v1", self.response):
            raise InvalidContractValue("cache response digest mismatch")
        expected = content_id("wiki.runtime.model-cache-key.v1", {
            "workspace_id": self.workspace_id,
            "route_id": self.route_id,
            "generation_id": self.generation_id,
            "request_digest": self.request_digest,
        })
        if self.cache_key != expected:
            raise InvalidContractValue("cache key mismatch")



class ModelCache:
    def __init__(self) -> None:
        self._values: dict[tuple[str, str], CacheEntry] = {}

    def get(self, workspace_id: str, cache_key: str, *, golden_eval: bool = False) -> CacheEntry | None:
        if golden_eval:
            return None
        return self._values.get((workspace_id, cache_key))

    def put(self, entry: CacheEntry, *, golden_eval: bool = False) -> None:
        if golden_eval:
            return
        key = (entry.workspace_id, entry.cache_key)
        existing = self._values.get(key)
        if existing is not None and existing.response_digest != entry.response_digest:
            raise InvalidContractValue("nondeterministic cache entry")
        self._values.setdefault(key, entry)


__all__ = ["CACHE_ENTRY_VERSION", "CacheEntry", "ModelCache"]
