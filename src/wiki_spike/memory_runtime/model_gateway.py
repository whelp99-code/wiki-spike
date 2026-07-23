"""P4-12 provider-neutral exact-route ModelGateway."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Mapping, Protocol

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_runtime.errors import InvalidContractValue
from .cache import CacheEntry, ModelCache
from .cost import CostContext, CostTracker
from .service_contracts import canonical_object, content_id, verify_content_id, ensure_no_secret_keys, hex64, nonempty, safe_code

MODEL_ROUTE_VERSION = "phase4-model-route-v1"
MODEL_CALL_RESULT_VERSION = "phase4-model-call-result-v1"
_EXACT_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")


class ModelErrorClass(str, Enum):
    TRANSIENT = "transient"
    FATAL = "fatal"


class ModelGatewayError(RuntimeError):
    def __init__(self, code: str, error_class: ModelErrorClass) -> None:
        super().__init__(code)
        self.code = safe_code(code, "model_error_code")
        self.error_class = error_class


@dataclass(frozen=True)
class ModelRoute:
    model_route_version: str
    route_id: str
    provider_id: str
    purpose: str
    exact_model_id: str
    prompt_version: str
    policy_version: str
    enabled: bool
    shadow: bool

    @classmethod
    def create(cls, **kwargs: object) -> "ModelRoute":
        payload = {"model_route_version": MODEL_ROUTE_VERSION, **kwargs}
        return cls(route_id=content_id("wiki.runtime.model-route.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.model_route_version != MODEL_ROUTE_VERSION:
            raise InvalidContractValue("unsupported model route version")
        safe_code(self.provider_id, "provider_id")
        safe_code(self.purpose, "purpose")
        nonempty(self.prompt_version, "prompt_version")
        nonempty(self.policy_version, "policy_version")
        if not isinstance(self.exact_model_id, str) or not _EXACT_MODEL.fullmatch(self.exact_model_id):
            raise InvalidContractValue("exact_model_id is malformed")
        lowered = self.exact_model_id.lower()
        if lowered in {"latest", "default", "auto"} or lowered.endswith(":latest") or "*" in lowered:
            raise InvalidContractValue("model aliases/latest/wildcards are forbidden")
        if not isinstance(self.enabled, bool) or not isinstance(self.shadow, bool):
            raise InvalidContractValue("route flags must be boolean")
        verify_content_id(self.route_id, "wiki.runtime.model-route.v1", self.to_mapping(), "route_id", "model route_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "model_route_version": self.model_route_version,
            "route_id": self.route_id,
            "provider_id": self.provider_id,
            "purpose": self.purpose,
            "exact_model_id": self.exact_model_id,
            "prompt_version": self.prompt_version,
            "policy_version": self.policy_version,
            "enabled": self.enabled,
            "shadow": self.shadow,
        }


class ModelProvider(Protocol):
    def complete(self, route: ModelRoute, request: Mapping[str, object]) -> tuple[Mapping[str, object], str]: ...


@dataclass(frozen=True)
class ModelCallResult:
    model_call_result_version: str
    result_id: str
    route_id: str
    request_digest: str
    response_digest: str | None
    status: str
    error_class: str | None
    error_code: str | None
    cost_micros: str
    cache_hit: bool

    @classmethod
    def create(cls, **kwargs: object) -> "ModelCallResult":
        payload = {"model_call_result_version": MODEL_CALL_RESULT_VERSION, **kwargs}
        return cls(result_id=content_id("wiki.runtime.model-call-result.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.model_call_result_version != MODEL_CALL_RESULT_VERSION:
            raise InvalidContractValue("unsupported model call result version")
        hex64(self.route_id, "route_id")
        hex64(self.request_digest, "request_digest")
        if self.response_digest is not None:
            hex64(self.response_digest, "response_digest")
        if self.status not in {"ok", "shadow_ok", "retry_later", "failed", "disabled"}:
            raise InvalidContractValue("unsupported model call status")
        if self.error_class is not None:
            ModelErrorClass(self.error_class)
        if self.status in {"ok", "shadow_ok"} and self.response_digest is None:
            raise InvalidContractValue("successful model call requires response_digest")
        verify_content_id(self.result_id, "wiki.runtime.model-call-result.v1", self.to_mapping(), "result_id", "model call result_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "model_call_result_version": self.model_call_result_version,
            "result_id": self.result_id,
            "route_id": self.route_id,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "status": self.status,
            "error_class": self.error_class,
            "error_code": self.error_code,
            "cost_micros": self.cost_micros,
            "cache_hit": self.cache_hit,
        }



@dataclass(frozen=True)
class GatewayResponse:
    metadata: ModelCallResult
    output: dict[str, JsonValue] | None


class ModelGateway:
    def __init__(self, providers: Mapping[str, ModelProvider], tracker: CostTracker, cache: ModelCache) -> None:
        self.providers = dict(providers)
        self.tracker = tracker
        self.cache = cache

    @staticmethod
    def classify_http(status: int) -> ModelErrorClass:
        if status == 429 or status >= 500:
            return ModelErrorClass.TRANSIENT
        return ModelErrorClass.FATAL

    def call(
        self,
        *,
        route: ModelRoute,
        request: Mapping[str, object],
        workspace_id: str,
        generation_id: str,
        cost_context: CostContext,
        estimated_cost_micros: str,
        golden_eval: bool = False,
    ) -> GatewayResponse:
        stable_request = canonical_object(request, "model request")
        ensure_no_secret_keys(stable_request, label="model request")
        request_digest = content_id("wiki.runtime.model-request.v1", stable_request)
        cache_key = content_id("wiki.runtime.model-cache-key.v1", {
            "workspace_id": workspace_id,
            "route_id": route.route_id,
            "generation_id": generation_id,
            "request_digest": request_digest,
        })
        cached = self.cache.get(workspace_id, cache_key, golden_eval=golden_eval)
        if cached is not None:
            return GatewayResponse(
                ModelCallResult.create(
                    route_id=route.route_id,
                    request_digest=request_digest,
                    response_digest=cached.response_digest,
                    status="ok",
                    error_class=None,
                    error_code=None,
                    cost_micros="0",
                    cache_hit=True,
                ),
                dict(cached.response),
            )
        if not route.enabled:
            return GatewayResponse(
                ModelCallResult.create(
                    route_id=route.route_id,
                    request_digest=request_digest,
                    response_digest=None,
                    status="disabled",
                    error_class=None,
                    error_code="route_disabled",
                    cost_micros="0",
                    cache_hit=False,
                ),
                None,
            )
        self.tracker.reserve(cost_context, estimated_cost_micros)
        provider = self.providers.get(route.provider_id)
        if provider is None:
            return GatewayResponse(
                ModelCallResult.create(
                    route_id=route.route_id,
                    request_digest=request_digest,
                    response_digest=None,
                    status="failed",
                    error_class=ModelErrorClass.FATAL.value,
                    error_code="provider_missing",
                    cost_micros=estimated_cost_micros,
                    cache_hit=False,
                ),
                None,
            )
        try:
            output_raw, actual_cost = provider.complete(route, stable_request)
            output = canonical_object(output_raw, "model response")
            actual_cost_value = str(int(actual_cost))
        except ModelGatewayError as exc:
            status = "retry_later" if exc.error_class is ModelErrorClass.TRANSIENT else "failed"
            return GatewayResponse(
                ModelCallResult.create(
                    route_id=route.route_id,
                    request_digest=request_digest,
                    response_digest=None,
                    status=status,
                    error_class=exc.error_class.value,
                    error_code=exc.code,
                    cost_micros=estimated_cost_micros,
                    cache_hit=False,
                ),
                None,
            )
        entry = CacheEntry.create(
            workspace_id=workspace_id,
            route_id=route.route_id,
            generation_id=generation_id,
            request_digest=request_digest,
            response=output,
        )
        self.cache.put(entry, golden_eval=golden_eval)
        status = "shadow_ok" if route.shadow else "ok"
        return GatewayResponse(
            ModelCallResult.create(
                route_id=route.route_id,
                request_digest=request_digest,
                response_digest=entry.response_digest,
                status=status,
                error_class=None,
                error_code=None,
                cost_micros=actual_cost_value,
                cache_hit=False,
            ),
            output,
        )


__all__ = [
    "MODEL_ROUTE_VERSION", "MODEL_CALL_RESULT_VERSION", "ModelErrorClass",
    "ModelGatewayError", "ModelRoute", "ModelProvider", "ModelCallResult",
    "GatewayResponse", "ModelGateway",
]
