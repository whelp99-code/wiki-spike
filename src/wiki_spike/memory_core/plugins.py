"""Fail-closed PluginGateway contracts for out-of-process extensions."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
from threading import RLock
from typing import Callable, Mapping, Protocol

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from .policy import CapabilityToken, PolicyEngine, PolicyRequest, Sensitivity

PLUGIN_MANIFEST_VERSION = "phase3-plugin-manifest-v1"
PLUGIN_REQUEST_VERSION = "phase3-plugin-request-v1"
PLUGIN_RESPONSE_VERSION = "phase3-plugin-response-v1"


def _positive_integer(value: str, field: str, *, maximum: int | None = None) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise InvalidContractValue(f"{field} must be a canonical positive integer string")
    parsed = int(value)
    if maximum is not None and parsed > maximum:
        raise InvalidContractValue(f"{field} exceeds maximum {maximum}")
    return parsed


def _string_sequence(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array of strings")
    result = tuple(value)
    if not result or any(not isinstance(item, str) or not item for item in result):
        raise InvalidContractValue(f"{field} must be non-empty strings")
    return result


class EgressClass(str, Enum):
    NONE = "none"
    PUBLIC = "public"
    INTERNAL = "internal"
    PRIVATE = "private"
    RESTRICTED = "secret"

    @property
    def rank(self) -> int:
        return {
            EgressClass.NONE: -1,
            EgressClass.PUBLIC: 0,
            EgressClass.INTERNAL: 1,
            EgressClass.PRIVATE: 2,
            EgressClass.RESTRICTED: 3,
        }[self]


@dataclass(frozen=True)
class PluginManifest:
    plugin_schema_version: str
    manifest_id: str
    plugin_id: str
    plugin_version: str
    runner_mode: str
    allowed_operations: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    egress_class: str
    max_request_bytes: str
    max_response_bytes: str
    timeout_ms: str
    max_calls_per_operation: str
    output_schema_id: str

    FIELDS = {
        "plugin_schema_version", "manifest_id", "plugin_id", "plugin_version",
        "runner_mode", "allowed_operations", "required_capabilities", "egress_class",
        "max_request_bytes", "max_response_bytes", "timeout_ms",
        "max_calls_per_operation", "output_schema_id",
    }

    @staticmethod
    def _identity(values: Mapping[str, object]) -> dict[str, object]:
        return {key: values[key] for key in PluginManifest.FIELDS - {"manifest_id"}}

    def __post_init__(self) -> None:
        if self.plugin_schema_version != PLUGIN_MANIFEST_VERSION:
            raise UnsupportedContractVersion("unsupported plugin manifest version")
        for field in ("plugin_id", "plugin_version", "output_schema_id"):
            if not isinstance(getattr(self, field), str) or not getattr(self, field):
                raise InvalidContractValue(f"{field} must be a non-empty string")
        if self.runner_mode != "out_of_process":
            raise InvalidContractValue("plugins must use out_of_process runner mode")
        for name, values in (
            ("allowed_operations", self.allowed_operations),
            ("required_capabilities", self.required_capabilities),
        ):
            if not values or tuple(sorted(set(values))) != values:
                raise InvalidContractValue(f"{name} must be sorted, unique, and non-empty")
            if any(not isinstance(item, str) or not item for item in values):
                raise InvalidContractValue(f"{name} contains an invalid value")
        EgressClass(self.egress_class)
        _positive_integer(self.max_request_bytes, "max_request_bytes")
        _positive_integer(self.max_response_bytes, "max_response_bytes")
        _positive_integer(self.timeout_ms, "timeout_ms", maximum=120000)
        _positive_integer(self.max_calls_per_operation, "max_calls_per_operation")
        expected = sha256(canonical_bytes(self._identity(self.to_mapping()))).hexdigest()
        if self.manifest_id != expected:
            raise InvalidContractValue("manifest_id does not match canonical manifest")

    @classmethod
    def create(cls, **kwargs):
        values = {"plugin_schema_version": PLUGIN_MANIFEST_VERSION, **kwargs}
        values["allowed_operations"] = tuple(
            sorted(set(_string_sequence(values["allowed_operations"], "allowed_operations")))
        )
        values["required_capabilities"] = tuple(
            sorted(set(_string_sequence(values["required_capabilities"], "required_capabilities")))
        )
        identity = cls._identity({**values, "manifest_id": ""})
        return cls(manifest_id=sha256(canonical_bytes(identity)).hexdigest(), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "PluginManifest":
        unknown = set(data) - cls.FIELDS
        missing = cls.FIELDS - set(data)
        if unknown:
            raise UnknownContractField(f"unknown plugin manifest fields: {sorted(unknown)}")
        if missing:
            raise InvalidContractValue(f"missing plugin manifest fields: {sorted(missing)}")
        values = dict(data)
        values["allowed_operations"] = _string_sequence(
            values["allowed_operations"], "allowed_operations"
        )
        values["required_capabilities"] = _string_sequence(
            values["required_capabilities"], "required_capabilities"
        )
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "plugin_schema_version": self.plugin_schema_version,
            "manifest_id": self.manifest_id,
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "runner_mode": self.runner_mode,
            "allowed_operations": list(self.allowed_operations),
            "required_capabilities": list(self.required_capabilities),
            "egress_class": self.egress_class,
            "max_request_bytes": self.max_request_bytes,
            "max_response_bytes": self.max_response_bytes,
            "timeout_ms": self.timeout_ms,
            "max_calls_per_operation": self.max_calls_per_operation,
            "output_schema_id": self.output_schema_id,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class PluginRequest:
    plugin_request_version: str
    request_id: str
    plugin_id: str
    plugin_version: str
    workspace_id: str
    actor_id: str
    operation_id: str
    operation_type: str
    capability_token_ref: str
    sensitivity: str
    deadline_at: str
    correlation_id: str
    payload: dict[str, JsonValue]

    FIELDS = {
        "plugin_request_version", "request_id", "plugin_id", "plugin_version",
        "workspace_id", "actor_id", "operation_id", "operation_type",
        "capability_token_ref", "sensitivity", "deadline_at", "correlation_id", "payload",
    }

    def __post_init__(self) -> None:
        if self.plugin_request_version != PLUGIN_REQUEST_VERSION:
            raise UnsupportedContractVersion("unsupported plugin request version")
        for field in self.FIELDS - {"payload"}:
            if not isinstance(getattr(self, field), str) or not getattr(self, field):
                raise InvalidContractValue(f"{field} must be a non-empty string")
        Sensitivity(self.sensitivity)
        if not isinstance(self.payload, dict):
            raise InvalidContractValue("plugin payload must be an object")
        normalized = json.loads(canonical_bytes({"payload": self.payload}))
        object.__setattr__(self, "payload", normalized["payload"])

    @classmethod
    def create(cls, **kwargs):
        return cls(plugin_request_version=PLUGIN_REQUEST_VERSION, **kwargs)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "PluginRequest":
        unknown = set(data) - cls.FIELDS
        missing = cls.FIELDS - set(data)
        if unknown:
            raise UnknownContractField(f"unknown plugin request fields: {sorted(unknown)}")
        if missing:
            raise InvalidContractValue(f"missing plugin request fields: {sorted(missing)}")
        values = dict(data)
        if not isinstance(values["payload"], dict):
            raise InvalidContractValue("plugin payload must be an object")
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "plugin_request_version": self.plugin_request_version,
            "request_id": self.request_id,
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "capability_token_ref": self.capability_token_ref,
            "sensitivity": self.sensitivity,
            "deadline_at": self.deadline_at,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class PluginInvocationResult:
    status: str
    request_id: str
    plugin_id: str
    output: dict[str, JsonValue]
    output_digest: str | None
    error_code: str | None


class PluginRunner(Protocol):
    def invoke(self, manifest: PluginManifest, request_bytes: bytes, timeout_ms: int) -> bytes: ...


class PluginOutputValidator(Protocol):
    def validate(self, schema_id: str, output: Mapping[str, JsonValue]) -> bool: ...


class PluginQuotaStore(Protocol):
    def consume(self, workspace_id: str, operation_id: str, plugin_id: str, limit: int) -> bool: ...


class InMemoryPluginQuotaStore:
    def __init__(self) -> None:
        self._counts: dict[tuple[str, str, str], int] = {}
        self._lock = RLock()

    def consume(self, workspace_id: str, operation_id: str, plugin_id: str, limit: int) -> bool:
        with self._lock:
            key = workspace_id, operation_id, plugin_id
            current = self._counts.get(key, 0)
            if current >= limit:
                return False
            self._counts[key] = current + 1
            return True


class InMemoryPluginOutputValidator:
    def __init__(self, validators: Mapping[str, Callable[[Mapping[str, JsonValue]], bool]]):
        self.validators = dict(validators)

    def validate(self, schema_id: str, output: Mapping[str, JsonValue]) -> bool:
        validator = self.validators.get(schema_id)
        return bool(validator and validator(output))


class PluginGateway:
    RESPONSE_FIELDS = {
        "plugin_response_version", "request_id", "plugin_id", "plugin_version",
        "output_schema_id", "output",
    }

    def __init__(
        self,
        runner: PluginRunner,
        output_validator: PluginOutputValidator,
        quota_store: PluginQuotaStore,
        *,
        now: str,
        policy: PolicyEngine | None = None,
    ) -> None:
        self.runner = runner
        self.output_validator = output_validator
        self.quota_store = quota_store
        self.now = now
        self.policy = policy or PolicyEngine()

    @staticmethod
    def _result(request: PluginRequest, status: str, error_code: str | None, output=None):
        value = output or {}
        digest = sha256(canonical_bytes({"output": value})).hexdigest() if status == "ok" else None
        return PluginInvocationResult(status, request.request_id, request.plugin_id, value, digest, error_code)

    def invoke(
        self,
        manifest: PluginManifest,
        request: PluginRequest,
        token: CapabilityToken,
    ) -> PluginInvocationResult:
        if request.plugin_id != manifest.plugin_id or request.plugin_version != manifest.plugin_version:
            return self._result(request, "rejected", "plugin_manifest_mismatch")
        if request.operation_type not in manifest.allowed_operations:
            return self._result(request, "rejected", "plugin_operation_denied")
        if self.now >= request.deadline_at:
            return self._result(request, "rejected", "plugin_deadline_expired")

        action = f"plugin.invoke:{manifest.plugin_id}"
        decision = self.policy.authorize(
            token,
            PolicyRequest(
                request.workspace_id,
                request.actor_id,
                action,
                self.now,
                Sensitivity(request.sensitivity),
            ),
        )
        if not decision.allowed:
            return self._result(request, "rejected", f"plugin_policy_{decision.reason.value}")
        if not set(manifest.required_capabilities).issubset(token.actions):
            return self._result(request, "rejected", "plugin_capability_missing")

        egress = EgressClass(manifest.egress_class)
        request_level = EgressClass(request.sensitivity)
        if egress is EgressClass.NONE and request.payload:
            return self._result(request, "rejected", "plugin_egress_denied")
        if egress is not EgressClass.NONE and request_level.rank > egress.rank:
            return self._result(request, "rejected", "plugin_egress_denied")

        request_bytes = request.canonical_bytes()
        if len(request_bytes) > _positive_integer(manifest.max_request_bytes, "max_request_bytes"):
            return self._result(request, "rejected", "plugin_request_oversized")
        if not self.quota_store.consume(
            request.workspace_id,
            request.operation_id,
            manifest.plugin_id,
            _positive_integer(manifest.max_calls_per_operation, "max_calls_per_operation"),
        ):
            return self._result(request, "rejected", "plugin_quota_exceeded")

        try:
            raw = self.runner.invoke(
                manifest,
                request_bytes,
                _positive_integer(manifest.timeout_ms, "timeout_ms", maximum=120000),
            )
        except TimeoutError:
            return self._result(request, "retry_later", "plugin_timeout")
        except Exception:
            return self._result(request, "retry_later", "plugin_crashed")

        if not isinstance(raw, bytes):
            return self._result(request, "rejected", "plugin_response_not_bytes")
        if len(raw) > _positive_integer(manifest.max_response_bytes, "max_response_bytes"):
            return self._result(request, "rejected", "plugin_response_oversized")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._result(request, "rejected", "plugin_response_malformed")
        if not isinstance(decoded, dict):
            return self._result(request, "rejected", "plugin_response_malformed")
        if set(decoded) != self.RESPONSE_FIELDS:
            return self._result(request, "rejected", "plugin_response_fields_invalid")
        if decoded["plugin_response_version"] != PLUGIN_RESPONSE_VERSION:
            return self._result(request, "rejected", "plugin_response_version_unsupported")
        if (
            decoded["request_id"] != request.request_id
            or decoded["plugin_id"] != manifest.plugin_id
            or decoded["plugin_version"] != manifest.plugin_version
            or decoded["output_schema_id"] != manifest.output_schema_id
        ):
            return self._result(request, "rejected", "plugin_response_binding_mismatch")
        output = decoded["output"]
        if not isinstance(output, dict):
            return self._result(request, "rejected", "plugin_output_invalid")
        try:
            normalized = json.loads(canonical_bytes({"output": output}))["output"]
        except ValueError:
            return self._result(request, "rejected", "plugin_output_invalid")
        if not self.output_validator.validate(manifest.output_schema_id, normalized):
            return self._result(request, "rejected", "plugin_output_schema_failed")
        return self._result(request, "ok", None, normalized)
