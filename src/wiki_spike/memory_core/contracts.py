"""Versioned, deterministic contracts shared by Phase 3 components.

This module intentionally depends only on the Python standard library so it can
be imported without any storage adapter or runtime implementation.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import unicodedata
from typing import Any, ClassVar, Mapping

from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

CONTRACT_VERSION = "phase3-core-v1"
JsonValue = None | bool | str | list["JsonValue"] | dict[str, "JsonValue"]


def _normalize(value: Any, path: str = "$") -> JsonValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (int, float)):
        raise InvalidContractValue(f"raw numbers are forbidden at {path}; use canonical strings")
    if isinstance(value, list):
        return [_normalize(item, f"{path}[{index}]") for index, item in enumerate(value)]
    if isinstance(value, Mapping):
        normalized: dict[str, JsonValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidContractValue(f"object key must be a string at {path}")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise InvalidContractValue(f"duplicate key after NFC normalization at {path}: {key!r}")
            normalized[normalized_key] = _normalize(item, f"{path}.{normalized_key}")
        return {key: normalized[key] for key in sorted(normalized)}
    raise InvalidContractValue(f"unsupported value at {path}: {type(value).__name__}")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    normalized = _normalize(value)
    return json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _strict_mapping(data: Mapping[str, Any], allowed: set[str], required: set[str]) -> dict[str, Any]:
    unknown = set(data) - allowed
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    missing = required - set(data)
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    version = data.get("contract_version")
    if version != CONTRACT_VERSION:
        raise UnsupportedContractVersion(f"unsupported contract_version: {version!r}")
    return dict(data)


@dataclass(frozen=True)
class CommandEnvelope:
    contract_version: str
    command_id: str
    idempotency_key: str
    workspace_id: str
    actor_id: str
    command_type: str
    expected_generation_id: str | None
    payload: dict[str, JsonValue]

    FIELDS: ClassVar[set[str]] = {
        "contract_version", "command_id", "idempotency_key", "workspace_id", "actor_id",
        "command_type", "expected_generation_id", "payload",
    }

    @classmethod
    def create(cls, **kwargs: Any) -> "CommandEnvelope":
        return cls.from_mapping({"contract_version": CONTRACT_VERSION, **kwargs})

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "CommandEnvelope":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS)
        payload = _normalize(values["payload"], "$.payload")
        if not isinstance(payload, dict):
            raise InvalidContractValue("payload must be an object")
        for field in cls.FIELDS - {"payload", "expected_generation_id"}:
            if not isinstance(values[field], str) or not values[field]:
                raise InvalidContractValue(f"{field} must be a non-empty string")
        expected = values["expected_generation_id"]
        if expected is not None and (not isinstance(expected, str) or not expected):
            raise InvalidContractValue("expected_generation_id must be null or a non-empty string")
        return cls(payload=payload, **{key: values[key] for key in cls.FIELDS - {"payload"}})

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "command_id": self.command_id,
            "idempotency_key": self.idempotency_key,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "command_type": self.command_type,
            "expected_generation_id": self.expected_generation_id,
            "payload": self.payload,
        }


@dataclass(frozen=True)
class QueryEnvelope:
    contract_version: str
    query_id: str
    workspace_id: str
    actor_id: str
    query_type: str
    as_of_generation_id: str
    consistency: str
    parameters: dict[str, JsonValue]

    FIELDS: ClassVar[set[str]] = {
        "contract_version", "query_id", "workspace_id", "actor_id", "query_type",
        "as_of_generation_id", "consistency", "parameters",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "QueryEnvelope":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS)
        params = _normalize(values["parameters"], "$.parameters")
        if not isinstance(params, dict):
            raise InvalidContractValue("parameters must be an object")
        for field in cls.FIELDS - {"parameters"}:
            if not isinstance(values[field], str) or not values[field]:
                raise InvalidContractValue(f"{field} must be a non-empty string")
        if values["consistency"] not in {"authoritative", "projection_ok"}:
            raise InvalidContractValue("consistency must be authoritative or projection_ok")
        return cls(parameters=params, **{key: values[key] for key in cls.FIELDS - {"parameters"}})

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())

    def to_mapping(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "query_id": self.query_id,
            "workspace_id": self.workspace_id,
            "actor_id": self.actor_id,
            "query_type": self.query_type,
            "as_of_generation_id": self.as_of_generation_id,
            "consistency": self.consistency,
            "parameters": self.parameters,
        }


@dataclass(frozen=True)
class CoreResult:
    contract_version: str
    request_id: str
    status: str
    generation_id: str | None
    result: dict[str, JsonValue]
    error_code: str | None = None

    def to_mapping(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "request_id": self.request_id,
            "status": self.status,
            "generation_id": self.generation_id,
            "result": _normalize(self.result, "$.result"),
            "error_code": self.error_code,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class OperationalEvent:
    contract_version: str
    event_id: str
    event_type: str
    workspace_id: str
    generation_id: str | None
    payload: dict[str, JsonValue]

    def canonical_bytes(self) -> bytes:
        return canonical_bytes({
            "contract_version": self.contract_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "workspace_id": self.workspace_id,
            "generation_id": self.generation_id,
            "payload": self.payload,
        })


@dataclass(frozen=True)
class AcceptedChangeSet:
    contract_version: str
    changeset_id: str
    workspace_id: str
    parent_generation_id: str | None
    command_ids: tuple[str, ...]
    object_refs: tuple[str, ...]
    changes_root: str

    def canonical_bytes(self) -> bytes:
        return canonical_bytes({
            "contract_version": self.contract_version,
            "changeset_id": self.changeset_id,
            "workspace_id": self.workspace_id,
            "parent_generation_id": self.parent_generation_id,
            "command_ids": list(self.command_ids),
            "object_refs": list(self.object_refs),
            "changes_root": self.changes_root,
        })
