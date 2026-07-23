"""Deterministic intent and temporal planning contracts for P4-02.

P4-02 intentionally performs only conservative, policy-independent resolution.
It never calls a model, reads Storage, or executes an external action. Ambiguity is
represented explicitly for the later clarification stage instead of being guessed.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
import re
import unicodedata
from typing import ClassVar, Mapping

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_runtime.contracts import canonical_bytes, parse_utc_timestamp
from wiki_spike.memory_runtime.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_runtime.orchestrator import (
    FatalStageError,
    RuntimeOperationInput,
    RuntimeStageResult,
    StageDisposition,
    StageExecutionContext,
)
from wiki_spike.memory_runtime.temporal import TemporalResolution, TemporalResolver

INTENT_TEMPORAL_INPUT_VERSION = "phase4-intent-temporal-input-v1"
INTENT_RESOLUTION_VERSION = "phase4-intent-resolution-v1"
INTENT_TEMPORAL_RESOLUTION_VERSION = "phase4-intent-temporal-resolution-v1"
INTENT_TEMPORAL_STAGE_SCHEMA_ID = INTENT_TEMPORAL_RESOLUTION_VERSION

_INPUT_DOMAIN = b"wiki.runtime.intent-temporal-input.v1\x00"
_INTENT_DOMAIN = b"wiki.runtime.intent-resolution.v1\x00"
_COMBINED_DOMAIN = b"wiki.runtime.intent-temporal-resolution.v1\x00"
_QUERY_DOMAIN = b"wiki.runtime.intent-query.v1\x00"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")


class IntentClassification(str, Enum):
    RECALL = "recall"
    ASK = "ask"
    EXTRACT_DECISION = "extract_decision"
    CLARIFY = "clarify"
    PROACTIVE_EVALUATE = "proactive_evaluate"
    AMBIGUOUS = "ambiguous"


class IntentSource(str, Enum):
    REQUEST_TYPE = "request_type"
    EXPLICIT_HINT = "explicit_hint"
    UNRESOLVED = "unresolved"


_REQUEST_TYPE_INTENTS: dict[str, IntentClassification | None] = {
    "recall": IntentClassification.RECALL,
    "memory.recall": IntentClassification.RECALL,
    "ask": IntentClassification.ASK,
    "memory.ask": IntentClassification.ASK,
    "extract_decision": IntentClassification.EXTRACT_DECISION,
    "decision.extract": IntentClassification.EXTRACT_DECISION,
    "clarify": IntentClassification.CLARIFY,
    "memory.clarify": IntentClassification.CLARIFY,
    "proactive_evaluate": IntentClassification.PROACTIVE_EVALUATE,
    "proactive.evaluate": IntentClassification.PROACTIVE_EVALUATE,
    "runtime.resolve": None,
    "memory.resolve": None,
}
_QUERY_REQUIRED = frozenset(
    {
        IntentClassification.RECALL,
        IntentClassification.ASK,
        IntentClassification.EXTRACT_DECISION,
        IntentClassification.CLARIFY,
    }
)


def _nonempty(value: object, field: str, *, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be a non-empty string")
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or not normalized.strip() or len(normalized) > maximum:
        raise InvalidContractValue(f"{field} must be a bounded non-empty string")
    return normalized


def _optional_nonempty(value: object, field: str, *, maximum: int = 512) -> str | None:
    if value is None:
        return None
    return _nonempty(value, field, maximum=maximum)


def _safe_code(value: object, field: str) -> str:
    text = _nonempty(value, field, maximum=128)
    if not _SAFE_CODE.fullmatch(text):
        raise InvalidContractValue(f"{field} must be a lowercase Runtime code")
    return text


def _hex64(value: object, field: str) -> str:
    text = _nonempty(value, field, maximum=64)
    if not _HEX64.fullmatch(text):
        raise InvalidContractValue(f"{field} must be lowercase SHA-256 hex")
    return text


def _strict_mapping(data: Mapping[str, object], allowed: set[str], required: set[str], label: str) -> dict[str, object]:
    if not isinstance(data, Mapping):
        raise InvalidContractValue(f"{label} must be an object")
    unknown = set(data) - allowed
    missing = required - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def _reason_codes(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue("reason_codes must be an array")
    result = tuple(_safe_code(item, "reason_code") for item in value)
    if tuple(sorted(set(result))) != result:
        raise InvalidContractValue("reason_codes must be sorted and unique")
    return result


def _hash(domain: bytes, payload: Mapping[str, object]) -> str:
    return sha256(domain + canonical_bytes(payload)).hexdigest()


@dataclass(frozen=True)
class IntentTemporalInput:
    intent_temporal_input_version: str
    input_id: str
    operation_id: str
    request_type: str
    query_text: str | None
    intent_hint: str | None
    timezone: str
    as_of_at: str
    temporal_expression: str | None
    temporal_fold: str | None

    FIELDS: ClassVar[set[str]] = {
        "intent_temporal_input_version", "input_id", "operation_id", "request_type",
        "query_text", "intent_hint", "timezone", "as_of_at", "temporal_expression",
        "temporal_fold",
    }
    PAYLOAD_FIELDS: ClassVar[set[str]] = {
        "query_text", "intent_hint", "timezone", "as_of_at", "temporal_expression",
        "temporal_fold",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {key: values[key] for key in IntentTemporalInput.FIELDS - {"input_id"}}

    def __post_init__(self) -> None:
        if self.intent_temporal_input_version != INTENT_TEMPORAL_INPUT_VERSION:
            raise UnsupportedContractVersion("unsupported intent-temporal input version")
        _hex64(self.operation_id, "operation_id")
        object.__setattr__(self, "request_type", _safe_code(self.request_type, "request_type"))
        object.__setattr__(self, "query_text", _optional_nonempty(self.query_text, "query_text", maximum=8192))
        if self.intent_hint is not None:
            try:
                hint = IntentClassification(_safe_code(self.intent_hint, "intent_hint"))
            except ValueError as exc:
                raise InvalidContractValue("intent_hint is unsupported") from exc
            if hint is IntentClassification.AMBIGUOUS:
                raise InvalidContractValue("intent_hint cannot assert ambiguous")
            object.__setattr__(self, "intent_hint", hint.value)
        object.__setattr__(self, "timezone", _nonempty(self.timezone, "timezone", maximum=128))
        parse_utc_timestamp(self.as_of_at, "as_of_at")
        object.__setattr__(
            self,
            "temporal_expression",
            _optional_nonempty(self.temporal_expression, "temporal_expression", maximum=256),
        )
        if self.temporal_fold not in {None, "0", "1"}:
            raise InvalidContractValue("temporal_fold must be null, 0, or 1")
        expected = _hash(_INPUT_DOMAIN, self.identity(self.to_mapping()))
        if self.input_id != expected:
            raise InvalidContractValue("input_id does not match canonical intent-temporal input")

    @classmethod
    def create(cls, **kwargs: object) -> "IntentTemporalInput":
        values = {"intent_temporal_input_version": INTENT_TEMPORAL_INPUT_VERSION, **kwargs}
        identity = cls.identity({**values, "input_id": ""})
        return cls(input_id=_hash(_INPUT_DOMAIN, identity), **values)  # type: ignore[arg-type]

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "IntentTemporalInput":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, "intent-temporal input")
        return cls(**values)  # type: ignore[arg-type]

    @classmethod
    def from_operation(cls, operation: RuntimeOperationInput) -> "IntentTemporalInput":
        payload = operation.payload.get("intent_temporal")
        values = _strict_mapping(
            payload if isinstance(payload, Mapping) else {},
            cls.PAYLOAD_FIELDS,
            cls.PAYLOAD_FIELDS,
            "intent_temporal payload",
        )
        return cls.create(
            operation_id=operation.operation_id,
            request_type=operation.request_type,
            query_text=values["query_text"],
            intent_hint=values["intent_hint"],
            timezone=values["timezone"],
            as_of_at=values["as_of_at"],
            temporal_expression=values["temporal_expression"],
            temporal_fold=values["temporal_fold"],
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "intent_temporal_input_version": self.intent_temporal_input_version,
            "input_id": self.input_id,
            "operation_id": self.operation_id,
            "request_type": self.request_type,
            "query_text": self.query_text,
            "intent_hint": self.intent_hint,
            "timezone": self.timezone,
            "as_of_at": self.as_of_at,
            "temporal_expression": self.temporal_expression,
            "temporal_fold": self.temporal_fold,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class IntentResolution:
    intent_resolution_version: str
    resolution_id: str
    operation_id: str
    classification: str
    source: str
    query_digest: str | None
    requires_clarification: bool
    reason_codes: tuple[str, ...]

    FIELDS: ClassVar[set[str]] = {
        "intent_resolution_version", "resolution_id", "operation_id", "classification",
        "source", "query_digest", "requires_clarification", "reason_codes",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {key: values[key] for key in IntentResolution.FIELDS - {"resolution_id"}}

    def __post_init__(self) -> None:
        if self.intent_resolution_version != INTENT_RESOLUTION_VERSION:
            raise UnsupportedContractVersion("unsupported intent resolution version")
        _hex64(self.operation_id, "operation_id")
        try:
            classification = IntentClassification(self.classification)
            source = IntentSource(self.source)
        except ValueError as exc:
            raise InvalidContractValue("unsupported intent classification/source") from exc
        if self.query_digest is not None:
            _hex64(self.query_digest, "query_digest")
        if not isinstance(self.requires_clarification, bool):
            raise InvalidContractValue("requires_clarification must be boolean")
        reasons = _reason_codes(self.reason_codes)
        object.__setattr__(self, "reason_codes", reasons)
        if classification is IntentClassification.AMBIGUOUS:
            if not self.requires_clarification or source is not IntentSource.UNRESOLVED:
                raise InvalidContractValue("ambiguous intent must require clarification and use unresolved source")
            if not reasons:
                raise InvalidContractValue("ambiguous intent must carry a reason code")
        else:
            if self.requires_clarification:
                raise InvalidContractValue("resolved intent must not require clarification")
            if source is IntentSource.UNRESOLVED:
                raise InvalidContractValue("resolved intent must not use unresolved source")
            if reasons:
                raise InvalidContractValue("resolved intent must not carry ambiguity reasons")
            if classification in _QUERY_REQUIRED and self.query_digest is None:
                raise InvalidContractValue("query-required intent must carry query_digest")
        expected = _hash(_INTENT_DOMAIN, self.identity(self.to_mapping()))
        if self.resolution_id != expected:
            raise InvalidContractValue("intent resolution_id does not match canonical content")

    @classmethod
    def create(cls, **kwargs: object) -> "IntentResolution":
        values = {"intent_resolution_version": INTENT_RESOLUTION_VERSION, **kwargs}
        values["reason_codes"] = tuple(sorted(set(values.get("reason_codes", ()))))
        identity = cls.identity({**values, "resolution_id": ""})
        identity["reason_codes"] = list(values["reason_codes"])
        return cls(resolution_id=_hash(_INTENT_DOMAIN, identity), **values)  # type: ignore[arg-type]

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "IntentResolution":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, "intent resolution")
        values["reason_codes"] = _reason_codes(values["reason_codes"])
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "intent_resolution_version": self.intent_resolution_version,
            "resolution_id": self.resolution_id,
            "operation_id": self.operation_id,
            "classification": self.classification,
            "source": self.source,
            "query_digest": self.query_digest,
            "requires_clarification": self.requires_clarification,
            "reason_codes": list(self.reason_codes),
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class IntentResolver:
    def resolve(self, request: IntentTemporalInput) -> IntentResolution:
        request_type = request.request_type
        mapped = _REQUEST_TYPE_INTENTS.get(request_type)
        if request.intent_hint is not None:
            hinted = IntentClassification(request.intent_hint)
            if mapped is not None and mapped is not hinted:
                raise InvalidContractValue("intent_hint conflicts with request_type")
            classification = hinted
            source = IntentSource.EXPLICIT_HINT
        elif request_type in _REQUEST_TYPE_INTENTS and mapped is not None:
            classification = mapped
            source = IntentSource.REQUEST_TYPE
        else:
            classification = IntentClassification.AMBIGUOUS
            source = IntentSource.UNRESOLVED

        query_digest = (
            _hash(_QUERY_DOMAIN, {"query_text": request.query_text})
            if request.query_text is not None
            else None
        )
        if classification in _QUERY_REQUIRED and request.query_text is None:
            classification = IntentClassification.AMBIGUOUS
            source = IntentSource.UNRESOLVED
            reason_codes = ("query_text_missing",)
        elif classification is IntentClassification.AMBIGUOUS:
            reason_codes = ("intent_ambiguous",)
        else:
            reason_codes = ()
        return IntentResolution.create(
            operation_id=request.operation_id,
            classification=classification.value,
            source=source.value,
            query_digest=query_digest,
            requires_clarification=classification is IntentClassification.AMBIGUOUS,
            reason_codes=reason_codes,
        )


@dataclass(frozen=True)
class IntentTemporalResolution:
    intent_temporal_resolution_version: str
    resolution_id: str
    operation_id: str
    input_id: str
    intent: IntentResolution
    temporal: TemporalResolution
    requires_clarification: bool

    FIELDS: ClassVar[set[str]] = {
        "intent_temporal_resolution_version", "resolution_id", "operation_id", "input_id",
        "intent", "temporal", "requires_clarification",
    }

    @staticmethod
    def identity(values: Mapping[str, object]) -> dict[str, object]:
        return {key: values[key] for key in IntentTemporalResolution.FIELDS - {"resolution_id"}}

    def __post_init__(self) -> None:
        if self.intent_temporal_resolution_version != INTENT_TEMPORAL_RESOLUTION_VERSION:
            raise UnsupportedContractVersion("unsupported intent-temporal resolution version")
        _hex64(self.operation_id, "operation_id")
        _hex64(self.input_id, "input_id")
        if not isinstance(self.intent, IntentResolution) or not isinstance(self.temporal, TemporalResolution):
            raise InvalidContractValue("intent and temporal must be typed resolutions")
        if self.intent.operation_id != self.operation_id or self.temporal.operation_id != self.operation_id:
            raise InvalidContractValue("nested resolution operation_id mismatch")
        expected_clarification = self.intent.requires_clarification or self.temporal.requires_clarification
        if self.requires_clarification != expected_clarification:
            raise InvalidContractValue("combined clarification flag does not match nested resolutions")
        expected = _hash(_COMBINED_DOMAIN, self.identity(self.to_mapping()))
        if self.resolution_id != expected:
            raise InvalidContractValue("combined resolution_id does not match canonical content")

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        input_id: str,
        intent: IntentResolution,
        temporal: TemporalResolution,
    ) -> "IntentTemporalResolution":
        values: dict[str, object] = {
            "intent_temporal_resolution_version": INTENT_TEMPORAL_RESOLUTION_VERSION,
            "operation_id": operation_id,
            "input_id": input_id,
            "intent": intent,
            "temporal": temporal,
            "requires_clarification": intent.requires_clarification or temporal.requires_clarification,
        }
        identity = {
            "intent_temporal_resolution_version": values["intent_temporal_resolution_version"],
            "operation_id": operation_id,
            "input_id": input_id,
            "intent": intent.to_mapping(),
            "temporal": temporal.to_mapping(),
            "requires_clarification": values["requires_clarification"],
        }
        return cls(resolution_id=_hash(_COMBINED_DOMAIN, identity), **values)  # type: ignore[arg-type]

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "IntentTemporalResolution":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, "intent-temporal resolution")
        if not isinstance(values["intent"], Mapping) or not isinstance(values["temporal"], Mapping):
            raise InvalidContractValue("nested intent and temporal values must be objects")
        values["intent"] = IntentResolution.from_mapping(values["intent"])
        values["temporal"] = TemporalResolution.from_mapping(values["temporal"])
        return cls(**values)  # type: ignore[arg-type]

    def to_mapping(self) -> dict[str, object]:
        return {
            "intent_temporal_resolution_version": self.intent_temporal_resolution_version,
            "resolution_id": self.resolution_id,
            "operation_id": self.operation_id,
            "input_id": self.input_id,
            "intent": self.intent.to_mapping(),
            "temporal": self.temporal.to_mapping(),
            "requires_clarification": self.requires_clarification,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class IntentTemporalResolver:
    def __init__(
        self,
        *,
        intent_resolver: IntentResolver | None = None,
        temporal_resolver: TemporalResolver | None = None,
    ) -> None:
        self.intent_resolver = intent_resolver or IntentResolver()
        self.temporal_resolver = temporal_resolver or TemporalResolver()

    def resolve(self, request: IntentTemporalInput) -> IntentTemporalResolution:
        # Reparse the canonical representation so caller-owned objects cannot be
        # mutated after their content-bound input ID was established.
        stable = IntentTemporalInput.from_mapping(
            json.loads(request.canonical_bytes().decode("utf-8"))
        )
        intent = self.intent_resolver.resolve(stable)
        temporal = self.temporal_resolver.resolve(
            operation_id=stable.operation_id,
            timezone_name=stable.timezone,
            as_of_at=stable.as_of_at,
            explicit_expression=stable.temporal_expression,
            query_text=stable.query_text,
            temporal_fold=stable.temporal_fold,
        )
        return IntentTemporalResolution.create(
            operation_id=stable.operation_id,
            input_id=stable.input_id,
            intent=intent,
            temporal=temporal,
        )


class IntentTemporalStageHandler:
    stage_name = "planned"

    def __init__(self, resolver: IntentTemporalResolver | None = None) -> None:
        self.resolver = resolver or IntentTemporalResolver()

    def execute(self, context: StageExecutionContext) -> RuntimeStageResult:
        if context.stage_name != self.stage_name:
            raise FatalStageError("intent_temporal_stage_mismatch")
        try:
            input_value = IntentTemporalInput.from_operation(context.request)
            resolution = self.resolver.resolve(input_value)
        except (InvalidContractValue, UnknownContractField, UnsupportedContractVersion) as exc:
            raise FatalStageError("intent_temporal_invalid") from exc
        context.checkpoint()
        return RuntimeStageResult(
            stage_name=self.stage_name,
            payload=resolution.to_mapping(),  # type: ignore[arg-type]
            disposition=StageDisposition.CONTINUE,
            schema_id=INTENT_TEMPORAL_STAGE_SCHEMA_ID,
            provenance_refs=(f"runtime:intent-temporal:{resolution.resolution_id}",),
        )


__all__ = [
    "INTENT_TEMPORAL_INPUT_VERSION",
    "INTENT_RESOLUTION_VERSION",
    "INTENT_TEMPORAL_RESOLUTION_VERSION",
    "INTENT_TEMPORAL_STAGE_SCHEMA_ID",
    "IntentClassification",
    "IntentSource",
    "IntentTemporalInput",
    "IntentResolution",
    "IntentResolver",
    "IntentTemporalResolution",
    "IntentTemporalResolver",
    "IntentTemporalStageHandler",
]
