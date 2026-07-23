"""P4-11 content-bound ActionIntent contract.  Runtime never executes it."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_object, content_id, verify_content_id, ensure_no_secret_keys, hex64, nonempty, safe_code, string_tuple, utc_second

ACTION_INTENT_VERSION = "phase4-action-intent-v1"


@dataclass(frozen=True)
class ActionIntent:
    action_intent_version: str
    action_intent_id: str
    operation_id: str
    workspace_id: str
    action_type: str
    parameters: dict[str, object]
    evidence_refs: tuple[str, ...]
    created_at: str
    expires_at: str
    confirmation_requirement: str
    execution_state: str

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        workspace_id: str,
        action_type: str,
        parameters: Mapping[str, object],
        evidence_refs: Sequence[str],
        created_at: str,
        expires_at: str,
    ) -> "ActionIntent":
        normalized = canonical_object(parameters, "parameters")
        ensure_no_secret_keys(normalized, label="action parameters")
        refs = tuple(sorted(set(evidence_refs)))
        payload = {
            "action_intent_version": ACTION_INTENT_VERSION,
            "operation_id": operation_id,
            "workspace_id": workspace_id,
            "action_type": action_type,
            "parameters": normalized,
            "evidence_refs": list(refs),
            "created_at": created_at,
            "expires_at": expires_at,
            "confirmation_requirement": "explicit",
            "execution_state": "not_executed",
        }
        return cls(action_intent_id=content_id("wiki.runtime.action-intent.v1", payload), parameters=normalized, evidence_refs=refs, **{k: v for k, v in payload.items() if k not in {"parameters", "evidence_refs"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.action_intent_version != ACTION_INTENT_VERSION:
            raise InvalidContractValue("unsupported action intent version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.workspace_id, "workspace_id")
        safe_code(self.action_type, "action_type")
        ensure_no_secret_keys(self.parameters, label="action parameters")
        string_tuple(self.evidence_refs, "evidence_refs", allow_empty=False, sorted_unique=True)
        if utc_second(self.expires_at, "expires_at") <= utc_second(self.created_at, "created_at"):
            raise InvalidContractValue("action intent expiry must be after creation")
        if self.confirmation_requirement != "explicit" or self.execution_state != "not_executed":
            raise InvalidContractValue("Runtime action intents require explicit confirmation and no execution")
        verify_content_id(self.action_intent_id, "wiki.runtime.action-intent.v1", self.to_mapping(), "action_intent_id", "action intent_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "action_intent_version": self.action_intent_version,
            "action_intent_id": self.action_intent_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "action_type": self.action_type,
            "parameters": self.parameters,
            "evidence_refs": list(self.evidence_refs),
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "confirmation_requirement": self.confirmation_requirement,
            "execution_state": self.execution_state,
        }


__all__ = ["ACTION_INTENT_VERSION", "ActionIntent"]
