"""P4-03 deterministic Context Planner and egress policy boundary."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping, Protocol, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import (
    SENSITIVITY_RANK,
    canonical_int,
    canonical_object,
    content_id, verify_content_id,
    ensure_no_secret_keys,
    hex64,
    nonempty,
    safe_code,
    sensitivity,
    string_tuple,
)

CONTEXT_ITEM_VERSION = "phase4-context-item-v1"
CONTEXT_PLAN_VERSION = "phase4-context-plan-v1"
EGRESS_DECISION_VERSION = "phase4-egress-decision-v1"


class EgressRoute(str, Enum):
    LOCAL_ONLY = "local_only"
    PROVIDER = "provider"


@dataclass(frozen=True)
class ContextItem:
    context_item_version: str
    item_id: str
    ref_id: str
    purpose: str
    sensitivity: str
    token_count: str
    priority: str
    payload_digest: str
    available_fields: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        ref_id: str,
        purpose: str,
        sensitivity: str,
        token_count: str,
        priority: str,
        payload_digest: str,
        available_fields: Sequence[str],
    ) -> "ContextItem":
        fields = tuple(sorted(set(available_fields)))
        payload = {
            "context_item_version": CONTEXT_ITEM_VERSION,
            "ref_id": ref_id,
            "purpose": purpose,
            "sensitivity": sensitivity,
            "token_count": token_count,
            "priority": priority,
            "payload_digest": payload_digest,
            "available_fields": list(fields),
        }
        return cls(item_id=content_id("wiki.runtime.context-item.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.context_item_version != CONTEXT_ITEM_VERSION:
            raise InvalidContractValue("unsupported context item version")
        nonempty(self.ref_id, "ref_id")
        safe_code(self.purpose, "purpose")
        sensitivity(self.sensitivity)
        canonical_int(self.token_count, "token_count", maximum=1_000_000)
        canonical_int(self.priority, "priority", maximum=1000)
        hex64(self.payload_digest, "payload_digest")
        string_tuple(self.available_fields, "available_fields", sorted_unique=True, codes=True)
        verify_content_id(self.item_id, "wiki.runtime.context-item.v1", self.to_mapping(), "item_id", "context item_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "context_item_version": self.context_item_version,
            "item_id": self.item_id,
            "ref_id": self.ref_id,
            "purpose": self.purpose,
            "sensitivity": self.sensitivity,
            "token_count": self.token_count,
            "priority": self.priority,
            "payload_digest": self.payload_digest,
            "available_fields": list(self.available_fields),
        }


@dataclass(frozen=True)
class EgressDecision:
    egress_decision_version: str
    decision_id: str
    provider_id: str
    purpose: str
    route: str
    maximum_sensitivity: str
    allowed_fields: tuple[str, ...]
    reason_code: str

    @classmethod
    def create(
        cls,
        *,
        provider_id: str,
        purpose: str,
        route: str,
        maximum_sensitivity: str,
        allowed_fields: Sequence[str],
        reason_code: str,
    ) -> "EgressDecision":
        fields = tuple(sorted(set(allowed_fields)))
        payload = {
            "egress_decision_version": EGRESS_DECISION_VERSION,
            "provider_id": provider_id,
            "purpose": purpose,
            "route": route,
            "maximum_sensitivity": maximum_sensitivity,
            "allowed_fields": list(fields),
            "reason_code": reason_code,
        }
        return cls(decision_id=content_id("wiki.runtime.egress-decision.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.egress_decision_version != EGRESS_DECISION_VERSION:
            raise InvalidContractValue("unsupported egress decision version")
        safe_code(self.provider_id, "provider_id")
        safe_code(self.purpose, "purpose")
        try:
            EgressRoute(self.route)
        except ValueError as exc:
            raise InvalidContractValue("unsupported egress route") from exc
        sensitivity(self.maximum_sensitivity)
        string_tuple(self.allowed_fields, "allowed_fields", sorted_unique=True, codes=True)
        safe_code(self.reason_code, "reason_code")
        verify_content_id(self.decision_id, "wiki.runtime.egress-decision.v1", self.to_mapping(), "decision_id", "egress decision_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "egress_decision_version": self.egress_decision_version,
            "decision_id": self.decision_id,
            "provider_id": self.provider_id,
            "purpose": self.purpose,
            "route": self.route,
            "maximum_sensitivity": self.maximum_sensitivity,
            "allowed_fields": list(self.allowed_fields),
            "reason_code": self.reason_code,
        }


class EgressPolicyClient(Protocol):
    def authorize(self, *, provider_id: str, purpose: str) -> EgressDecision: ...


class StaticEgressPolicy:
    """Reference policy. Unknown providers/purposes are local-only."""

    def __init__(self, decisions: Mapping[tuple[str, str], EgressDecision]) -> None:
        self._decisions = dict(decisions)

    def authorize(self, *, provider_id: str, purpose: str) -> EgressDecision:
        key = (provider_id, purpose)
        if key in self._decisions:
            return self._decisions[key]
        return EgressDecision.create(
            provider_id=provider_id,
            purpose=purpose,
            route=EgressRoute.LOCAL_ONLY.value,
            maximum_sensitivity="secret",
            allowed_fields=(),
            reason_code="route_not_allowlisted",
        )


@dataclass(frozen=True)
class PlannedContextItem:
    item_id: str
    ref_id: str
    selected_fields: tuple[str, ...]
    token_count: str
    payload_digest: str
    sensitivity: str

    def to_mapping(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "ref_id": self.ref_id,
            "selected_fields": list(self.selected_fields),
            "token_count": self.token_count,
            "payload_digest": self.payload_digest,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class ContextPlan:
    context_plan_version: str
    plan_id: str
    operation_id: str
    provider_id: str
    purpose: str
    route: str
    egress_decision_id: str
    max_tokens: str
    selected_tokens: str
    selected_items: tuple[PlannedContextItem, ...]
    omitted_item_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        provider_id: str,
        purpose: str,
        route: str,
        egress_decision_id: str,
        max_tokens: str,
        selected_tokens: str,
        selected_items: Sequence[PlannedContextItem],
        omitted_item_ids: Sequence[str],
        reason_codes: Sequence[str],
    ) -> "ContextPlan":
        items = tuple(selected_items)
        omitted = tuple(sorted(set(omitted_item_ids)))
        reasons = tuple(sorted(set(reason_codes)))
        payload = {
            "context_plan_version": CONTEXT_PLAN_VERSION,
            "operation_id": operation_id,
            "provider_id": provider_id,
            "purpose": purpose,
            "route": route,
            "egress_decision_id": egress_decision_id,
            "max_tokens": max_tokens,
            "selected_tokens": selected_tokens,
            "selected_items": [item.to_mapping() for item in items],
            "omitted_item_ids": list(omitted),
            "reason_codes": list(reasons),
        }
        return cls(plan_id=content_id("wiki.runtime.context-plan.v1", payload), selected_items=items, omitted_item_ids=omitted, reason_codes=reasons, **{k: v for k, v in payload.items() if k not in {"selected_items", "omitted_item_ids", "reason_codes"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.context_plan_version != CONTEXT_PLAN_VERSION:
            raise InvalidContractValue("unsupported context plan version")
        hex64(self.operation_id, "operation_id")
        safe_code(self.provider_id, "provider_id")
        safe_code(self.purpose, "purpose")
        EgressRoute(self.route)
        hex64(self.egress_decision_id, "egress_decision_id")
        max_tokens = canonical_int(self.max_tokens, "max_tokens", maximum=1_000_000)
        selected = canonical_int(self.selected_tokens, "selected_tokens", maximum=max_tokens)
        if sum(int(item.token_count) for item in self.selected_items) != selected:
            raise InvalidContractValue("selected_tokens does not equal selected item total")
        string_tuple(self.omitted_item_ids, "omitted_item_ids", sorted_unique=True)
        string_tuple(self.reason_codes, "reason_codes", sorted_unique=True, codes=True)
        verify_content_id(self.plan_id, "wiki.runtime.context-plan.v1", self.to_mapping(), "plan_id", "context plan_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "context_plan_version": self.context_plan_version,
            "plan_id": self.plan_id,
            "operation_id": self.operation_id,
            "provider_id": self.provider_id,
            "purpose": self.purpose,
            "route": self.route,
            "egress_decision_id": self.egress_decision_id,
            "max_tokens": self.max_tokens,
            "selected_tokens": self.selected_tokens,
            "selected_items": [item.to_mapping() for item in self.selected_items],
            "omitted_item_ids": list(self.omitted_item_ids),
            "reason_codes": list(self.reason_codes),
        }


class ContextPlanner:
    def __init__(self, policy: EgressPolicyClient) -> None:
        self.policy = policy

    def plan(
        self,
        *,
        operation_id: str,
        provider_id: str,
        purpose: str,
        max_tokens: str,
        items: Sequence[ContextItem],
    ) -> ContextPlan:
        hex64(operation_id, "operation_id")
        token_cap = canonical_int(max_tokens, "max_tokens", maximum=1_000_000)
        decision = self.policy.authorize(provider_id=provider_id, purpose=purpose)
        route = EgressRoute(decision.route)
        allowed = set(decision.allowed_fields)
        selected: list[PlannedContextItem] = []
        omitted: list[str] = []
        reasons: set[str] = set()
        total = 0
        for item in sorted(items, key=lambda value: (-int(value.priority), value.item_id)):
            if item.purpose != purpose:
                omitted.append(item.item_id)
                reasons.add("purpose_mismatch")
                continue
            if route is EgressRoute.PROVIDER and item.sensitivity == "secret":
                omitted.append(item.item_id)
                reasons.add("secret_local_only")
                continue
            if SENSITIVITY_RANK[item.sensitivity] > SENSITIVITY_RANK[decision.maximum_sensitivity]:
                omitted.append(item.item_id)
                reasons.add("sensitivity_exceeds_route")
                continue
            fields = tuple(sorted(set(item.available_fields) & allowed)) if route is EgressRoute.PROVIDER else tuple(item.available_fields)
            if route is EgressRoute.PROVIDER and not fields:
                omitted.append(item.item_id)
                reasons.add("no_allowed_fields")
                continue
            cost = int(item.token_count)
            if total + cost > token_cap:
                omitted.append(item.item_id)
                reasons.add("token_cap")
                continue
            selected.append(
                PlannedContextItem(
                    item_id=item.item_id,
                    ref_id=item.ref_id,
                    selected_fields=fields,
                    token_count=item.token_count,
                    payload_digest=item.payload_digest,
                    sensitivity=item.sensitivity,
                )
            )
            total += cost
        if route is EgressRoute.LOCAL_ONLY:
            reasons.add("local_only")
        return ContextPlan.create(
            operation_id=operation_id,
            provider_id=provider_id,
            purpose=purpose,
            route=route.value,
            egress_decision_id=decision.decision_id,
            max_tokens=max_tokens,
            selected_tokens=str(total),
            selected_items=selected,
            omitted_item_ids=omitted,
            reason_codes=sorted(reasons),
        )


def validate_provider_payload(payload: Mapping[str, object]) -> dict[str, object]:
    """Fail closed if a caller tries to smuggle credentials into provider context."""
    ensure_no_secret_keys(payload, label="provider_payload")
    return canonical_object(payload, "provider_payload")


__all__ = [
    "CONTEXT_ITEM_VERSION", "CONTEXT_PLAN_VERSION", "EGRESS_DECISION_VERSION",
    "EgressRoute", "ContextItem", "EgressDecision", "EgressPolicyClient",
    "StaticEgressPolicy", "PlannedContextItem", "ContextPlan", "ContextPlanner",
    "validate_provider_payload",
]
