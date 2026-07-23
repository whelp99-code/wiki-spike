"""P4-12 shared hierarchical cost budgets."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .service_contracts import canonical_int, content_id, verify_content_id, hex64, nonempty

COST_CONTEXT_VERSION = "phase4-cost-context-v1"


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class CostContext:
    cost_context_version: str
    context_id: str
    operation_id: str
    workspace_id: str
    source_id: str
    max_call_micros: str
    max_operation_micros: str
    max_source_micros: str
    max_workspace_micros: str

    @classmethod
    def create(cls, **kwargs: object) -> "CostContext":
        payload = {"cost_context_version": COST_CONTEXT_VERSION, **kwargs}
        return cls(context_id=content_id("wiki.runtime.cost-context.v1", payload), **payload)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.cost_context_version != COST_CONTEXT_VERSION:
            raise InvalidContractValue("unsupported cost context version")
        hex64(self.operation_id, "operation_id")
        nonempty(self.workspace_id, "workspace_id")
        nonempty(self.source_id, "source_id")
        for field in (
            "max_call_micros", "max_operation_micros", "max_source_micros", "max_workspace_micros"
        ):
            canonical_int(getattr(self, field), field, maximum=10**15)
        verify_content_id(self.context_id, "wiki.runtime.cost-context.v1", self.to_mapping(), "context_id", "cost context_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "cost_context_version": self.cost_context_version,
            "context_id": self.context_id,
            "operation_id": self.operation_id,
            "workspace_id": self.workspace_id,
            "source_id": self.source_id,
            "max_call_micros": self.max_call_micros,
            "max_operation_micros": self.max_operation_micros,
            "max_source_micros": self.max_source_micros,
            "max_workspace_micros": self.max_workspace_micros,
        }



class CostTracker:
    def __init__(self) -> None:
        self._operation: dict[str, int] = {}
        self._source: dict[tuple[str, str], int] = {}
        self._workspace: dict[str, int] = {}
        self._lock = RLock()

    def reserve(self, context: CostContext, estimated_micros: str) -> None:
        amount = canonical_int(estimated_micros, "estimated_micros", maximum=10**15)
        with self._lock:
            if amount > int(context.max_call_micros):
                raise BudgetExceeded("call_budget_exceeded")
            operation = self._operation.get(context.operation_id, 0)
            source_key = (context.workspace_id, context.source_id)
            source = self._source.get(source_key, 0)
            workspace = self._workspace.get(context.workspace_id, 0)
            if operation + amount > int(context.max_operation_micros):
                raise BudgetExceeded("operation_budget_exceeded")
            if source + amount > int(context.max_source_micros):
                raise BudgetExceeded("source_budget_exceeded")
            if workspace + amount > int(context.max_workspace_micros):
                raise BudgetExceeded("workspace_budget_exceeded")
            self._operation[context.operation_id] = operation + amount
            self._source[source_key] = source + amount
            self._workspace[context.workspace_id] = workspace + amount

    def usage(self, context: CostContext) -> dict[str, str]:
        return {
            "operation_micros": str(self._operation.get(context.operation_id, 0)),
            "source_micros": str(self._source.get((context.workspace_id, context.source_id), 0)),
            "workspace_micros": str(self._workspace.get(context.workspace_id, 0)),
        }


__all__ = ["COST_CONTEXT_VERSION", "BudgetExceeded", "CostContext", "CostTracker"]
