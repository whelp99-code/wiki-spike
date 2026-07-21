"""LLM runtime contracts: retry, rate limiting, and per-call cost budgets."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable

from .llm import LLMClient, LLMError


class TransientLLMError(LLMError):
    """Retryable provider/network failure: timeout, HTTP 429, or 5xx."""


class FatalLLMError(LLMError):
    """Non-retryable failure: other 4xx, schema violation, or budget breach."""


class BudgetExceededError(FatalLLMError):
    pass


class CallBudgetExceededError(BudgetExceededError):
    """A single LLM call exceeded max_cost_per_call."""


class SourceBudgetExceededError(BudgetExceededError):
    """The cumulative cost of ALL calls for one source exceeded max_cost_per_source_total."""


def classify_http(status: int) -> type[LLMError] | None:
    if status == 429 or 500 <= status < 600:
        return TransientLLMError
    if 400 <= status < 500:
        return FatalLLMError
    return None


@dataclass
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.0
    max_delay: float = 30.0
    sleep: Callable[[float], None] = time.sleep

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.base_delay < 0 or self.max_delay < 0:
            raise ValueError("retry delays must be non-negative")

    def run(self, fn: Callable[[], object]) -> object:
        for attempt in range(1, self.max_attempts + 1):
            try:
                return fn()
            except TransientLLMError:
                if attempt >= self.max_attempts:
                    raise
                delay = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
                if delay:
                    self.sleep(delay)
        raise AssertionError("unreachable")


@dataclass
class TokenBucketRateLimiter:
    rate_per_sec: float
    capacity: float
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    _tokens: float = field(default=0.0, init=False)
    _last: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if self.rate_per_sec <= 0 or self.capacity <= 0:
            raise ValueError("rate_per_sec and capacity must be > 0")
        self._tokens = self.capacity
        self._last = self.clock()

    def _refill(self) -> None:
        now = self.clock()
        elapsed = max(0.0, now - self._last)
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate_per_sec)
        self._last = now

    def try_acquire(self, n: float = 1.0) -> bool:
        if n <= 0 or n > self.capacity:
            raise ValueError("requested tokens must be in (0, capacity]")
        self._refill()
        if self._tokens >= n:
            self._tokens -= n
            return True
        return False

    def acquire(self, n: float = 1.0, max_wait: float | None = None) -> None:
        if self.try_acquire(n):
            return
        needed = n - self._tokens
        wait = needed / self.rate_per_sec
        if max_wait is not None and wait > max_wait:
            raise TransientLLMError("rate-limit wait exceeds max_wait")
        self.sleep(wait)
        if not self.try_acquire(n):
            raise TransientLLMError("rate limiter clock did not advance")


@dataclass
class CostTracker:
    price_in_per_mtok: float
    price_out_per_mtok: float
    input_tokens: int = 0
    output_tokens: int = 0
    last_call_cost: float = 0.0

    def cost_of(self, usage: dict) -> float:
        inp = max(0, int(usage.get("input_tokens", 0)))
        out = max(0, int(usage.get("output_tokens", 0)))
        return (inp / 1_000_000) * self.price_in_per_mtok + (
            out / 1_000_000
        ) * self.price_out_per_mtok

    def add(self, usage: dict) -> float:
        inp = max(0, int(usage.get("input_tokens", 0)))
        out = max(0, int(usage.get("output_tokens", 0)))
        self.input_tokens += inp
        self.output_tokens += out
        self.last_call_cost = self.cost_of(usage)
        return self.last_call_cost

    def cost(self) -> float:
        return (self.input_tokens / 1_000_000) * self.price_in_per_mtok + (
            self.output_tokens / 1_000_000
        ) * self.price_out_per_mtok

    def check_call_budget(self, max_cost: float) -> None:
        if self.last_call_cost > max_cost:
            raise BudgetExceededError(
                f"call cost {self.last_call_cost:.6f} exceeds max_cost_per_source {max_cost:.6f}"
            )

    def check_budget(self, max_cost: float) -> None:
        """Backward-compatible cumulative-budget check."""
        if self.cost() > max_cost:
            raise BudgetExceededError(
                f"cost {self.cost():.6f} exceeds max_cost {max_cost:.6f}"
            )


@dataclass
class SourceCostContext:
    """Accumulates cost across EVERY LLM call for a single source execution
    (extraction + verification + render). Enforces two independent caps:
      - max_cost_per_call:         no single call may exceed this
      - max_cost_per_source_total: the running total for the source may not exceed this

    One context is created per source (per ingest) and shared by all ManagedLLMClients
    used while processing that source, so cost cannot leak across multiple calls.
    """

    max_cost_per_call: float | None = None
    max_cost_per_source_total: float | None = None
    total_cost: float = 0.0
    call_count: int = 0
    per_call_costs: list[float] = field(default_factory=list)

    def record(self, call_cost: float) -> None:
        self.call_count += 1
        self.per_call_costs.append(call_cost)
        if self.max_cost_per_call is not None and call_cost > self.max_cost_per_call:
            raise CallBudgetExceededError(
                f"call cost {call_cost:.6f} exceeds max_cost_per_call {self.max_cost_per_call:.6f}"
            )
        self.total_cost += call_cost
        if (
            self.max_cost_per_source_total is not None
            and self.total_cost > self.max_cost_per_source_total
        ):
            raise SourceBudgetExceededError(
                f"source total {self.total_cost:.6f} exceeds "
                f"max_cost_per_source_total {self.max_cost_per_source_total:.6f}"
            )


@dataclass
class ManagedLLMClient:
    inner: LLMClient
    retry: RetryPolicy = field(default_factory=RetryPolicy)
    limiter: TokenBucketRateLimiter | None = None
    tracker: CostTracker | None = None
    max_cost_per_source: float | None = None  # legacy alias: per-CALL cap
    rate_limit_max_wait: float | None = 60.0
    cost_context: SourceCostContext | None = None  # per-source-total accumulation

    def complete_json(self, model_id: str, system: str, user: str) -> dict:
        def _call() -> dict:
            if self.limiter is not None:
                self.limiter.acquire(max_wait=self.rate_limit_max_wait)
            return self.inner.complete_json(model_id, system, user)

        result = self.retry.run(_call)
        usage = getattr(self.inner, "last_usage", None)
        if usage and self.tracker is not None:
            call_cost = self.tracker.add(usage)
            if self.max_cost_per_source is not None:  # legacy per-call check
                self.tracker.check_call_budget(self.max_cost_per_source)
            if self.cost_context is not None:  # per-call + per-source-total
                self.cost_context.record(call_cost)
        return result  # type: ignore[return-value]
