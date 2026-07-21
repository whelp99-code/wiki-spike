"""Per-source cumulative cost contract: max_cost_per_call + max_cost_per_source_total.

Closes the gap where a source triggering multiple LLM calls (extraction +
verification + render) could leak cost because only a per-call cap existed.

Costs use $0.30 units (= 100,000 input tokens at $3/Mtok) so token->cost is exact.
"""
import pytest

from wiki_spike.llm import MockLLMClient
from wiki_spike.runtime import (
    CallBudgetExceededError,
    CostTracker,
    ManagedLLMClient,
    SourceBudgetExceededError,
    SourceCostContext,
)

RESP = {"claims": [], "abstain": True}


def _client(cost_dollars: float, ctx: SourceCostContext):
    tokens = round(cost_dollars / 3.0 * 1_000_000)  # exact for multiples of $0.30
    client = MockLLMClient({"SRC": RESP}, usage={"input_tokens": tokens, "output_tokens": 0})
    return ManagedLLMClient(client, tracker=CostTracker(3.0, 15.0), cost_context=ctx)


def test_per_source_total_accumulates_across_calls():
    # 3 calls each $0.30 (< per-call cap $1.0); cumulative $0.90 > per-source-total $0.80
    # -> blocked on the 3rd call.
    ctx = SourceCostContext(max_cost_per_call=1.0, max_cost_per_source_total=0.80)
    _client(0.30, ctx).complete_json("m", "s", "SRC")   # total 0.30
    _client(0.30, ctx).complete_json("m", "s", "SRC")   # total 0.60
    with pytest.raises(SourceBudgetExceededError):
        _client(0.30, ctx).complete_json("m", "s", "SRC")  # total 0.90 > 0.80
    assert ctx.call_count == 3
    assert abs(ctx.total_cost - 0.90) < 1e-9  # includes the over-budget call (cost was spent)


def test_per_call_cap_independent_of_source_total():
    ctx = SourceCostContext(max_cost_per_call=0.5, max_cost_per_source_total=100.0)
    with pytest.raises(CallBudgetExceededError):
        _client(0.90, ctx).complete_json("m", "s", "SRC")


def test_under_both_caps_passes():
    ctx = SourceCostContext(max_cost_per_call=1.0, max_cost_per_source_total=2.0)
    for _ in range(4):
        _client(0.30, ctx).complete_json("m", "s", "SRC")  # 4 * 0.30 = 1.20 <= 2.0
    assert ctx.call_count == 4
    assert abs(ctx.total_cost - 1.20) < 1e-9


def test_legacy_per_call_param_still_works():
    client = MockLLMClient({"SRC": RESP}, usage={"input_tokens": 500_000, "output_tokens": 0})
    mgd = ManagedLLMClient(client, tracker=CostTracker(3.0, 15.0), max_cost_per_source=1.0)
    with pytest.raises(Exception) as ei:
        mgd.complete_json("m", "s", "SRC")  # $1.50 > $1.00
    assert "call cost" in str(ei.value)


def test_shared_context_models_extraction_verification_render():
    # One context shared by three clients = three pipeline stages.
    ctx = SourceCostContext(max_cost_per_call=1.0, max_cost_per_source_total=1.0)
    extraction = _client(0.30, ctx)
    verification = _client(0.30, ctx)
    render = _client(0.60, ctx)  # cumulative 1.20 > 1.0 -> render blocked
    extraction.complete_json("m", "s", "SRC")
    verification.complete_json("m", "s", "SRC")
    with pytest.raises(SourceBudgetExceededError):
        render.complete_json("m", "s", "SRC")
    assert abs(ctx.total_cost - 1.20) < 1e-9  # cost was spent before abort
