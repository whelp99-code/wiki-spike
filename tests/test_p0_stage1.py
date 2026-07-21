"""P0 stage-1 contracts (API-free, mock-verifiable):
hedge/modality preservation, retry, rate limit, cost/budget, golden acceptance,
Layer P 3-state, and API-failure -> pointer-invariant."""
import json
from pathlib import Path

import pytest

from wiki_spike.extraction import LLMExtractor
from wiki_spike.llm import LLMConfig, MockLLMClient
from wiki_spike.runtime import (
    BudgetExceededError,
    CostTracker,
    FatalLLMError,
    ManagedLLMClient,
    RetryPolicy,
    TokenBucketRateLimiter,
    TransientLLMError,
    classify_http,
)
from wiki_spike.verify import (
    ACCEPTANCE,
    GoldenExample,
    LayerPDecision,
    MockEntailmentChecker,
    detect_hedge,
    layer_d_ok,
    passes_acceptance,
    preserve_modality,
    run_golden,
)
from wiki_spike.workspace import Workspace

GOLDEN = json.loads((Path(__file__).parent / "golden" / "dataset.json").read_text())


def _extractor(client):
    return LLMExtractor(client, LLMConfig(extraction_model_id="MOCK"))


# --- 1. hedge / modality preservation ------------------------------------ #
def test_hedge_detected():
    assert detect_hedge("Product A may support X")
    assert detect_hedge("아마 지원할 수 있다")
    assert not detect_hedge("Product A supports X")


def test_hedged_span_not_promoted_to_asserted():
    assert preserve_modality("A may support X", "asserted") == "possible"
    assert preserve_modality("A supports X", "asserted") == "asserted"


def test_extractor_preserves_hedge_end_to_end():
    ex = next(e for e in GOLDEN if e["id"] == "hedge-may-possible")
    client = MockLLMClient({ex["source"]: ex["model_output"]})
    claims = _extractor(client).extract(ex["source"], "s", "r").claims
    assert claims and claims[0].assertion.modality == "possible"  # source certainty preserved


# --- 2. retry policy ------------------------------------------------------ #
def test_retry_recovers_after_transient():
    client = MockLLMClient(
        {"SOURCE": {"claims": [], "abstain": True}},
        fail_times=2, fail_error=TransientLLMError("503"),
    )
    managed = ManagedLLMClient(client, retry=RetryPolicy(max_attempts=3, base_delay=0.0))
    out = managed.complete_json("m", "sys", "SOURCE text")
    assert out == {"claims": [], "abstain": True}
    assert client.calls == 3


def test_retry_gives_up_and_raises():
    client = MockLLMClient(fail_times=5, fail_error=TransientLLMError("429"))
    managed = ManagedLLMClient(client, retry=RetryPolicy(max_attempts=3, base_delay=0.0))
    with pytest.raises(TransientLLMError):
        managed.complete_json("m", "sys", "x")


def test_fatal_error_not_retried():
    client = MockLLMClient(fail_times=5, fail_error=FatalLLMError("400"))
    managed = ManagedLLMClient(client, retry=RetryPolicy(max_attempts=3))
    with pytest.raises(FatalLLMError):
        managed.complete_json("m", "sys", "x")
    assert client.calls == 1  # not retried


def test_classify_http():
    assert classify_http(429) is TransientLLMError
    assert classify_http(503) is TransientLLMError
    assert classify_http(400) is FatalLLMError


# --- 3. rate limit -------------------------------------------------------- #
def test_rate_limiter_deterministic_clock():
    t = [0.0]
    rl = TokenBucketRateLimiter(rate_per_sec=1.0, capacity=2.0, clock=lambda: t[0])
    assert rl.try_acquire() and rl.try_acquire()   # burst capacity = 2
    assert not rl.try_acquire()                    # empty
    t[0] = 1.0
    assert rl.try_acquire()                        # 1 token refilled after 1s


# --- 4. cost / budget ----------------------------------------------------- #
def test_cost_tracking_and_budget():
    tr = CostTracker(price_in_per_mtok=3.0, price_out_per_mtok=15.0)
    tr.add({"input_tokens": 1_000_000, "output_tokens": 1_000_000})
    assert abs(tr.cost() - 18.0) < 1e-9
    with pytest.raises(BudgetExceededError):
        tr.check_budget(max_cost=10.0)


def test_budget_exceeded_is_fatal_via_managed_client():
    client = MockLLMClient({"SOURCE": {"claims": [], "abstain": True}},
                           usage={"input_tokens": 2_000_000, "output_tokens": 0})
    managed = ManagedLLMClient(
        client, tracker=CostTracker(3.0, 15.0), max_cost_per_source=1.0
    )
    with pytest.raises(BudgetExceededError):
        managed.complete_json("m", "sys", "SOURCE")


# --- 5. golden acceptance ------------------------------------------------- #
def _golden_examples():
    out = []
    for e in GOLDEN:
        out.append(GoldenExample(
            source=e["source"],
            expected_claims={tuple(x) for x in e["expected"]},
            model_output=e["model_output"],
        ))
    return out


class _GoldenClient:
    """Serves each example's canned model output by source match."""
    def __init__(self, examples):
        self._m = {e.source: e.model_output for e in examples}
        self.last_usage = {"input_tokens": 10, "output_tokens": 10}
    def complete_json(self, model_id, system, user):
        for src, out in self._m.items():
            if src in user:
                return out
        return {"claims": [], "abstain": True}


def test_golden_meets_stage1_acceptance():
    examples = _golden_examples()
    report = run_golden(_extractor(_GoldenClient(examples)), examples)
    assert report.unsupported_acceptance == 0.0     # unsupported claim was dropped
    assert report.hedge_preservation == 1.0         # hedge not promoted
    assert report.structured_output_success >= 0.99
    assert report.precision >= ACCEPTANCE["min_precision"]
    assert passes_acceptance(report)


# --- 6. Layer P 3-state --------------------------------------------------- #
def test_layer_p_unresolved_when_unsupported():
    ex = next(e for e in GOLDEN if e["id"] == "unsupported-dropped")
    # craft a claim whose quote is NOT in the source by extracting from a mismatched src
    client = MockLLMClient({ex["source"]: ex["model_output"]})
    # extractor drops unsupported, so build via supported example then test checker
    sup = next(e for e in GOLDEN if e["id"] == "supported-asserted")
    c = _extractor(MockLLMClient({sup["source"]: sup["model_output"]})).extract(
        sup["source"], "s", "r").claims[0]
    chk = MockEntailmentChecker()
    assert chk.check(c, sup["source"]) is LayerPDecision.ENTAILED
    assert chk.check(c, "unrelated text with no overlap") is LayerPDecision.UNRESOLVED


# --- 7. API failure -> publication pointer invariant --------------------- #
def test_api_failure_leaves_pointer_unchanged(tmp_path):
    # seed one good generation via the deterministic mock extractor (default)
    ws0 = Workspace(tmp_path / "ws")
    a = tmp_path / "a.md"; a.write_text("A | supports | X | positive | v=1\n")
    ws0.ingest_and_publish(a)
    ptr = ws0.cp.current_pointer()
    ws0.close()

    # now reopen with an LLM extractor whose client always 5xx (retries exhausted)
    failing = MockLLMClient(fail_times=99, fail_error=TransientLLMError("503"))
    managed = ManagedLLMClient(failing, retry=RetryPolicy(max_attempts=2, base_delay=0.0))
    ws = Workspace(tmp_path / "ws",
                   extractor=LLMExtractor(managed, LLMConfig(extraction_model_id="MOCK")))
    b = tmp_path / "b.md"; b.write_text("Some source text that triggers extraction.\n")
    with pytest.raises(TransientLLMError):
        ws.ingest_and_publish(b)
    assert ws.cp.current_pointer() == ptr  # pointer unchanged on API failure
    ws.close()
