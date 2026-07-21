import io
import json
import urllib.error

import pytest

from wiki_spike.extraction import LLMExtractor
from wiki_spike.llm import AnthropicClient, LLMConfig, MockLLMClient
from wiki_spike.runtime import (
    CostTracker,
    FatalLLMError,
    ManagedLLMClient,
    RetryPolicy,
    TokenBucketRateLimiter,
    TransientLLMError,
)
from wiki_spike.verify import LayerPDecision, preserve_modality, run_golden, GoldenExample


def test_per_source_budget_does_not_accumulate_across_calls():
    client = MockLLMClient({"SOURCE": {"claims": [], "abstain": True}},
                           usage={"input_tokens": 100_000, "output_tokens": 0})
    tracker = CostTracker(3.0, 15.0)
    managed = ManagedLLMClient(client, tracker=tracker, max_cost_per_source=0.31)
    managed.complete_json("m", "s", "SOURCE one")
    managed.complete_json("m", "s", "SOURCE two")
    assert tracker.cost() == pytest.approx(0.6)
    assert tracker.last_call_cost == pytest.approx(0.3)


def test_rate_limiter_waits_instead_of_consuming_retry_attempts():
    t = [0.0]
    def sleep(dt):
        t[0] += dt
    limiter = TokenBucketRateLimiter(1.0, 1.0, clock=lambda: t[0], sleep=sleep)
    assert limiter.try_acquire()
    client = MockLLMClient({"x": {"claims": [], "abstain": True}})
    managed = ManagedLLMClient(client, limiter=limiter, retry=RetryPolicy(max_attempts=1))
    managed.complete_json("m", "s", "x")
    assert client.calls == 1
    assert t[0] == pytest.approx(1.0)


def test_possible_source_is_not_upgraded_to_likely():
    assert preserve_modality("A may support X", "likely") == "possible"
    assert preserve_modality("A likely supports X", "asserted") == "likely"
    # capability 'can' is not automatically epistemic uncertainty
    assert preserve_modality("A can encrypt files", "asserted") == "asserted"


def test_ambiguous_quote_with_wrong_offset_is_dropped():
    source = "A supports X. A supports X."
    out = {"claims": [{
        "subject": "A", "predicate": "supports", "object": "X",
        "polarity": "positive", "modality": "asserted", "scope": {},
        "evidence_quote": "A supports X", "offset": [2, 14],
    }], "abstain": False}
    ex = LLMExtractor(MockLLMClient({source: out}), LLMConfig(extraction_model_id="m"))
    assert ex.extract(source, "s", "r").claims == []


def test_malformed_claim_marks_structured_output_failure():
    source = "A supports X"
    out = {"claims": [{"subject": "A"}], "abstain": False}
    ex = LLMExtractor(MockLLMClient({source: out}), LLMConfig(extraction_model_id="m"))
    report = run_golden(ex, [GoldenExample(source, set(), out)])
    assert report.structured_output_success == 0.0


class _Unresolved:
    def check(self, claim, source_text):
        return LayerPDecision.UNRESOLVED


class _Contradicted:
    def check(self, claim, source_text):
        return LayerPDecision.CONTRADICTED


def _supported_output(source):
    return {"claims": [{
        "subject": "A", "predicate": "supports", "object": "X",
        "polarity": "positive", "modality": "asserted", "scope": {},
        "evidence_quote": source, "offset": [0, len(source)],
    }], "abstain": False}


@pytest.mark.parametrize("checker,expected", [(_Unresolved(), "unresolved"), (_Contradicted(), "contradicted")])
def test_layer_p_is_integrated_as_publish_gate(checker, expected):
    source = "A supports X"
    ex = LLMExtractor(MockLLMClient({source: _supported_output(source)}),
                      LLMConfig(extraction_model_id="m"), entailment_checker=checker)
    assert ex.extract(source, "s", "r").claims == []
    assert ex.last_layer_p_decisions == [expected]


def test_anthropic_http_errors_are_classified_for_retry(monkeypatch):
    calls = {"n": 0}
    def fake_urlopen(req, timeout):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 503, "bad", {}, io.BytesIO())
        payload = {"content": [{"type": "text", "text": json.dumps({"claims": [], "abstain": True})}],
                   "usage": {"input_tokens": 2, "output_tokens": 3}}
        class R:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self): return json.dumps(payload).encode()
        return R()
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    inner = AnthropicClient(api_key="k")
    managed = ManagedLLMClient(inner, retry=RetryPolicy(max_attempts=2))
    assert managed.complete_json("exact-model", "s", "u")["abstain"] is True
    assert calls["n"] == 2
    assert inner.last_usage == {"input_tokens": 2, "output_tokens": 3}


def test_anthropic_400_is_fatal(monkeypatch):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 400, "bad", {}, io.BytesIO())
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    with pytest.raises(FatalLLMError):
        AnthropicClient(api_key="k").complete_json("exact-model", "s", "u")
