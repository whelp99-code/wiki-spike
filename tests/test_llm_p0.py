"""P0 first slice: LLM extractor structured output + Layer D + golden eval (mock client)."""
import pytest

from wiki_spike.extraction import LLMExtractor
from wiki_spike.llm import AnthropicClient, LLMConfig, LLMError, MockLLMClient
from wiki_spike.verify import (
    GoldenExample,
    MockEntailmentChecker,
    layer_d_ok,
    run_golden,
)

SOURCE = "Product A supports feature X. It may improve latency."


def _mock_client():
    # Deterministic structured response keyed on the source substring.
    return MockLLMClient({
        "Product A supports feature X": {
            "claims": [
                {"subject": "Product A", "predicate": "supports", "object": "feature X",
                 "polarity": "positive", "modality": "asserted", "scope": {},
                 "evidence_quote": "Product A supports feature X", "offset": [0, 28]},
                # unsupported claim (quote not in source) -> must be DROPPED by Layer D
                {"subject": "Product A", "predicate": "cures", "object": "cancer",
                 "polarity": "positive", "modality": "asserted", "scope": {},
                 "evidence_quote": "Product A cures cancer", "offset": [0, 22]},
            ],
            "abstain": False,
        }
    })


def _extractor():
    return LLMExtractor(_mock_client(), LLMConfig(extraction_model_id="MOCK"))


def test_llm_extract_keeps_supported_drops_unsupported():
    res = _extractor().extract(SOURCE, "src", "rep")
    keys = {(c.identity.subject_id, c.identity.predicate_id, c.identity.obj) for c in res.claims}
    assert ("Product A", "supports", "feature X") in keys
    assert ("Product A", "cures", "cancer") not in keys  # REFUSE-TO-WRITE


def test_layer_d_validates_quote_hash():
    c = _extractor().extract(SOURCE, "src", "rep").claims[0]
    assert layer_d_ok(c, SOURCE)


def test_mock_entailment_follows_layer_d():
    c = _extractor().extract(SOURCE, "src", "rep").claims[0]
    assert MockEntailmentChecker().entails(c, SOURCE)


def test_abstains_on_unknown_source():
    # No registered response -> mock returns abstain -> zero claims.
    res = LLMExtractor(MockLLMClient(), LLMConfig(extraction_model_id="MOCK")).extract(
        "totally unrelated text", "s", "r")
    assert res.claims == []


def test_golden_eval_precision_recall():
    examples = [
        GoldenExample(SOURCE, {("Product A", "supports", "feature X", "positive")}),
        GoldenExample("no claims here", set()),  # abstention case
    ]
    report = run_golden(_extractor(), examples)
    assert report.precision == 1.0  # unsupported claim was dropped, so no false positives
    assert report.recall == 1.0
    assert report.abstention_correct == 1


def test_real_client_refuses_without_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(LLMError):
        AnthropicClient(api_key="").complete_json("some-model", "sys", "user")


def test_real_client_refuses_without_model_id(monkeypatch):
    with pytest.raises(LLMError):
        AnthropicClient(api_key="fake-key").complete_json("", "sys", "user")
