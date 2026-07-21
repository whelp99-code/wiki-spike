"""Layer P (verification) boundary: real-model-shaped checker + golden harness.

Validates the entailment checker as a SEPARATE model/service boundary, measured by
entailment precision and false-acceptance rate — independent of extraction.
"""
import json
from pathlib import Path

import pytest

from wiki_spike.llm import AnthropicClient, LLMConfig, LLMError, MockLLMClient
from wiki_spike.verify import (
    LayerPDecision,
    LayerPExample,
    LLMEntailmentChecker,
    passes_layer_p_acceptance,
    run_layer_p_golden,
)

LP = json.loads((Path(__file__).parent / "golden" / "layerp.json").read_text())


def _examples():
    return [
        LayerPExample(e["subject"], e["predicate"], e["obj"], e["polarity"],
                      e["source"], e["evidence_quote"], e["truly_entailed"])
        for e in LP
    ]


def _mock_verifier():
    # Canned model decisions keyed on the source text.
    client = MockLLMClient({e["source"]: {"decision": e["model_decision"]} for e in LP})
    return LLMEntailmentChecker(client, LLMConfig(verification_model_id="MOCK-VERIFY"))


def test_llm_checker_maps_three_states():
    chk = _mock_verifier()
    by_id = {e["id"]: e for e in LP}
    ex = _examples()
    ent = next(x for x in ex if x.source == by_id["clear-entail"]["source"])
    con = next(x for x in ex if x.source == by_id["contradiction"]["source"])
    unr = next(x for x in ex if x.source == by_id["insufficient"]["source"])
    from wiki_spike.verify import _build_claim
    assert chk.check(_build_claim(ent), ent.source) is LayerPDecision.ENTAILED
    assert chk.check(_build_claim(con), con.source) is LayerPDecision.CONTRADICTED
    assert chk.check(_build_claim(unr), unr.source) is LayerPDecision.UNRESOLVED


def test_malformed_verifier_response_fails_closed():
    # A judge that returns garbage must NOT auto-accept -> UNRESOLVED.
    client = MockLLMClient({"any": {"not_a_decision": True}})
    chk = LLMEntailmentChecker(client, LLMConfig(verification_model_id="M"))
    ex = _examples()[0]
    from wiki_spike.verify import _build_claim
    assert chk.check(_build_claim(ex), ex.source) is LayerPDecision.UNRESOLVED


def test_layer_p_golden_meets_acceptance():
    report = run_layer_p_golden(_mock_verifier(), _examples())
    assert report.false_acceptance_rate == 0.0        # no non-entailed claim accepted
    assert report.entailment_precision >= 0.95
    assert passes_layer_p_acceptance(report)


def test_false_acceptance_is_caught():
    # A broken judge that says 'entailed' for a contradiction must fail acceptance.
    bad = MockLLMClient({e["source"]: {"decision": "entailed"} for e in LP})
    chk = LLMEntailmentChecker(bad, LLMConfig(verification_model_id="M"))
    report = run_layer_p_golden(chk, _examples())
    assert report.false_acceptance_rate > 0.0
    assert not passes_layer_p_acceptance(report)


def test_real_verifier_gated_without_model_id():
    chk = LLMEntailmentChecker(AnthropicClient(api_key="fake"),
                               LLMConfig(verification_model_id=""))
    ex = _examples()[0]
    from wiki_spike.verify import _build_claim
    # underlying client refuses (no model id) -> fail-closed UNRESOLVED
    assert chk.check(_build_claim(ex), ex.source) is LayerPDecision.UNRESOLVED


def test_expanded_extraction_golden_still_passes():
    # sanity: the expanded extraction golden loads and has 12 examples
    ext = json.loads((Path(__file__).parent / "golden" / "dataset.json").read_text())
    assert len(ext) == 12
    assert len({e["source"] for e in ext}) == 12  # unique sources
