#!/usr/bin/env python3
"""Real-API canary runner — RUN THIS ON YOUR LOCAL MACHINE (not in Claude's container).

Claude's sandbox cannot reach your localhost router, so this script is delivered for
you to execute where the router is reachable. It reads ALL secrets/endpoints from the
environment (never hard-coded):

    export ROUTER_BASE_URL="http://localhost:20128/v1"
    export ROUTER_API_KEY="sk-..."          # keep out of chat; rotate the one you pasted
    export EXTRACTION_MODEL_ID="<model id served by the router>"
    export VERIFICATION_MODEL_ID="<model id served by the router>"   # may equal extraction

Then:
    cd wiki-spike
    PYTHONPATH=src python3 scripts/run_canary.py

It runs BOTH boundaries against the golden sets and prints acceptance:
  - extraction: structured_output_success, unsupported_acceptance, hedge_preservation, precision
  - layer P:    entailment_precision, false_acceptance_rate

Nothing is published; this only measures quality. Send the printed report back to
Claude for analysis.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wiki_spike.extraction import LLMExtractor  # noqa: E402
from wiki_spike.llm import LLMConfig, OpenAICompatClient  # noqa: E402
from wiki_spike.runtime import (  # noqa: E402
    CostTracker,
    ManagedLLMClient,
    RetryPolicy,
    SourceCostContext,
    TokenBucketRateLimiter,
)
from wiki_spike.verify import (  # noqa: E402
    GoldenExample,
    LayerPExample,
    LLMEntailmentChecker,
    passes_acceptance,
    passes_layer_p_acceptance,
    run_golden,
    run_layer_p_golden,
)

GOLDEN = Path(__file__).resolve().parents[1] / "tests" / "golden"


def _require(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        print(f"ERROR: {name} not set in environment", file=sys.stderr)
        sys.exit(2)
    return v


def main() -> int:
    base_url = _require("ROUTER_BASE_URL")
    extraction_model = _require("EXTRACTION_MODEL_ID")
    verification_model = os.environ.get("VERIFICATION_MODEL_ID", extraction_model)
    # API key read from env inside the client; never printed.
    print(f"router: {base_url}")
    print(f"extraction_model={extraction_model}  verification_model={verification_model}\n")

    cfg = LLMConfig(extraction_model_id=extraction_model, verification_model_id=verification_model)

    # Managed client: retry + rate limit + cost tracking (per-source context available).
    def managed() -> ManagedLLMClient:
        return ManagedLLMClient(
            OpenAICompatClient(base_url=base_url),
            retry=RetryPolicy(max_attempts=3, base_delay=0.5),
            limiter=TokenBucketRateLimiter(rate_per_sec=2.0, capacity=4.0),
            tracker=CostTracker(price_in_per_mtok=0.0, price_out_per_mtok=0.0),
            cost_context=SourceCostContext(max_cost_per_call=1.0, max_cost_per_source_total=5.0),
        )

    # ---- extraction golden ----
    ext_data = json.loads((GOLDEN / "dataset.json").read_text())
    extractor = LLMExtractor(managed(), cfg)
    ext_examples = [
        GoldenExample(e["source"], {tuple(x) for x in e["expected"]}, e.get("model_output"))
        for e in ext_data
    ]
    ext_report = run_golden(extractor, ext_examples)
    print("=== EXTRACTION GOLDEN ===")
    print(f"  structured_output_success = {ext_report.structured_output_success:.3f}")
    print(f"  unsupported_acceptance    = {ext_report.unsupported_acceptance:.3f}")
    print(f"  hedge_preservation        = {ext_report.hedge_preservation:.3f}")
    print(f"  precision                 = {ext_report.precision:.3f}")
    print(f"  recall                    = {ext_report.recall:.3f}")
    print(f"  PASS                      = {passes_acceptance(ext_report)}\n")

    # ---- layer P golden ----
    lp_data = json.loads((GOLDEN / "layerp.json").read_text())
    checker = LLMEntailmentChecker(managed(), cfg)
    lp_examples = [
        LayerPExample(e["subject"], e["predicate"], e["obj"], e["polarity"],
                      e["source"], e["evidence_quote"], e["truly_entailed"])
        for e in lp_data
    ]
    lp_report = run_layer_p_golden(checker, lp_examples)
    print("=== LAYER P GOLDEN ===")
    print(f"  entailment_precision   = {lp_report.entailment_precision:.3f}")
    print(f"  false_acceptance_rate  = {lp_report.false_acceptance_rate:.3f}")
    print(f"  accepted/total         = {lp_report.accepted}/{lp_report.total}")
    print(f"  PASS                   = {passes_layer_p_acceptance(lp_report)}\n")

    overall = passes_acceptance(ext_report) and passes_layer_p_acceptance(lp_report)
    print(f"OVERALL CANARY: {'PASS' if overall else 'FAIL'}")
    return 0 if overall else 1


if __name__ == "__main__":
    raise SystemExit(main())
