"""Verification layers + golden eval harness (P0 first slice).

- Layer D (deterministic): quote_hash matches the source span. Reproducible, free.
- Hedge/modality preservation: a hedged source span may NOT yield an 'asserted' claim
  (may/likely/possible must not be promoted to asserted/certain).
- Layer P (probabilistic entailment): 3-state decision (ENTAILED / UNRESOLVED /
  CONTRADICTED) so "insufficient support -> unresolved" is representable.
- golden eval: run an extractor over labeled examples and report precision / recall /
  abstention / hedge preservation / unsupported acceptance.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from .claims import ClaimExtractor, CompiledClaim
from .hashing import sha256_hex


# --------------------------------------------------------------------------- #
# Layer D — deterministic
# --------------------------------------------------------------------------- #
def layer_d_ok(claim: CompiledClaim, source_text: str) -> bool:
    loc = claim.evidence.locators[0]
    start, end = int(loc["start"]), int(loc["end"])
    if not (0 <= start < end <= len(source_text)):
        return False
    span = source_text[start:end]
    return sha256_hex(span.encode("utf-8")) == claim.evidence.quote_hash


# --------------------------------------------------------------------------- #
# Hedge / modality preservation
# --------------------------------------------------------------------------- #
import re

# Certainty ordering: asserted > likely > possible.  Preserve the least-certain
# level supported by either the source language or the model proposal.
_MODALITY_RANK = {"possible": 0, "likely": 1, "asserted": 2}
_LIKELY_PATTERNS = (
    r"\blikely\b", r"\bprobably\b", r"\bappears?\b", r"\bseems?\b",
    r"\bsuggests?\b", r"가능성이\s*(?:높|크)", r"것으로\s*보인다",
)
_POSSIBLE_PATTERNS = (
    r"\bmay\b", r"\bmight\b", r"\bcould\b", r"\bpossibly\b",
    r"\bperhaps\b", r"\bpotential(?:ly)?\b", r"수\s*있", r"일\s*수",
    r"가능성", r"아마", r"인\s*듯", r"듯하다",
)


def infer_source_modality(span: str) -> str:
    s = span.lower()
    if any(re.search(p, s) for p in _POSSIBLE_PATTERNS):
        return "possible"
    if any(re.search(p, s) for p in _LIKELY_PATTERNS):
        return "likely"
    return "asserted"


def detect_hedge(span: str) -> bool:
    return infer_source_modality(span) != "asserted"


def preserve_modality(source_span: str, proposed_modality: str) -> str:
    proposed = proposed_modality if proposed_modality in _MODALITY_RANK else "asserted"
    source = infer_source_modality(source_span)
    return min((source, proposed), key=lambda m: _MODALITY_RANK[m])


def modality_preserved(claim: CompiledClaim, source_text: str) -> bool:
    loc = claim.evidence.locators[0]
    span = source_text[int(loc["start"]):int(loc["end"])]
    source = infer_source_modality(span)
    actual = claim.assertion.modality
    return _MODALITY_RANK.get(actual, 2) <= _MODALITY_RANK[source]

# --------------------------------------------------------------------------- #
# Layer P — probabilistic entailment (3-state)
# --------------------------------------------------------------------------- #
class LayerPDecision(str, Enum):
    ENTAILED = "entailed"
    UNRESOLVED = "unresolved"
    CONTRADICTED = "contradicted"


class EntailmentChecker(Protocol):
    def check(self, claim: CompiledClaim, source_text: str) -> LayerPDecision: ...


class MockEntailmentChecker:
    """Deterministic stand-in: Layer-D-valid -> ENTAILED, else UNRESOLVED."""

    def check(self, claim: CompiledClaim, source_text: str) -> LayerPDecision:
        return LayerPDecision.ENTAILED if layer_d_ok(claim, source_text) else LayerPDecision.UNRESOLVED

    # convenience boolean kept for existing callers
    def entails(self, claim: CompiledClaim, source_text: str) -> bool:
        return self.check(claim, source_text) is LayerPDecision.ENTAILED


# --- Real Layer P checker: a SEPARATE model/service boundary --------------- #
VERIFICATION_SYSTEM = (
    "You are a strict entailment judge. Given SOURCE, a CLAIM, and the EVIDENCE span, "
    'decide whether the evidence supports the claim. Return STRICT JSON only: '
    '{"decision":"entailed|unresolved|contradicted"}. '
    "Use 'entailed' ONLY if the evidence clearly supports the claim; 'contradicted' if it "
    "opposes; 'unresolved' if the evidence is insufficient. Never guess."
)


class LLMEntailmentChecker:
    """Layer P via a dedicated verification model — a boundary independent of extraction.

    Contract:
      - uses config.verification_model_id (NOT the extraction model);
      - returns a 3-state LayerPDecision;
      - a malformed/unknown model response defaults to UNRESOLVED (fail-closed: never
        auto-accept), so a broken judge cannot promote unsupported claims.
    Gated like AnthropicClient: with no key / no verification_model_id the underlying
    client refuses to run.
    """

    def __init__(self, client, config) -> None:
        self.client = client
        self.config = config
        self.last_raw: dict | None = None

    def check(self, claim: CompiledClaim, source_text: str) -> LayerPDecision:
        loc = claim.evidence.locators[0]
        span = source_text[int(loc["start"]):int(loc["end"])]
        user = (
            f"SOURCE:\n{source_text}\n\n"
            f"CLAIM: {claim.identity.subject_id} {claim.identity.predicate_id} "
            f"{claim.identity.obj} (polarity={claim.identity.polarity})\n"
            f"EVIDENCE: {span}"
        )
        try:
            resp = self.client.complete_json(self.config.verification_model_id, VERIFICATION_SYSTEM, user)
        except Exception:
            return LayerPDecision.UNRESOLVED  # fail-closed
        self.last_raw = resp if isinstance(resp, dict) else None
        decision = (resp or {}).get("decision") if isinstance(resp, dict) else None
        if decision == "entailed":
            return LayerPDecision.ENTAILED
        if decision == "contradicted":
            return LayerPDecision.CONTRADICTED
        return LayerPDecision.UNRESOLVED  # unknown/malformed -> fail-closed


# --------------------------------------------------------------------------- #
# Golden eval
# --------------------------------------------------------------------------- #
@dataclass
class GoldenExample:
    source: str
    expected_claims: set[tuple[str, str, str, str]]  # (subject,predicate,object,polarity)
    model_output: dict | None = None  # optional canned LLM output for the mock client


@dataclass
class GoldenReport:
    precision: float
    recall: float
    abstention_correct: int
    total: int
    hedge_preservation: float          # fraction of accepted claims with preserved modality
    unsupported_acceptance: float      # fraction of accepted claims failing Layer D (must be 0)
    structured_output_success: float   # fraction of examples that parsed without error


def _key(c: CompiledClaim) -> tuple[str, str, str, str]:
    return (c.identity.subject_id, c.identity.predicate_id, c.identity.obj, c.identity.polarity)


def run_golden(extractor: ClaimExtractor, examples: list[GoldenExample]) -> GoldenReport:
    tp = fp = fn = abst = 0
    accepted_total = 0
    hedge_ok = 0
    unsupported = 0
    parsed_ok = 0
    for ex in examples:
        try:
            claims = extractor.extract(ex.source, "golden", "rep").claims
            if getattr(extractor, "last_structured_output_ok", True):
                parsed_ok += 1
        except Exception:
            claims = []
        got = set()
        for c in claims:
            accepted_total += 1
            if not layer_d_ok(c, ex.source):
                unsupported += 1
                continue  # only Layer-D-valid claims count toward precision/recall
            if modality_preserved(c, ex.source):
                hedge_ok += 1
            got.add(_key(c))
        if not ex.expected_claims and not got:
            abst += 1
        tp += len(got & ex.expected_claims)
        fp += len(got - ex.expected_claims)
        fn += len(ex.expected_claims - got)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    valid_accepted = accepted_total - unsupported
    return GoldenReport(
        precision=precision,
        recall=recall,
        abstention_correct=abst,
        total=len(examples),
        hedge_preservation=(hedge_ok / valid_accepted) if valid_accepted else 1.0,
        unsupported_acceptance=(unsupported / accepted_total) if accepted_total else 0.0,
        structured_output_success=(parsed_ok / len(examples)) if examples else 1.0,
    )


# Initial acceptance thresholds (stage-1 contract; tuned before real-API canary).
ACCEPTANCE = {
    "structured_output_success": 0.99,
    "unsupported_claim_acceptance": 0.0,
    "hedge_preservation": 1.0,
    "min_precision": 0.95,
}


def passes_acceptance(report: GoldenReport) -> bool:
    return (
        report.structured_output_success >= ACCEPTANCE["structured_output_success"]
        and report.unsupported_acceptance <= ACCEPTANCE["unsupported_claim_acceptance"]
        and report.hedge_preservation >= ACCEPTANCE["hedge_preservation"]
        and report.precision >= ACCEPTANCE["min_precision"]
    )


# --------------------------------------------------------------------------- #
# Layer P golden eval — a boundary-specific harness
# --------------------------------------------------------------------------- #
@dataclass
class LayerPExample:
    subject: str
    predicate: str
    obj: str
    polarity: str
    source: str
    evidence_quote: str
    truly_entailed: bool  # ground-truth label


@dataclass
class LayerPReport:
    entailment_precision: float   # of ENTAILED verdicts, fraction truly entailed
    false_acceptance_rate: float  # of NON-entailed items, fraction wrongly ENTAILED
    accepted: int
    total: int


def _build_claim(ex: "LayerPExample"):
    from .hashing import sha256_hex
    from .models import ClaimAssertion, ClaimIdentity, Evidence

    start = ex.source.find(ex.evidence_quote)
    end = start + len(ex.evidence_quote)
    identity = ClaimIdentity.create(ex.subject, ex.predicate, ex.obj, ex.polarity, {})
    evidence = Evidence(
        evidence_id=sha256_hex(f"{ex.source}:{start}:{end}".encode()),
        source_object_hash="golden", representation_hash="rep",
        quote_hash=sha256_hex(ex.source[start:end].encode("utf-8")),
        locators=({"type": "text_span", "offset_unit": "unicode_codepoint",
                   "start": str(start), "end": str(end)},),
    )
    assertion = ClaimAssertion(
        assertion_id="a", claim_id=identity.claim_id, source_id="golden",
        evidence_ids=(evidence.evidence_id,), modality="asserted",
    )
    from .claims import CompiledClaim
    return CompiledClaim(identity=identity, assertion=assertion, evidence=evidence)


def run_layer_p_golden(checker: EntailmentChecker, examples: list["LayerPExample"]) -> LayerPReport:
    accepted_true = accepted_false = nonentailed = accepted = 0
    for ex in examples:
        decision = checker.check(_build_claim(ex), ex.source)
        is_entailed = decision is LayerPDecision.ENTAILED
        if not ex.truly_entailed:
            nonentailed += 1
        if is_entailed:
            accepted += 1
            if ex.truly_entailed:
                accepted_true += 1
            else:
                accepted_false += 1
    precision = accepted_true / accepted if accepted else 1.0
    far = accepted_false / nonentailed if nonentailed else 0.0
    return LayerPReport(precision, far, accepted, len(examples))


# Acceptance for the Layer P (verification) boundary.
LAYER_P_ACCEPTANCE = {"min_entailment_precision": 0.95, "max_false_acceptance_rate": 0.0}


def passes_layer_p_acceptance(report: LayerPReport) -> bool:
    return (
        report.entailment_precision >= LAYER_P_ACCEPTANCE["min_entailment_precision"]
        and report.false_acceptance_rate <= LAYER_P_ACCEPTANCE["max_false_acceptance_rate"]
    )
