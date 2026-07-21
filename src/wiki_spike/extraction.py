"""LLM extraction + Layer D deterministic verification (P0 first slice).

The LLM proposes claims as STRUCTURED JSON. Layer D is a deterministic gate: every
claim must carry an evidence quote that appears verbatim in the source at the stated
offset. Claims that fail Layer D are DROPPED (REFUSE-TO-WRITE) — the model cannot
introduce unsupported facts. Layer P (entailment) is a separate, probabilistic check
(see verify.py) applied on top.

This mirrors the deterministic mock extractor's output type (ExtractResult) so it is
a drop-in behind the same ClaimExtractor interface.
"""
from __future__ import annotations

import unicodedata

from .claims import ClaimExtractor, CompiledClaim, ExtractResult
from .hashing import canonical_hash, sha256_hex
from .llm import LLMClient, LLMConfig
from .models import ClaimAssertion, ClaimIdentity, Evidence

EXTRACTION_SYSTEM = (
    "You extract atomic factual claims from the SOURCE. Return STRICT JSON only:\n"
    '{"claims":[{"subject","predicate","object","polarity":"positive|negative",'
    '"modality":"asserted|likely|possible","scope":{},"evidence_quote","offset":[start,end]}],'
    '"abstain":false}\n'
    "Rules: use ONLY facts present in the SOURCE; evidence_quote MUST be an exact substring "
    "of the SOURCE; never raise the certainty of a hedged statement; if nothing is supported, "
    'return {"claims":[],"abstain":true}.'
)

_REQUIRED = ("subject", "predicate", "object", "polarity", "evidence_quote", "offset")


class SchemaError(ValueError):
    pass


def _validate_claim(obj: dict) -> None:
    for k in _REQUIRED:
        if k not in obj:
            raise SchemaError(f"missing field {k!r}")
    if obj["polarity"] not in ("positive", "negative"):
        raise SchemaError("bad polarity")
    off = obj["offset"]
    if not (isinstance(off, list) and len(off) == 2):
        raise SchemaError("bad offset")


class LLMExtractor(ClaimExtractor):
    def __init__(self, client: LLMClient, config: LLMConfig, entailment_checker=None) -> None:
        self.client = client
        self.config = config
        self.entailment_checker = entailment_checker
        self.last_structured_output_ok = True
        self.last_layer_p_decisions: list[str] = []

    def extract(self, text: str, source_id: str, representation_hash: str) -> ExtractResult:
        norm = unicodedata.normalize("NFC", text)
        resp = self.client.complete_json(
            self.config.extraction_model_id, EXTRACTION_SYSTEM, f"SOURCE:\n{norm}"
        )
        self.last_structured_output_ok = isinstance(resp, dict)
        self.last_layer_p_decisions = []
        if not isinstance(resp, dict) or not isinstance(resp.get("claims", []), list):
            self.last_structured_output_ok = False
            return ExtractResult(claims=[], revokes=[])
        claims: list[CompiledClaim] = []
        for raw in resp.get("claims", []):
            if not isinstance(raw, dict):
                self.last_structured_output_ok = False
                continue
            try:
                _validate_claim(raw)
            except (SchemaError, TypeError, ValueError):
                self.last_structured_output_ok = False
                continue  # malformed proposal -> drop
            start, end = int(raw["offset"][0]), int(raw["offset"][1])
            quote = raw["evidence_quote"]
            # --- Layer D (deterministic): the quote must appear verbatim at offset ---
            if not (0 <= start < end <= len(norm)) or norm[start:end] != quote:
                # tolerate exact-substring-without-offset, else DROP
                # Recover only when the quote occurs exactly once; otherwise the
                # evidence locator is ambiguous and must be refused.
                if isinstance(quote, str) and quote and norm.count(quote) == 1:
                    idx = norm.find(quote)
                    start, end = idx, idx + len(quote)
                else:
                    continue  # REFUSE-TO-WRITE: unsupported/ambiguous claim
            modality = raw.get("modality", "asserted")
            if modality not in ("asserted", "likely", "possible"):
                modality = "asserted"
            # Hedge preservation: a hedged source span may not be promoted to asserted.
            from .verify import preserve_modality
            modality = preserve_modality(norm[start:end], modality)
            scope = {str(k): str(v) for k, v in (raw.get("scope") or {}).items()}
            evidence = Evidence(
                evidence_id=sha256_hex(f"{source_id}:{start}:{end}".encode()),
                source_object_hash=source_id,
                representation_hash=representation_hash,
                quote_hash=sha256_hex(norm[start:end].encode("utf-8")),
                locators=({"type": "text_span", "offset_unit": "unicode_codepoint",
                           "start": str(start), "end": str(end)},),
            )
            identity = ClaimIdentity.create(
                str(raw["subject"]), str(raw["predicate"]), str(raw["object"]),
                raw["polarity"], scope,
            )
            assertion = ClaimAssertion(
                assertion_id=canonical_hash({"claim_id": identity.claim_id,
                                             "source_id": source_id,
                                             "evidence_id": evidence.evidence_id}),
                claim_id=identity.claim_id, source_id=source_id,
                evidence_ids=(evidence.evidence_id,), modality=modality,
            )
            compiled = CompiledClaim(identity=identity, assertion=assertion, evidence=evidence)
            if self.entailment_checker is not None:
                from .verify import LayerPDecision
                decision = self.entailment_checker.check(compiled, norm)
                self.last_layer_p_decisions.append(str(decision.value))
                if decision is not LayerPDecision.ENTAILED:
                    continue
            claims.append(compiled)
        # LLM extraction never revokes (untrusted); revokes only via trusted policy.
        return ExtractResult(claims=claims, revokes=[])
