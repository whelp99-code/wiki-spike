"""Claim compilation (v3.3 §5-1, §16).

The real extractor will call a pinned LLM (extraction_model_id) once the selection
eval locks an exact model id. That id is still PENDING, so the spike ships a
DETERMINISTIC MOCK extractor. This keeps M1a runnable without a live model and
proves the surrounding infrastructure.

instruction/data boundary (§10): the source body is parsed as DATA. There is no
code path that executes instructions found inside the text. An injection string in
the body is inert here; it does not trigger quarantine (§7 false-positive fix).

Mock grammar (one claim per line):
    subject | predicate | object | polarity | key=val;key=val   [modality]
Lines that are blank, start with '#', or don't match are ignored (treated as prose).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .hashing import canonical_hash, sha256_hex
from .models import ClaimAssertion, ClaimIdentity, Evidence

_MODALITY = {"asserted", "likely", "possible"}


@dataclass(frozen=True)
class CompiledClaim:
    identity: ClaimIdentity
    assertion: ClaimAssertion
    evidence: Evidence


@dataclass(frozen=True)
class ExtractResult:
    claims: list[CompiledClaim]
    revokes: list[str]  # explicit claim_id tombstones (REVOKE directive)


class ClaimExtractor:  # protocol-ish base
    def extract(self, text: str, source_id: str, representation_hash: str) -> ExtractResult:
        raise NotImplementedError


def _parse_scope(raw: str) -> dict[str, str]:
    scope: dict[str, str] = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            scope[k.strip()] = v.strip()
    return scope


class DeterministicMockExtractor(ClaimExtractor):
    """Rule-based, fully deterministic. Stands in for the pinned LLM.

    Grammar:
      subject | predicate | object | polarity | key=val;... [modality]
      REVOKE | <full_claim_id>          -> explicit tombstone
    Offsets in locators are UNICODE CODE POINT offsets into the NFC/LF
    representation (offset_unit='unicode_codepoint').
    """

    def extract(self, text: str, source_id: str, representation_hash: str) -> ExtractResult:
        claims: list[CompiledClaim] = []
        revokes: list[str] = []
        offset = 0
        for line in text.splitlines(keepends=True):
            start = offset
            offset += len(line)
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.count("|") < 1:
                continue
            head = stripped.split("|", 1)[0].strip()
            if head == "REVOKE":
                revokes.append(stripped.split("|", 1)[1].strip())
                continue
            if stripped.count("|") < 4:
                continue
            fields = [f.strip() for f in stripped.split("|")]
            subject, predicate, obj, polarity, scope_raw = fields[:5]
            modality = fields[5].strip() if len(fields) > 5 and fields[5].strip() in _MODALITY else "asserted"
            if polarity not in ("positive", "negative"):
                continue
            scope = _parse_scope(scope_raw)
            span_start = start + line.index(stripped)
            span_end = span_start + len(stripped)
            quote = text[span_start:span_end]
            evidence = Evidence(
                evidence_id=sha256_hex(f"{source_id}:{span_start}:{span_end}".encode()),
                source_object_hash=source_id,  # source_id == content_hash in the spike
                representation_hash=representation_hash,
                quote_hash=sha256_hex(quote.encode("utf-8")),
                locators=(
                    {
                        "type": "text_span",
                        "offset_unit": "unicode_codepoint",
                        "start": str(span_start),
                        "end": str(span_end),
                    },
                ),
            )
            identity = ClaimIdentity.create(subject, predicate, obj, polarity, scope)
            assertion = ClaimAssertion(
                assertion_id=canonical_hash(
                    {
                        "claim_id": identity.claim_id,
                        "source_id": source_id,
                        "evidence_id": evidence.evidence_id,
                    }
                ),
                claim_id=identity.claim_id,
                source_id=source_id,
                evidence_ids=(evidence.evidence_id,),
                modality=modality,
            )
            claims.append(CompiledClaim(identity=identity, assertion=assertion, evidence=evidence))
        return ExtractResult(claims=claims, revokes=revokes)
