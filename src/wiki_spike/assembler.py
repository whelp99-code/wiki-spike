"""Render + citation index + knowledge snapshot (Round 7 deltas #3.1, #3.5, #3.17).

- render_pages: one line per CLAIM (deduped), with source text ESCAPED (#3.17 XSS /
  markdown-injection mitigation).
- build_citation_index: aggregates ALL assertions per claim, so multiple independent
  sources for the same claim are preserved (#3.1).
- build_snapshot: the signed knowledge/snapshot.json that lets the next generation
  restore parent state from a verified artifact instead of trusting the DB (#3.3).
"""
from __future__ import annotations

import re

from .canonical import canonical_bytes
from .claims import CompiledClaim
from .hashing import canonical_hash, sha256_hex

_SLUG = re.compile(r"[^a-z0-9]+")
_MD_UNSAFE = re.compile(r"[\\`*_{}\[\]()#+\-!<>|]")


def _slug(s: str) -> str:
    return _SLUG.sub("-", s.lower()).strip("-")


def _page_path(subject: str) -> str:
    slug = _slug(subject)
    suffix = sha256_hex(subject.encode("utf-8"))[:12]
    stem = f"{slug}--{suffix}" if slug else f"entity--{suffix}"
    return f"wiki/{stem}.md"


def sanitize(text: str) -> str:
    """Escape markdown/HTML-significant characters in untrusted source-derived text."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_UNSAFE.sub(lambda m: "\\" + m.group(0), text)


def render_pages(accepted: list[CompiledClaim]) -> dict[str, bytes]:
    # Deduplicate by claim_id: a claim backed by N sources renders as ONE line.
    by_subject: dict[str, dict[str, CompiledClaim]] = {}
    for c in accepted:
        by_subject.setdefault(c.identity.subject_id, {})[c.identity.claim_id] = c
    pages: dict[str, bytes] = {}
    for subject, claims in sorted(by_subject.items()):
        lines = [f"# {sanitize(subject)}", ""]
        for cid, c in sorted(claims.items()):
            neg = "" if c.identity.polarity == "positive" else "does not "
            lines.append(
                f"- {sanitize(subject)} {neg}{sanitize(c.identity.predicate_id)} "
                f"{sanitize(c.identity.obj)} [{cid[:12]}]"
            )
        pages[_page_path(subject)] = ("\n".join(lines) + "\n").encode("utf-8")
    return pages


def build_citation_index(accepted: list[CompiledClaim]) -> bytes:
    # Aggregate every assertion per claim (multi-source preservation).
    idx: dict[str, list[dict]] = {}
    for c in accepted:
        idx.setdefault(c.identity.claim_id, []).append({
            "assertion_id": c.assertion.assertion_id,
            "source_id": c.assertion.source_id,
            "evidence_id": c.evidence.evidence_id,
            "locators": list(c.evidence.locators),
        })
    # sort assertion lists for determinism
    idx = {k: sorted(v, key=lambda a: a["assertion_id"]) for k, v in sorted(idx.items())}
    return canonical_bytes({"claims": idx})


def claim_to_record(c: CompiledClaim) -> dict:
    return {
        "identity": {"claim_id": c.identity.claim_id, "subject_id": c.identity.subject_id,
                     "predicate_id": c.identity.predicate_id, "object": c.identity.obj,
                     "polarity": c.identity.polarity, "scope": dict(c.identity.scope)},
        "assertion": {"assertion_id": c.assertion.assertion_id,
                      "claim_id": c.assertion.claim_id, "source_id": c.assertion.source_id,
                      "evidence_ids": list(c.assertion.evidence_ids),
                      "modality": c.assertion.modality},
        "evidence": {"evidence_id": c.evidence.evidence_id,
                     "source_object_hash": c.evidence.source_object_hash,
                     "representation_hash": c.evidence.representation_hash,
                     "quote_hash": c.evidence.quote_hash,
                     "locators": list(c.evidence.locators)},
    }


def claim_from_record(r: dict) -> CompiledClaim:
    from .models import ClaimAssertion, ClaimIdentity, Evidence
    i, a, e = r["identity"], r["assertion"], r["evidence"]
    identity = ClaimIdentity(i["claim_id"], i["subject_id"], i["predicate_id"],
                             i["object"], i["polarity"], dict(i.get("scope") or {}))
    if ClaimIdentity.create(identity.subject_id, identity.predicate_id, identity.obj,
                            identity.polarity, identity.scope).claim_id != identity.claim_id:
        raise ValueError("snapshot claim_id does not match canonical identity")
    evidence = Evidence(e["evidence_id"], e["source_object_hash"], e["representation_hash"],
                        e["quote_hash"], tuple(dict(x) for x in e["locators"]))
    assertion = ClaimAssertion(a["assertion_id"], a["claim_id"], a["source_id"],
                               tuple(a["evidence_ids"]), a["modality"])
    if assertion.claim_id != identity.claim_id:
        raise ValueError("snapshot assertion claim_id mismatch")
    if evidence.evidence_id not in assertion.evidence_ids:
        raise ValueError("snapshot evidence is not bound to assertion")
    return CompiledClaim(identity=identity, assertion=assertion, evidence=evidence)


def build_snapshot(accepted: list[CompiledClaim]) -> bytes:
    records = [claim_to_record(c) for c in accepted]
    records.sort(key=lambda r: r["assertion"]["assertion_id"])
    return canonical_bytes({"schema_version": "2", "accepted_claims": records})


def parse_snapshot(data: bytes) -> list[CompiledClaim]:
    import json
    obj = json.loads(data)
    if obj.get("schema_version") != "2" or not isinstance(obj.get("accepted_claims"), list):
        raise ValueError("unsupported or malformed knowledge snapshot")
    return [claim_from_record(r) for r in obj["accepted_claims"]]

def wiki_files_root(pages: dict[str, bytes]) -> str:
    return canonical_hash({path: sha256_hex(data) for path, data in pages.items()})
