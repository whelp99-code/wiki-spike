"""Deterministic text presentation of one recall answer.

DB-04 requires a user-facing surface that co-displays conflicting memories with
their citations, marks an approved current decision as the winner without
erasing what it beat, and shows an explicit abstention rather than inventing a
result. This product ships a CLI and a library, so that surface is text. The
renderer is pure: it reads one answer and returns a string.
"""
from __future__ import annotations

from wiki_spike.memory_runtime.second_brain_recall import (
    RuntimeRecallAnswerV2, RuntimeRecallResultV2,
)

_ABSTENTION_REASONS = {
    "approval_verification": "no candidate has a reviewed approval; recall will not serve review state",
    "citation_verification": "approved candidates exist but none carries verifiable citation evidence",
    "conflict": "conflicting approved candidates hold equal support; no winner may be invented",
    "authorization": "the request is not authorized for this workspace and capability",
    "deletion": "a deletion obligation is unsatisfied",
    "consent": "a consent obligation is unsatisfied",
    "global_floor": "the global safety floor is not satisfied",
    "binding": "the authority binding check did not pass",
    "recovery": "the recovery check did not pass",
    "route": "the route check did not pass",
    "cohort": "the cohort check did not pass",
    "pinned_drift": "the request does not match the pinned snapshot it claims",
    "continuation_invalid": "the supplied continuation is expired or does not match its cursor",
    "continuation_drift": "the supplied continuation belongs to a different serving authority",
    "cursor_without_continuation": "a cursor was supplied without its signed continuation",
}

_HEADER = "RECALL ANSWER"


def _describe(reason: str | None) -> str:
    if reason is None:
        return "no reason recorded"
    return _ABSTENTION_REASONS.get(reason, "unrecognised reason; treat as refusal")


def _render_result(position: int, result: RuntimeRecallResultV2) -> list[str]:
    marker = "WINNER OF AN OPEN CONFLICT" if result.contrary_citations else "APPROVED RESULT"
    lines = [
        f"[{position}] {marker}",
        f"    candidate:      {result.candidate_ref}",
        f"    revision:       {result.revision_ref}",
        f"    content digest: {result.content_digest}",
        f"    support count:  {result.support_count}",
        "    citations:",
    ]
    lines.extend(f"      - {item.source_ref}  {item.citation_digest}" for item in result.citations)
    if result.contrary_citations:
        lines.append("    contrary evidence it was ranked above (retained, not erased):")
        lines.extend(
            f"      - {item.candidate_ref}  {item.source_ref}  {item.citation_digest}"
            for item in result.contrary_citations
        )
    if result.unverified_conflicts:
        lines.append("    conflicting approved candidates withheld for missing citations:")
        lines.extend(f"      - {ref}" for ref in result.unverified_conflicts)
        lines.append("      this result is contested; it is not an unopposed answer")
    return lines


def render_recall_answer(answer: RuntimeRecallAnswerV2) -> str:
    """Render one answer as deterministic text, newline-terminated."""
    lines = [_HEADER, "=" * len(_HEADER), ""]
    if answer.abstained:
        lines.append("ABSTAINED - no winner was selected and no result is served")
        lines.append(f"reason: {answer.reason}")
        lines.append(f"        {_describe(answer.reason)}")
    else:
        lines.append(f"{len(answer.results)} result(s), ordered by support then candidate reference")
        for position, result in enumerate(answer.results, start=1):
            lines.append("")
            lines.extend(_render_result(position, result))
    lines.append("")
    lines.append(f"more pages available: {'yes' if answer.has_more else 'no'}")
    return "\n".join(lines) + "\n"


__all__ = ["render_recall_answer"]
