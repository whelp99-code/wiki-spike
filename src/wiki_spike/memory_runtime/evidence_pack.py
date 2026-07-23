"""P4-05 content-bound EvidencePack construction.

Retrieved content is represented as data references.  Text resembling system or
user instructions never becomes control input; the pack records an injection
flag for downstream verification instead.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .retrieval import RetrievalCandidate, RetrievalResult
from .service_contracts import (
    content_id, verify_content_id,
    hex64,
    modality,
    nonempty,
    safe_code,
    string_tuple,
)

EVIDENCE_ATOM_VERSION = "phase4-evidence-atom-v1"
EVIDENCE_PACK_VERSION = "phase4-evidence-pack-v1"

_INSTRUCTION_PATTERN = re.compile(
    r"(?i)(ignore (?:all|previous) instructions|system prompt|developer message|execute this|tool call|sudo\s|curl\s+https?://)"
)


@dataclass(frozen=True)
class EvidenceAtom:
    evidence_atom_version: str
    atom_id: str
    object_id: str
    revision_id: str
    generation_id: str
    statement_digest: str
    payload_digest: str
    locator_refs: tuple[str, ...]
    modality: str
    support_kind: str
    conflict_key: str | None
    instruction_like_data: bool

    @classmethod
    def create(
        cls,
        *,
        object_id: str,
        revision_id: str,
        generation_id: str,
        statement_digest: str,
        payload_digest: str,
        locator_refs: Sequence[str],
        modality: str,
        support_kind: str,
        conflict_key: str | None,
        instruction_like_data: bool,
    ) -> "EvidenceAtom":
        refs = tuple(sorted(set(locator_refs)))
        payload = {
            "evidence_atom_version": EVIDENCE_ATOM_VERSION,
            "object_id": object_id,
            "revision_id": revision_id,
            "generation_id": generation_id,
            "statement_digest": statement_digest,
            "payload_digest": payload_digest,
            "locator_refs": list(refs),
            "modality": modality,
            "support_kind": support_kind,
            "conflict_key": conflict_key,
            "instruction_like_data": instruction_like_data,
        }
        return cls(atom_id=content_id("wiki.runtime.evidence-atom.v1", payload), locator_refs=refs, **{k: v for k, v in payload.items() if k != "locator_refs"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.evidence_atom_version != EVIDENCE_ATOM_VERSION:
            raise InvalidContractValue("unsupported evidence atom version")
        for field in ("object_id", "revision_id", "generation_id"):
            nonempty(getattr(self, field), field)
        hex64(self.statement_digest, "statement_digest")
        hex64(self.payload_digest, "payload_digest")
        string_tuple(self.locator_refs, "locator_refs", sorted_unique=True)
        modality(self.modality)
        if safe_code(self.support_kind, "support_kind") not in {"supports", "contradicts", "context"}:
            raise InvalidContractValue("unsupported support_kind")
        if self.conflict_key is not None:
            nonempty(self.conflict_key, "conflict_key")
        if not isinstance(self.instruction_like_data, bool):
            raise InvalidContractValue("instruction_like_data must be boolean")
        verify_content_id(self.atom_id, "wiki.runtime.evidence-atom.v1", self.to_mapping(), "atom_id", "evidence atom_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "evidence_atom_version": self.evidence_atom_version,
            "atom_id": self.atom_id,
            "object_id": self.object_id,
            "revision_id": self.revision_id,
            "generation_id": self.generation_id,
            "statement_digest": self.statement_digest,
            "payload_digest": self.payload_digest,
            "locator_refs": list(self.locator_refs),
            "modality": self.modality,
            "support_kind": self.support_kind,
            "conflict_key": self.conflict_key,
            "instruction_like_data": self.instruction_like_data,
        }


@dataclass(frozen=True)
class EvidencePack:
    evidence_pack_version: str
    pack_id: str
    operation_id: str
    retrieval_result_id: str
    generation_id: str
    atoms: tuple[EvidenceAtom, ...]
    conflict_groups: tuple[tuple[str, tuple[str, ...]], ...]
    omission_codes: tuple[str, ...]
    degraded: bool

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        retrieval_result_id: str,
        generation_id: str,
        atoms: Sequence[EvidenceAtom],
        conflict_groups: Mapping[str, Sequence[str]],
        omission_codes: Sequence[str],
        degraded: bool,
    ) -> "EvidencePack":
        atom_values = tuple(sorted(atoms, key=lambda value: value.atom_id))
        groups = tuple(
            (key, tuple(sorted(set(values))))
            for key, values in sorted(conflict_groups.items())
        )
        omissions = tuple(sorted(set(omission_codes)))
        payload = {
            "evidence_pack_version": EVIDENCE_PACK_VERSION,
            "operation_id": operation_id,
            "retrieval_result_id": retrieval_result_id,
            "generation_id": generation_id,
            "atoms": [atom.to_mapping() for atom in atom_values],
            "conflict_groups": [
                {"conflict_key": key, "atom_ids": list(atom_ids)} for key, atom_ids in groups
            ],
            "omission_codes": list(omissions),
            "degraded": degraded,
        }
        return cls(pack_id=content_id("wiki.runtime.evidence-pack.v1", payload), atoms=atom_values, conflict_groups=groups, omission_codes=omissions, **{k: v for k, v in payload.items() if k not in {"atoms", "conflict_groups", "omission_codes"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.evidence_pack_version != EVIDENCE_PACK_VERSION:
            raise InvalidContractValue("unsupported evidence pack version")
        hex64(self.operation_id, "operation_id")
        hex64(self.retrieval_result_id, "retrieval_result_id")
        nonempty(self.generation_id, "generation_id")
        if not isinstance(self.degraded, bool):
            raise InvalidContractValue("degraded must be boolean")
        atom_ids = {atom.atom_id for atom in self.atoms}
        for key, values in self.conflict_groups:
            nonempty(key, "conflict_key")
            if len(values) < 2 or not set(values) <= atom_ids:
                raise InvalidContractValue("conflict group must bind at least two pack atoms")
        string_tuple(self.omission_codes, "omission_codes", sorted_unique=True, codes=True)
        verify_content_id(self.pack_id, "wiki.runtime.evidence-pack.v1", self.to_mapping(), "pack_id", "evidence pack_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "evidence_pack_version": self.evidence_pack_version,
            "pack_id": self.pack_id,
            "operation_id": self.operation_id,
            "retrieval_result_id": self.retrieval_result_id,
            "generation_id": self.generation_id,
            "atoms": [atom.to_mapping() for atom in self.atoms],
            "conflict_groups": [
                {"conflict_key": key, "atom_ids": list(atom_ids)}
                for key, atom_ids in self.conflict_groups
            ],
            "omission_codes": list(self.omission_codes),
            "degraded": self.degraded,
        }


class EvidencePackBuilder:
    def build(
        self,
        *,
        operation_id: str,
        retrieval: RetrievalResult,
        statement_digests: Mapping[str, str],
        modalities: Mapping[str, str] | None = None,
        support_kinds: Mapping[str, str] | None = None,
        sampled_text: Mapping[str, str] | None = None,
    ) -> EvidencePack:
        modalities = modalities or {}
        support_kinds = support_kinds or {}
        sampled_text = sampled_text or {}
        atoms: list[EvidenceAtom] = []
        omissions: set[str] = set()
        groups: dict[str, list[str]] = {}
        for candidate in retrieval.candidates:
            digest = statement_digests.get(candidate.object_id)
            if digest is None:
                omissions.add("statement_digest_missing")
                continue
            text = sampled_text.get(candidate.object_id, "")
            atom = EvidenceAtom.create(
                object_id=candidate.object_id,
                revision_id=candidate.revision_id,
                generation_id=retrieval.generation_id,
                statement_digest=digest,
                payload_digest=candidate.payload_digest,
                locator_refs=candidate.locator_refs,
                modality=modalities.get(candidate.object_id, "asserted"),
                support_kind=support_kinds.get(candidate.object_id, "supports"),
                conflict_key=candidate.conflict_key,
                instruction_like_data=bool(_INSTRUCTION_PATTERN.search(text)),
            )
            atoms.append(atom)
            if atom.conflict_key is not None:
                groups.setdefault(atom.conflict_key, []).append(atom.atom_id)
        groups = {key: values for key, values in groups.items() if len(values) >= 2}
        if retrieval.omitted_candidate_ids:
            omissions.add("retrieval_candidates_omitted")
        if retrieval.stale_detected:
            omissions.add("stale_projection_filtered")
        if retrieval.degraded_channels:
            omissions.add("optional_channel_degraded")
        return EvidencePack.create(
            operation_id=operation_id,
            retrieval_result_id=retrieval.result_id,
            generation_id=retrieval.generation_id,
            atoms=atoms,
            conflict_groups=groups,
            omission_codes=sorted(omissions),
            degraded=bool(retrieval.degraded_channels),
        )


__all__ = [
    "EVIDENCE_ATOM_VERSION", "EVIDENCE_PACK_VERSION", "EvidenceAtom",
    "EvidencePack", "EvidencePackBuilder",
]
