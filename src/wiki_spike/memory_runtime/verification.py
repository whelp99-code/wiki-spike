"""P4-06 verification pipeline: deterministic, probabilistic, and policy layers."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, Sequence

from wiki_spike.memory_runtime.errors import InvalidContractValue
from .evidence_pack import EvidenceAtom, EvidencePack
from .service_contracts import MODALITY_RANK, content_id, verify_content_id, hex64, modality, safe_code, string_tuple

VERIFICATION_CLAIM_VERSION = "phase4-verification-claim-v1"
VERIFICATION_OUTCOME_VERSION = "phase4-verification-outcome-v1"


class DeterministicVerdict(str, Enum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    CONTRADICTED = "contradicted"
    LOCATOR_INVALID = "locator_invalid"


class ProbabilisticVerdict(str, Enum):
    ENTAILED = "entailed"
    UNRESOLVED = "unresolved"
    CONTRADICTED = "contradicted"
    UNAVAILABLE = "unavailable"


class PolicyVerdict(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_CLARIFICATION = "require_clarification"


@dataclass(frozen=True)
class VerificationClaim:
    verification_claim_version: str
    claim_id: str
    operation_id: str
    statement_digest: str
    modality: str
    evidence_atom_ids: tuple[str, ...]
    locator_refs: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        operation_id: str,
        statement_digest: str,
        modality: str,
        evidence_atom_ids: Sequence[str],
        locator_refs: Sequence[str],
    ) -> "VerificationClaim":
        atoms = tuple(sorted(set(evidence_atom_ids)))
        locators = tuple(sorted(set(locator_refs)))
        payload = {
            "verification_claim_version": VERIFICATION_CLAIM_VERSION,
            "operation_id": operation_id,
            "statement_digest": statement_digest,
            "modality": modality,
            "evidence_atom_ids": list(atoms),
            "locator_refs": list(locators),
        }
        return cls(claim_id=content_id("wiki.runtime.verification-claim.v1", payload), evidence_atom_ids=atoms, locator_refs=locators, **{k: v for k, v in payload.items() if k not in {"evidence_atom_ids", "locator_refs"}})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.verification_claim_version != VERIFICATION_CLAIM_VERSION:
            raise InvalidContractValue("unsupported verification claim version")
        hex64(self.operation_id, "operation_id")
        hex64(self.statement_digest, "statement_digest")
        modality(self.modality)
        string_tuple(self.evidence_atom_ids, "evidence_atom_ids", sorted_unique=True)
        string_tuple(self.locator_refs, "locator_refs", sorted_unique=True)
        verify_content_id(self.claim_id, "wiki.runtime.verification-claim.v1", self.to_mapping(), "claim_id", "verification claim_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "verification_claim_version": self.verification_claim_version,
            "claim_id": self.claim_id,
            "operation_id": self.operation_id,
            "statement_digest": self.statement_digest,
            "modality": self.modality,
            "evidence_atom_ids": list(self.evidence_atom_ids),
            "locator_refs": list(self.locator_refs),
        }


class ProbabilisticVerifier(Protocol):
    def verify(self, claim: VerificationClaim, atoms: Sequence[EvidenceAtom]) -> ProbabilisticVerdict: ...


class VerificationPolicy(Protocol):
    def decide(self, claim: VerificationClaim, atoms: Sequence[EvidenceAtom]) -> PolicyVerdict: ...


class DefaultVerificationPolicy:
    def decide(self, claim: VerificationClaim, atoms: Sequence[EvidenceAtom]) -> PolicyVerdict:
        if any(atom.instruction_like_data for atom in atoms):
            return PolicyVerdict.REQUIRE_CLARIFICATION
        return PolicyVerdict.ALLOW


@dataclass(frozen=True)
class VerificationOutcome:
    verification_outcome_version: str
    outcome_id: str
    claim_id: str
    deterministic_verdict: str
    probabilistic_verdict: str
    policy_verdict: str
    accepted: bool
    abstained: bool
    output_modality: str
    reason_codes: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        claim_id: str,
        deterministic_verdict: str,
        probabilistic_verdict: str,
        policy_verdict: str,
        accepted: bool,
        abstained: bool,
        output_modality: str,
        reason_codes: Sequence[str],
    ) -> "VerificationOutcome":
        reasons = tuple(sorted(set(reason_codes)))
        payload = {
            "verification_outcome_version": VERIFICATION_OUTCOME_VERSION,
            "claim_id": claim_id,
            "deterministic_verdict": deterministic_verdict,
            "probabilistic_verdict": probabilistic_verdict,
            "policy_verdict": policy_verdict,
            "accepted": accepted,
            "abstained": abstained,
            "output_modality": output_modality,
            "reason_codes": list(reasons),
        }
        return cls(outcome_id=content_id("wiki.runtime.verification-outcome.v1", payload), reason_codes=reasons, **{k: v for k, v in payload.items() if k != "reason_codes"})  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if self.verification_outcome_version != VERIFICATION_OUTCOME_VERSION:
            raise InvalidContractValue("unsupported verification outcome version")
        hex64(self.claim_id, "claim_id")
        DeterministicVerdict(self.deterministic_verdict)
        ProbabilisticVerdict(self.probabilistic_verdict)
        PolicyVerdict(self.policy_verdict)
        modality(self.output_modality, "output_modality")
        string_tuple(self.reason_codes, "reason_codes", sorted_unique=True, codes=True)
        if self.accepted and self.abstained:
            raise InvalidContractValue("verification cannot be both accepted and abstained")
        if self.accepted:
            if self.deterministic_verdict != DeterministicVerdict.SUPPORTED.value:
                raise InvalidContractValue("accepted outcome requires deterministic support")
            if self.probabilistic_verdict not in {
                ProbabilisticVerdict.ENTAILED.value,
                ProbabilisticVerdict.UNRESOLVED.value,
            }:
                raise InvalidContractValue("accepted outcome has invalid probabilistic verdict")
            if self.policy_verdict != PolicyVerdict.ALLOW.value:
                raise InvalidContractValue("accepted outcome requires policy allow")
        verify_content_id(self.outcome_id, "wiki.runtime.verification-outcome.v1", self.to_mapping(), "outcome_id", "verification outcome_id")

    def to_mapping(self) -> dict[str, object]:
        return {
            "verification_outcome_version": self.verification_outcome_version,
            "outcome_id": self.outcome_id,
            "claim_id": self.claim_id,
            "deterministic_verdict": self.deterministic_verdict,
            "probabilistic_verdict": self.probabilistic_verdict,
            "policy_verdict": self.policy_verdict,
            "accepted": self.accepted,
            "abstained": self.abstained,
            "output_modality": self.output_modality,
            "reason_codes": list(self.reason_codes),
        }


class VerificationPipeline:
    def __init__(
        self,
        probabilistic: ProbabilisticVerifier | None,
        policy: VerificationPolicy | None = None,
        *,
        require_layer_p: bool = False,
    ) -> None:
        self.probabilistic = probabilistic
        self.policy = policy or DefaultVerificationPolicy()
        self.require_layer_p = require_layer_p

    @staticmethod
    def _atoms_for(claim: VerificationClaim, pack: EvidencePack) -> tuple[EvidenceAtom, ...]:
        by_id = {atom.atom_id: atom for atom in pack.atoms}
        try:
            return tuple(by_id[atom_id] for atom_id in claim.evidence_atom_ids)
        except KeyError:
            return ()

    @staticmethod
    def _deterministic(claim: VerificationClaim, atoms: Sequence[EvidenceAtom]) -> DeterministicVerdict:
        if not atoms:
            return DeterministicVerdict.UNSUPPORTED
        if any(atom.statement_digest != claim.statement_digest for atom in atoms):
            return DeterministicVerdict.UNSUPPORTED
        atom_locators = {locator for atom in atoms for locator in atom.locator_refs}
        if not set(claim.locator_refs) <= atom_locators:
            return DeterministicVerdict.LOCATOR_INVALID
        if any(atom.support_kind == "contradicts" for atom in atoms):
            return DeterministicVerdict.CONTRADICTED
        if not any(atom.support_kind == "supports" for atom in atoms):
            return DeterministicVerdict.UNSUPPORTED
        return DeterministicVerdict.SUPPORTED

    def verify(self, claim: VerificationClaim, pack: EvidencePack) -> VerificationOutcome:
        atoms = self._atoms_for(claim, pack)
        deterministic = self._deterministic(claim, atoms)
        reasons: list[str] = []
        if deterministic is not DeterministicVerdict.SUPPORTED:
            reasons.append(deterministic.value)
            probabilistic = ProbabilisticVerdict.UNRESOLVED
            policy = PolicyVerdict.DENY
            accepted = False
            abstained = deterministic is DeterministicVerdict.UNSUPPORTED
        else:
            try:
                probabilistic = (
                    self.probabilistic.verify(claim, atoms)
                    if self.probabilistic is not None
                    else ProbabilisticVerdict.UNAVAILABLE
                )
            except Exception:
                probabilistic = ProbabilisticVerdict.UNAVAILABLE
            policy = self.policy.decide(claim, atoms)
            accepted = True
            abstained = False
            if probabilistic in {ProbabilisticVerdict.CONTRADICTED, ProbabilisticVerdict.UNAVAILABLE}:
                accepted = False
                abstained = True
                reasons.append(f"layer_p_{probabilistic.value}")
            elif probabilistic is ProbabilisticVerdict.UNRESOLVED and self.require_layer_p:
                accepted = False
                abstained = True
                reasons.append("layer_p_unresolved")
            if policy is not PolicyVerdict.ALLOW:
                accepted = False
                abstained = policy is PolicyVerdict.REQUIRE_CLARIFICATION
                reasons.append(f"policy_{policy.value}")
        minimum_modality = min(
            [claim.modality, *(atom.modality for atom in atoms)],
            key=lambda value: MODALITY_RANK[value],
        ) if atoms else claim.modality
        return VerificationOutcome.create(
            claim_id=claim.claim_id,
            deterministic_verdict=deterministic.value,
            probabilistic_verdict=probabilistic.value,
            policy_verdict=policy.value,
            accepted=accepted,
            abstained=abstained,
            output_modality=minimum_modality,
            reason_codes=reasons,
        )


__all__ = [
    "VERIFICATION_CLAIM_VERSION", "VERIFICATION_OUTCOME_VERSION",
    "DeterministicVerdict", "ProbabilisticVerdict", "PolicyVerdict",
    "VerificationClaim", "ProbabilisticVerifier", "VerificationPolicy",
    "DefaultVerificationPolicy", "VerificationOutcome", "VerificationPipeline",
]
