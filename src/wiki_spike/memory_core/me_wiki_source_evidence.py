"""Frozen me-wiki evidence state: contract-and-synthetic-fixture only, never GO."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .me_wiki_source_evidence_contracts import (
    EVIDENCE_DOMAIN,
    EVIDENCE_STATE,
    EVIDENCE_VERSION,
)
from .me_wiki_source_evidence_profile import MeWikiSourceProfileV1
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields

_EVIDENCE_FIELDS: Final = frozenset(
    {
        "evidence_version",
        "state",
        "body_reads",
        "source_mutation",
        "import_invoked",
        "serving_promotion",
        "authorized_go",
        "profile_digest",
        "fixture_digest",
        "evidence_digest",
    }
)


@dataclass(frozen=True, slots=True)
class MeWikiSourceEvidenceV1:
    evidence_version: str
    state: str
    body_reads: str
    source_mutation: bool
    import_invoked: bool
    serving_promotion: bool
    authorized_go: bool
    profile_digest: str
    fixture_digest: str
    evidence_digest: str

    @classmethod
    def create(cls, profile: MeWikiSourceProfileV1) -> MeWikiSourceEvidenceV1:
        provisional = cls(
            EVIDENCE_VERSION,
            EVIDENCE_STATE,
            "0",
            False,
            False,
            False,
            False,
            profile.profile_digest,
            profile.fixture_digest,
            "0" * 64,
        )
        return cls.from_mapping(
            provisional.to_mapping() | {"evidence_digest": provisional.computed_digest()}
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> MeWikiSourceEvidenceV1:
        strict_fields(data, _EVIDENCE_FIELDS)
        version = parse_string(data["evidence_version"], "evidence_version")
        if version != EVIDENCE_VERSION:
            raise UnsupportedContractVersion(f"unsupported evidence_version: {version!r}")
        state = parse_string(data["state"], "state")
        if state != EVIDENCE_STATE:
            raise InvalidContractValue(
                "state must be CONTRACT_AND_SYNTHETIC_FIXTURE_ONLY"
            )
        body_reads = parse_string(data["body_reads"], "body_reads")
        if body_reads != "0":
            raise InvalidContractValue("body_reads must be 0")
        for field in ("source_mutation", "import_invoked", "serving_promotion", "authorized_go"):
            if data[field] is not False:
                raise InvalidContractValue(f"{field} must be false")
        evidence = cls(
            version,
            state,
            body_reads,
            False,
            False,
            False,
            False,
            parse_digest(data["profile_digest"], "profile_digest"),
            parse_digest(data["fixture_digest"], "fixture_digest"),
            parse_digest(data["evidence_digest"], "evidence_digest"),
        )
        if evidence.evidence_digest != evidence.computed_digest():
            raise InvalidContractValue("evidence_digest does not bind evidence fields")
        return evidence

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["evidence_digest"]
        return canonical_ledger_digest(EVIDENCE_DOMAIN, body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "evidence_version": self.evidence_version,
            "state": self.state,
            "body_reads": self.body_reads,
            "source_mutation": self.source_mutation,
            "import_invoked": self.import_invoked,
            "serving_promotion": self.serving_promotion,
            "authorized_go": self.authorized_go,
            "profile_digest": self.profile_digest,
            "fixture_digest": self.fixture_digest,
            "evidence_digest": self.evidence_digest,
        }
