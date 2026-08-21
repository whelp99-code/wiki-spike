"""Opening and closing read-safety proofs for fixture export."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_ledger_contracts import canonical_ledger_digest
from .snapshot_import_parse import parse_digest, parse_string, strict_fields
from .unified_db_snapshot_export import (
    UnifiedDbExportRowV1,
    parse_decimal,
)
from .unified_db_snapshot_export_cursors import SnapshotCursorMapV1

PROOF_VERSION: Final = "second-brain-unified-db-export-read-safety-proof-v1"
_PROOF_FIELDS: Final = frozenset(
    {
        "proof_version",
        "phase",
        "isolation",
        "read_only",
        "deferrable",
        "writer_count",
        "db_commitment",
        "catalog_commitment",
        "source_commitment",
        "data_root_commitment",
        "proof_digest",
    }
)


@dataclass(frozen=True, slots=True)
class UnifiedDbReadSafetyProofV1:
    proof_version: str
    phase: str
    isolation: str
    read_only: bool
    deferrable: bool
    writer_count: str
    db_commitment: str
    catalog_commitment: str
    source_commitment: str
    data_root_commitment: str
    proof_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> UnifiedDbReadSafetyProofV1:
        strict_fields(data, _PROOF_FIELDS)
        version = parse_string(data["proof_version"], "proof_version")
        if version != PROOF_VERSION:
            raise UnsupportedContractVersion(f"unsupported proof_version: {version!r}")
        phase = parse_string(data["phase"], "phase")
        if phase not in {"OPENING", "CLOSING"}:
            raise InvalidContractValue("phase must be OPENING or CLOSING")
        isolation = parse_string(data["isolation"], "isolation")
        if isolation != "SERIALIZABLE":
            raise InvalidContractValue("isolation must be SERIALIZABLE")
        if data["read_only"] is not True or data["deferrable"] is not True:
            raise InvalidContractValue("read_only and deferrable must be true")
        proof = cls(
            version,
            phase,
            isolation,
            True,
            True,
            parse_decimal(data["writer_count"], "writer_count"),
            parse_digest(data["db_commitment"], "db_commitment"),
            parse_digest(data["catalog_commitment"], "catalog_commitment"),
            parse_digest(data["source_commitment"], "source_commitment"),
            parse_digest(data["data_root_commitment"], "data_root_commitment"),
            parse_digest(data["proof_digest"], "proof_digest"),
        )
        if proof.proof_digest != proof.computed_digest():
            raise InvalidContractValue("proof_digest does not bind proof fields")
        return proof

    def computed_digest(self) -> str:
        body = self.to_mapping()
        del body["proof_digest"]
        return canonical_ledger_digest("unified-db-export-read-safety-proof-v1", body)

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "proof_version": self.proof_version,
            "phase": self.phase,
            "isolation": self.isolation,
            "read_only": self.read_only,
            "deferrable": self.deferrable,
            "writer_count": self.writer_count,
            "db_commitment": self.db_commitment,
            "catalog_commitment": self.catalog_commitment,
            "source_commitment": self.source_commitment,
            "data_root_commitment": self.data_root_commitment,
            "proof_digest": self.proof_digest,
        }


@dataclass(frozen=True, slots=True)
class FixtureReadResultV1:
    rows: tuple[UnifiedDbExportRowV1, ...]
    opening_proof: UnifiedDbReadSafetyProofV1
    closing_proof: UnifiedDbReadSafetyProofV1
    cursors: SnapshotCursorMapV1
    fixture_id: str
    fixture_digest: str
    row_set_digest: str
