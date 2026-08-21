"""Fixture-only unified-db snapshot reader."""
from __future__ import annotations

from dataclasses import dataclass

from wiki_spike.memory_core.unified_db_snapshot_export import (
    FixtureExportAuthorityV1,
    UnifiedDbExportError,
    UnifiedDbExportRowV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_cursors import (
    SnapshotCursorMapV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
    UnifiedDbExportPlanV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_proof import (
    FixtureReadResultV1,
    UnifiedDbReadSafetyProofV1,
)


@dataclass(frozen=True, slots=True)
class StaticUnifiedDbFixtureReader:
    rows: tuple[UnifiedDbExportRowV1, ...]
    opening_proof: UnifiedDbReadSafetyProofV1
    closing_proof: UnifiedDbReadSafetyProofV1
    cursors: SnapshotCursorMapV1
    fixture_id: str
    fixture_digest: str
    row_set_digest: str

    def read_fixture_rows(
        self,
        authority: object,
        plan: UnifiedDbExportPlanV1,
        limit: int,
    ) -> FixtureReadResultV1:
        if not isinstance(authority, FixtureExportAuthorityV1):
            raise UnifiedDbExportError("fixture read requires fixture-only authority")
        if limit < 1:
            raise UnifiedDbExportError("fixture read limit must be positive")
        _ = plan
        return FixtureReadResultV1(
            self.rows[:limit],
            self.opening_proof,
            self.closing_proof,
            self.cursors,
            self.fixture_id,
            self.fixture_digest,
            self.row_set_digest,
        )
