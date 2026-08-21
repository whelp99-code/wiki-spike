"""Pre-DSN live-export preflight against an explicit mapper registry."""
from __future__ import annotations

from datetime import datetime
from typing import Protocol

from wiki_spike.applications.unified_db_live_export_verify import (
    LiveExportVerifyRequestV1,
    verify_live_export_plan,
)
from wiki_spike.memory_core.unified_db_live_export_mapping import (
    UnifiedDbLiveExportMappingV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


class MapperRegistry(Protocol):
    def approved_mapping(
        self, mapper_id: str, mapper_version: str
    ) -> UnifiedDbLiveExportMappingV1: ...


def preflight_live_export(
    request: LiveExportVerifyRequestV1,
    registry: MapperRegistry,
    now: datetime,
) -> None:
    approved = registry.approved_mapping(
        request.mapping.mapper_id, request.mapping.mapper_version
    )
    if approved.mapping_digest != request.mapping.mapping_digest:
        raise UnifiedDbExportError("live export refused: unapproved mapper")
    verify_live_export_plan(request, now)
