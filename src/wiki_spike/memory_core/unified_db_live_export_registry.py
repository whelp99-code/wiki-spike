"""Hard-coded production mapper registry. Intentionally empty."""
from __future__ import annotations

from typing import Final

from .unified_db_live_export_mapping import UnifiedDbLiveExportMappingV1
from .unified_db_snapshot_export import UnifiedDbExportError

PRODUCTION_APPROVED_MAPPINGS: Final[tuple[UnifiedDbLiveExportMappingV1, ...]] = ()
PRODUCTION_APPROVED_MAPPING_COUNT: Final = len(PRODUCTION_APPROVED_MAPPINGS)


class ProductionMapperRegistry:
    """Lookup over the empty production mapping tuple. Fail closed."""

    def __init__(
        self,
        approved_mappings: tuple[UnifiedDbLiveExportMappingV1, ...],
    ) -> None:
        self._approved_mappings: tuple[UnifiedDbLiveExportMappingV1, ...] = (
            approved_mappings
        )

    def approved_mapping(
        self, mapper_id: str, mapper_version: str
    ) -> UnifiedDbLiveExportMappingV1:
        known_mapper_id = False
        for item in self._approved_mappings:
            if item.mapper_id == mapper_id:
                known_mapper_id = True
            if item.mapper_id == mapper_id and item.mapper_version == mapper_version:
                return item
        if not known_mapper_id:
            raise UnifiedDbExportError("live export refused: unapproved mapper")
        raise UnifiedDbExportError("live export refused: unknown mapper version")


PRODUCTION_MAPPER_REGISTRY: Final = ProductionMapperRegistry(
    PRODUCTION_APPROVED_MAPPINGS
)
