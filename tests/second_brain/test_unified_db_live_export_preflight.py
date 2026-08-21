"""Production empty registry, test-only mapping injection, and DSN unread."""
from __future__ import annotations

import ast
import inspect
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from tests.second_brain.unified_db_live_export_support import (
    MAPPER_ID,
    NOW,
    consistent_live_export_bundle,
    mapping_body,
)
from wiki_spike.applications.unified_db_live_export_preflight import (
    preflight_live_export,
)
from wiki_spike.applications.unified_db_live_export_verify import (
    LiveExportVerifyRequestV1,
)
from wiki_spike.composition.unified_db_live_export import refuse_live_unified_db_export
from wiki_spike.memory_core.unified_db_live_export_mapping import (
    UnifiedDbLiveExportMappingV1,
)
from wiki_spike.memory_core.unified_db_live_export_registry import (
    PRODUCTION_APPROVED_MAPPING_COUNT,
    PRODUCTION_MAPPER_REGISTRY,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


@dataclass(frozen=True, slots=True)
class ExplicitMapperRegistry:
    mappings: tuple[UnifiedDbLiveExportMappingV1, ...]

    def approved_mapping(
        self, mapper_id: str, mapper_version: str
    ) -> UnifiedDbLiveExportMappingV1:
        known = tuple(item for item in self.mappings if item.mapper_id == mapper_id)
        if not known:
            raise UnifiedDbExportError("live export refused: unapproved mapper")
        for item in known:
            if item.mapper_version == mapper_version:
                return item
        raise UnifiedDbExportError("live export refused: unknown mapper version")


def _request() -> LiveExportVerifyRequestV1:
    return LiveExportVerifyRequestV1.from_mappings(consistent_live_export_bundle())


def test_production_registry_contains_zero_approved_mappings() -> None:
    assert PRODUCTION_APPROVED_MAPPING_COUNT == 0
    with pytest.raises(UnifiedDbExportError, match="unapproved mapper"):
        _ = PRODUCTION_MAPPER_REGISTRY.approved_mapping(MAPPER_ID, "v1")


def test_preflight_refuses_unapproved_mapper() -> None:
    with pytest.raises(UnifiedDbExportError, match="unapproved mapper"):
        preflight_live_export(_request(), PRODUCTION_MAPPER_REGISTRY, NOW)


def test_preflight_accepts_only_explicit_test_mapping() -> None:
    request = _request()
    registry = ExplicitMapperRegistry((request.mapping,))
    preflight_live_export(request, registry, NOW)
    with pytest.raises(UnifiedDbExportError, match="unapproved mapper"):
        preflight_live_export(request, ExplicitMapperRegistry(()), NOW)


def test_preflight_rejects_unknown_mapper_version() -> None:
    request = _request()
    other = UnifiedDbLiveExportMappingV1.from_mapping(
        mapping_body(request.identity.identity_digest, mapper_version="v2")
    )
    with pytest.raises(UnifiedDbExportError, match="unknown mapper version"):
        preflight_live_export(request, ExplicitMapperRegistry((other,)), NOW)


def test_production_refuse_leaves_exact_dsn_bytes_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    support = tmp_path / "Library" / "Application Support"
    support.mkdir(parents=True)
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    with pytest.raises(UnifiedDbExportError, match="unapproved mapper"):
        refuse_live_unified_db_export(dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload


def test_production_composition_has_no_registry_or_env_override() -> None:
    composition = Path("src/wiki_spike/composition/unified_db_live_export.py")
    text = composition.read_text(encoding="utf-8")
    assert "os.environ" not in text
    assert "getenv" not in text
    assert "sys.argv" not in text
    refuse = inspect.signature(refuse_live_unified_db_export)
    assert "registry" not in refuse.parameters
    assert "mapping" not in refuse.parameters
    tree = ast.parse(text)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", maxsplit=1)[0])
    assert {"psycopg", "psycopg2", "asyncpg", "socket"}.isdisjoint(imported)
