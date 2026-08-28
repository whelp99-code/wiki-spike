from __future__ import annotations

from pathlib import Path

import pytest

from wiki_spike.operational.agent import MAX_RESPONSE_BYTES, ReadOnlyMemoryTools, _serialized_size
from wiki_spike.operational.desktop_service import DesktopMemoryService
from wiki_spike.operational.store import LocalMemoryError


def test_ai_read_only_tools_see_the_same_memory_and_real_source(tmp_path: Path) -> None:
    root = tmp_path / "data"
    service = DesktopMemoryService.open_or_initialize(root).service
    source = tmp_path / "고객 회의.md"
    source.write_text("고객 회의에서 10월 복구 일정을 확정했다.", encoding="utf-8")
    created = service.import_file(source)

    tools = ReadOnlyMemoryTools(service.store)
    recalled = tools.handle(
        {"tool": "memory_recall", "params": {"query": "복구 일정", "limit": "10"}}
    )
    assert recalled["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    assert recalled["results"][0]["memory_id"] == created["memory_id"]
    assert "10월 복구" in recalled["results"][0]["content"]
    assert _serialized_size(recalled) <= MAX_RESPONSE_BYTES

    sourced = tools.handle(
        {"tool": "memory_source", "params": {"memory_id": created["memory_id"]}}
    )
    assert sourced["memory"]["memory_id"] == created["memory_id"]
    assert sourced["citation"]["origin_name"] == "고객 회의.md"
    assert sourced["citation"]["origin_kind"] == "MARKDOWN_FILE"
    assert sourced["citation"]["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    service.store.close()


def test_ai_tool_surface_has_no_write_operation(tmp_path: Path) -> None:
    root = tmp_path / "data"
    service = DesktopMemoryService.open_or_initialize(root).service
    created = service.save(memory_id=None, title="운영 원칙", body="읽기 전용 도구 검증")
    before = service.events(limit=100)
    tools = ReadOnlyMemoryTools(service.store)

    for tool in ("remember", "correct", "forget", "backup", "restore", "memory_write"):
        with pytest.raises(LocalMemoryError, match="only memory_recall and memory_source"):
            tools.handle({"tool": tool, "params": {"memory_id": created["memory_id"]}})

    after = service.events(limit=100)
    assert after == before
    service.store.close()
