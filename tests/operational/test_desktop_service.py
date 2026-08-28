from __future__ import annotations

from pathlib import Path

from wiki_spike.operational.desktop_service import DesktopMemoryService


PASSPHRASE = "desktop backup passphrase 2026"


def test_first_run_is_automatic_and_complete_user_flow_needs_no_cli(tmp_path: Path) -> None:
    root = tmp_path / "Wiki Memory" / "data"
    opened = DesktopMemoryService.open_or_initialize(root)
    assert opened.first_run is True
    service = opened.service
    assert service.status()["operational_ready"] is True

    created = service.save(
        memory_id=None,
        title="고객 회의",
        body="고객 회의에서 교체 일정을 9월로 확정했다.",
    )
    memory_id = created["memory_id"]
    assert service.browse("교체 일정")[0].memory_id == memory_id
    assert service.get(memory_id).source_name == "고객 회의"

    service.save(
        memory_id=memory_id,
        title="고객 회의 수정",
        body="고객 회의에서 복구 일정을 10월로 확정했다.",
    )
    assert service.browse("교체") == ()
    assert service.browse("복구 일정")[0].source_name == "고객 회의 수정"

    backup = tmp_path / "memory.wkbak"
    service.backup(backup, passphrase=PASSPHRASE)
    assert backup.is_file()

    service.delete(memory_id)
    assert service.browse("복구") == ()
    service.restore(backup, passphrase=PASSPHRASE)
    assert service.browse("복구")[0].memory_id == memory_id

    reopened = DesktopMemoryService.open_or_initialize(root)
    assert reopened.first_run is False
    assert reopened.service.get(memory_id).content.endswith("10월로 확정했다.")


def test_file_import_and_permission_repair_are_one_click_operations(tmp_path: Path) -> None:
    root = tmp_path / "data"
    service = DesktopMemoryService.open_or_initialize(root).service
    source = tmp_path / "회의 기록.md"
    source.write_text("파일로 받은 회의 기록을 암호화해 저장한다.", encoding="utf-8")

    imported = service.import_file(source)
    assert service.get(imported["memory_id"]).source_name == "회의 기록"

    (root / "keys/identity.key").chmod(0o644)
    repaired = service.repair_permissions()
    assert repaired["operational_ready"] is True
    assert (root / "keys/identity.key").stat().st_mode & 0o777 == 0o600


def test_body_only_note_gets_an_automatic_human_title(tmp_path: Path) -> None:
    service = DesktopMemoryService.open_or_initialize(tmp_path / "data").service

    saved = service.save(
        memory_id=None,
        title="",
        body="  다음 주 고객 미팅 준비  \n세부 일정과 담당자를 확인한다.",
    )

    hit = service.get(saved["memory_id"])
    assert hit.source_name == "다음 주 고객 미팅 준비"
    assert service.browse("담당자")[0].memory_id == hit.memory_id
