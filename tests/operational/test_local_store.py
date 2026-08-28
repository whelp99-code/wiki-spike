from __future__ import annotations

import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from wiki_spike.operational.store import LocalMemoryError, LocalMemoryStore
from wiki_spike.infrastructure.encrypted_serving import EncryptedServingError


PASS = "correct horse battery staple 2026"


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _tables(root: Path) -> set[str]:
    connection = sqlite3.connect(root / "lifecycle.sqlite3")
    try:
        return {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    finally:
        connection.close()


def test_full_operating_lifecycle_uses_existing_core_and_survives_reopen(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    original_text = "고객 미팅에서 알파 프로젝트의 백업 정책을 확정했다."
    original = write(tmp_path / "meeting.md", original_text)

    store = LocalMemoryStore.initialize(root)
    remembered = store.remember(original)
    memory_id = remembered["memory_id"]
    assert store.status()["operational_ready"] is True
    assert store.status()["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    assert store.status()["parallel_memory_database"] is False
    assert (root.stat().st_mode & 0o777) == 0o700
    assert ((root / "keys/identity.key").stat().st_mode & 0o777) == 0o600
    assert ((root / "lifecycle.sqlite3").stat().st_mode & 0o777) == 0o600
    assert original_text.encode("utf-8") not in (root / "lifecycle.sqlite3").read_bytes()

    tables = _tables(root)
    assert {
        "canonical_artifact",
        "object_binding",
        "key_state",
        "state_delta",
        "generation",
        "deletion_state",
    } <= tables
    assert {"memory", "memory_token", "memory_version", "metadata"}.isdisjoint(tables)

    store.close()
    reopened = LocalMemoryStore(root)
    hits = reopened.recall("알파 백업")
    assert [hit.memory_id for hit in hits] == [memory_id]
    assert hits[0].content == original_text
    citation = reopened.citation(memory_id)
    assert citation["origin_name"] == "meeting.md"
    assert citation["origin_kind"] == "MARKDOWN_FILE"
    assert citation["origin_locator_kind"] == "WHOLE_SOURCE"
    assert citation["origin_sha256"] == remembered["source_sha256"]
    assert citation["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    assert citation["prior_versions"] == "0"

    corrected_text = "고객 미팅에서 베타 프로젝트의 복구 정책을 확정했다."
    corrected = write(tmp_path / "corrected.md", corrected_text)
    update = reopened.correct(memory_id, corrected)
    assert update["memory_id"] == memory_id
    assert update["content_sha256"] != remembered["content_sha256"]
    assert reopened.recall("알파 백업") == ()
    corrected_hits = reopened.recall("베타 복구")
    assert corrected_hits[0].content == corrected_text
    assert reopened.citation(memory_id)["prior_versions"] == "1"
    with pytest.raises(EncryptedServingError, match="not the active revision") as old_read:
        reopened.reader.read(
            artifact_id=remembered["artifact_id"],
            blob_id=remembered["blob_id"],
        )
    assert old_read.value.code == "artifact_not_active"

    connection = sqlite3.connect(root / "lifecycle.sqlite3")
    try:
        states = {
            row[0]
            for row in connection.execute(
                "SELECT custody_state FROM key_state ORDER BY custody_state"
            )
        }
        assert states == {"ACTIVE", "SUPERSEDED"}
        locator = connection.execute(
            "SELECT envelope_ref_id FROM state_delta "
            "WHERE object_id=? AND operation_kind='ADD'",
            (update["artifact_id"],),
        ).fetchone()[0]
        assert locator == update["blob_id"]
    finally:
        connection.close()

    backup = tmp_path / "memory.backup"
    backup_result = reopened.backup(backup, passphrase=PASS)
    assert backup_result["state"] == "WRITTEN"
    backup_bytes = backup.read_bytes()
    assert corrected_text.encode("utf-8") not in backup_bytes
    assert (root / "keys/identity.key").read_bytes() not in backup_bytes
    assert (backup.stat().st_mode & 0o777) == 0o600
    reopened.close()

    restored_root = tmp_path / "restored"
    restored = LocalMemoryStore.restore(backup, restored_root, passphrase=PASS)
    assert restored["state"] == "RESTORED"
    restored_store = LocalMemoryStore(restored_root)
    restored_hits = restored_store.recall("베타 복구")
    assert restored_hits[0].memory_id == memory_id
    assert restored_hits[0].content == corrected_text
    restored_store.close()

    deleting = LocalMemoryStore(root)
    forgotten = deleting.forget(memory_id)
    assert forgotten["state"] == "FORGOTTEN"
    assert forgotten["deleted_revisions"] == "2"
    assert deleting.recall("베타 복구") == ()
    status = deleting.status()
    assert status["active_memories"] == "0"
    assert status["forgotten_memories"] == "1"
    with pytest.raises(LocalMemoryError, match="active memory not found"):
        deleting.citation(memory_id)
    deleting.close()


def test_backup_refuses_wrong_passphrase_tamper_and_nonempty_target(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    store = LocalMemoryStore.initialize(root)
    store.remember(write(tmp_path / "note.md", "운영 백업 검증 문서"))
    backup = tmp_path / "memory.backup"
    store.backup(backup, passphrase=PASS)
    store.close()

    with pytest.raises(LocalMemoryError, match="authentication failed"):
        LocalMemoryStore.restore(
            backup,
            tmp_path / "wrong",
            passphrase="wrong passphrase 123",
        )

    container = json.loads(backup.read_text("utf-8"))
    ciphertext = container["ciphertext"]
    container["ciphertext"] = ("A" if ciphertext[0] != "A" else "B") + ciphertext[1:]
    tampered = tmp_path / "tampered.backup"
    tampered.write_text(
        json.dumps(container, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    with pytest.raises(LocalMemoryError):
        LocalMemoryStore.restore(tampered, tmp_path / "tampered-root", passphrase=PASS)

    occupied = tmp_path / "occupied"
    occupied.mkdir()
    write(occupied / "keep.txt", "do not replace silently")
    with pytest.raises(LocalMemoryError, match="not empty"):
        LocalMemoryStore.restore(backup, occupied, passphrase=PASS)
    assert (occupied / "keep.txt").read_text("utf-8") == "do not replace silently"


def test_replace_restore_preserves_previous_workspace(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source = LocalMemoryStore.initialize(source_root)
    source.remember(write(tmp_path / "source.md", "복구 대상 본문"))
    backup = tmp_path / "source.backup"
    source.backup(backup, passphrase=PASS)
    source.close()

    target = tmp_path / "target"
    previous = LocalMemoryStore.initialize(target)
    previous.remember(write(tmp_path / "previous.md", "기존 저장소 본문"))
    previous.close()
    result = LocalMemoryStore.restore(backup, target, passphrase=PASS, replace=True)
    prior_path = Path(result["replaced_workspace"])
    assert prior_path.is_dir()
    prior = LocalMemoryStore(prior_path)
    assert prior.recall("기존 저장소")
    prior.close()
    restored = LocalMemoryStore(target)
    assert restored.recall("복구 대상")
    restored.close()


def test_symlink_and_permission_boundaries_fail_closed(tmp_path: Path) -> None:
    root = tmp_path / "memory"
    store = LocalMemoryStore.initialize(root)
    source = write(tmp_path / "real.md", "심볼릭 링크 입력")
    link = tmp_path / "link.md"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks unavailable")
    with pytest.raises(LocalMemoryError, match="symlink"):
        store.remember(link)

    backup_link = tmp_path / "backup-link.wkbak"
    backup_link.symlink_to(tmp_path / "real-backup.wkbak")
    with pytest.raises(LocalMemoryError, match="symlink"):
        store.backup(backup_link, passphrase=PASS)

    valid_backup = tmp_path / "valid.wkbak"
    store.backup(valid_backup, passphrase=PASS)
    store.close()

    root_link = tmp_path / "root-link"
    root_link.symlink_to(root, target_is_directory=True)
    with pytest.raises(LocalMemoryError, match="symlink"):
        LocalMemoryStore(root_link)

    real_restore_target = tmp_path / "real-restore-target"
    real_restore_target.mkdir()
    restore_link = tmp_path / "restore-link"
    restore_link.symlink_to(real_restore_target, target_is_directory=True)
    with pytest.raises(LocalMemoryError, match="symlink"):
        LocalMemoryStore.restore(
            valid_backup,
            restore_link,
            passphrase=PASS,
        )

    os.chmod(root / "keys/identity.key", 0o644)
    with pytest.raises(LocalMemoryError, match="0600"):
        LocalMemoryStore(root)


def test_forget_requires_existing_active_memory(tmp_path: Path) -> None:
    store = LocalMemoryStore.initialize(tmp_path / "memory")
    with pytest.raises(LocalMemoryError, match="active memory not found"):
        store.forget("mem_" + "0" * 64)
    store.close()


def test_korean_attached_particle_is_searchable_without_plaintext_index(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    store = LocalMemoryStore.initialize(root)
    unique = "운영정책은 반드시 복구훈련으로 검증한다"
    store.remember(write(tmp_path / "korean.md", unique))
    hits = store.recall("운영정책")
    assert len(hits) == 1
    raw = (root / "lifecycle.sqlite3").read_bytes()
    assert "운영정책".encode("utf-8") not in raw
    assert "복구훈련".encode("utf-8") not in raw
    store.close()


def test_ciphertext_tamper_is_detected_before_content_is_returned(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    store = LocalMemoryStore.initialize(root)
    created = store.remember_text("암호문 변조 탐지", title="변조 검증")
    blob = root / "cas/objects" / created["blob_id"]
    blob.chmod(0o600)
    payload = blob.read_bytes()
    blob.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
    blob.chmod(0o444)
    with pytest.raises(LocalMemoryError, match="integrity"):
        store.recall("변조 탐지")
    store.close()


def test_concurrent_local_writes_are_serialized_and_all_recallable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    LocalMemoryStore.initialize(root).close()
    sources = [
        write(tmp_path / f"note-{index}.md", f"동시쓰기 검증 항목 {index}")
        for index in range(8)
    ]

    def remember(path: Path) -> str:
        store = LocalMemoryStore(root)
        try:
            return store.remember(path)["memory_id"]
        finally:
            store.close()

    with ThreadPoolExecutor(max_workers=4) as pool:
        memory_ids = list(pool.map(remember, sources))
    assert len(set(memory_ids)) == 8
    opened = LocalMemoryStore(root)
    hits = opened.recall("동시쓰기", limit=20)
    assert {hit.memory_id for hit in hits} == set(memory_ids)
    opened.close()


def test_init_refuses_to_mix_workspace_with_unrelated_files(tmp_path: Path) -> None:
    root = tmp_path / "memory"
    root.mkdir()
    write(root / "unrelated.txt", "keep separate")
    with pytest.raises(LocalMemoryError, match="must be empty"):
        LocalMemoryStore.initialize(root)
    assert (root / "unrelated.txt").read_text("utf-8") == "keep separate"


def test_direct_text_recent_and_correction_need_no_plaintext_temp_file(
    tmp_path: Path,
) -> None:
    root = tmp_path / "memory"
    store = LocalMemoryStore.initialize(root)

    first = store.remember_text("회의에서 로컬 백업 정책을 확정했다.", title="회의 메모")
    second = store.remember_text("고객 장비 교체 일정을 확인했다.", title="고객 일정")

    recent = store.recent()
    assert {item.memory_id for item in recent} == {second["memory_id"], first["memory_id"]}
    selected = store.get(first["memory_id"])
    assert selected.source_name == "회의 메모"
    assert selected.content == "회의에서 로컬 백업 정책을 확정했다."
    assert selected.score == "0"

    store.correct_text(
        first["memory_id"],
        "회의에서 로컬 복구 정책을 확정했다.",
        title="회의 메모 수정",
    )
    corrected = store.get(first["memory_id"])
    assert corrected.source_name == "회의 메모 수정"
    assert "복구 정책" in corrected.content
    assert store.recall("백업") == ()
    assert store.recall("복구 정책")[0].memory_id == first["memory_id"]
    store.close()


@pytest.mark.parametrize(
    ("text", "title", "message"),
    [
        ("", "제목", "empty"),
        ("본문", "", "title"),
    ],
)
def test_direct_text_rejects_empty_body_or_title(
    tmp_path: Path,
    text: str,
    title: str,
    message: str,
) -> None:
    store = LocalMemoryStore.initialize(tmp_path / "memory")
    with pytest.raises(LocalMemoryError, match=message):
        store.remember_text(text, title=title)
    store.close()
