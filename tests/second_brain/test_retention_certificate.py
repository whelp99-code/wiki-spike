"""Non-destructive retention certificates reject destructive actions."""
from __future__ import annotations

import json
from pathlib import Path

CLI = Path("scripts/second_brain_retention_certificate.py")
_CONSERVATION = "a" * 64
_RESTORE = "b" * 64


def _run(argv: list[str]) -> int:
    from scripts.second_brain_retention_certificate import main

    return main(argv)


def _issue_args(dest: Path) -> list[str]:
    return [
        "--dest",
        str(dest),
        "--conservation-digest",
        _CONSERVATION,
        "--restore-digest",
        _RESTORE,
    ]


def test_destructive_flag_is_rejected_and_dest_is_not_written(tmp_path: Path) -> None:
    dest = tmp_path / "retention-certificate.json"
    source = tmp_path / "source"
    source.mkdir()
    marker = source / "keep.md"
    marker.write_text("keep\n", encoding="utf-8")

    code = _run(
        [
            "--dest",
            str(dest),
            "--destructive-action-authorized",
            "true",
        ]
    )

    assert code != 0
    assert not dest.exists()
    assert marker.read_text(encoding="utf-8") == "keep\n"


def test_certificate_without_conservation_or_restore_evidence_is_not_written(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "retention-certificate.json"

    code = _run(["--dest", str(dest)])

    assert code != 0
    assert not dest.exists()


def test_non_destructive_certificate_has_false_flags(tmp_path: Path) -> None:
    dest = tmp_path / "retention-certificate.json"

    code = _run(_issue_args(dest))

    assert code == 0
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["destructive_action_authorized"] == "false"
    assert payload["source_deletion_authorized"] == "false"
    assert payload["key_deletion_authorized"] == "false"
    assert payload["retention_hours"] == "2160"
    assert isinstance(payload["retention_hours"], str)
    assert payload["conservation_digest"] == _CONSERVATION
    assert payload["restore_digest"] == _RESTORE
    assert payload["conservation_digest"] != payload["restore_digest"]
    assert "signatures" not in payload
    assert dest.stat().st_mode & 0o222 == 0


def test_early_expiry_is_refused_and_dest_is_not_written(tmp_path: Path) -> None:
    dest = tmp_path / "retention-certificate.json"

    code = _run([*_issue_args(dest), "--retention-hours", "2159"])

    assert code != 0
    assert not dest.exists()


def test_source_purge_request_is_refused_and_dest_is_not_written(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "retention-certificate.json"

    code = _run([*_issue_args(dest), "--source-deletion-authorized", "true"])

    assert code != 0
    assert not dest.exists()


def test_identical_conservation_and_restore_digests_are_refused(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "retention-certificate.json"

    code = _run(
        [
            "--dest",
            str(dest),
            "--conservation-digest",
            _CONSERVATION,
            "--restore-digest",
            _CONSERVATION,
        ]
    )

    assert code != 0
    assert not dest.exists()


def test_existing_dest_is_refused(tmp_path: Path) -> None:
    dest = tmp_path / "retention-certificate.json"
    dest.write_text("{}\n", encoding="utf-8")

    code = _run(["--dest", str(dest)])

    assert code != 0
    assert dest.read_text(encoding="utf-8") == "{}\n"
