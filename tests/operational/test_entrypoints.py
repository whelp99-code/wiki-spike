from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from wiki_spike.operational import cli
from wiki_spike.operational.desktop_service import DesktopMemoryService


PASS = "entrypoint backup passphrase 2026"


def test_support_cli_and_desktop_check_use_the_same_operational_store(
    tmp_path: Path,
    capsys,
) -> None:
    root = tmp_path / "data"
    assert cli.main(["--root", str(root), "--json", "init"]) == 0
    _ = capsys.readouterr()
    assert cli.main(
        [
            "--root",
            str(root),
            "--json",
            "remember",
            "--text",
            "일반 사용자는 앱에서 메모를 바로 저장한다.",
            "--title",
            "사용 원칙",
        ]
    ) == 0
    remembered = json.loads(capsys.readouterr().out)
    assert remembered["source_name"] == "사용 원칙"

    assert cli.main(["--root", str(root), "--json", "recall", "일반 사용자"]) == 0
    output = capsys.readouterr().out
    assert "사용 원칙" in output
    assert "일반 사용자는 앱에서" in output

    checked = DesktopMemoryService(root).status()
    assert checked["operational_ready"] is True
    assert checked["active_memories"] == "1"
    assert checked["network_enabled"] is False


def test_desktop_main_check_initializes_a_new_workspace_without_opening_a_window(
    tmp_path: Path,
    capsys,
) -> None:
    if sys.platform != "darwin":
        pytest.skip("native desktop check is macOS-only")
    from wiki_spike.operational import desktop

    root = tmp_path / "first-run"
    assert desktop.main(["--check", "--root", str(root)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["first_run"] is True
    assert payload["state"] == "READY"
    assert (root / "lifecycle.sqlite3").is_file()
    assert (root / "cas/objects").is_dir()
    assert (root / "keys/platform").is_dir()
