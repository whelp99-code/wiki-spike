"""Public-only pending decision signature report."""
from __future__ import annotations

import subprocess
from pathlib import Path

_RUNNER = Path("scripts/report_pending_decision_signatures.sh")
_SIGNABLE = (
    "DB-01",
    "DB-02-claude-memory-bank",
    "DB-02-codex",
    "DB-02-git",
    "DB-02-markdown",
    "DB-03-legacy-mem0-rag",
    "DB-03-me-wiki",
    "DB-03-unified-db",
    "DB-07",
)
_BLOCKED = ("DB-05 global",)


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(_RUNNER), *args],
        capture_output=True,
        check=False,
        text=True,
    )


def test_report_prints_usage_when_help_requested() -> None:
    result = _run("--help")
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    assert "public" in result.stdout.casefold() or "envelope" in result.stdout.casefold()
    assert "--private-key" not in combined
    assert "--dsn-fd" not in combined
    assert "BEGIN" not in combined


def test_report_refuses_extra_args() -> None:
    result = _run("one", "two")
    assert result.returncode == 2
    assert "--private-key" not in result.stdout + result.stderr


def test_report_lists_signable_stems_and_blocked_identities() -> None:
    result = _run()
    combined = result.stdout + result.stderr
    assert result.returncode == 0, result.stderr
    for stem in _SIGNABLE:
        assert stem in result.stdout
        assert f"{stem}: unsigned" in result.stdout
    for identity in _BLOCKED:
        assert identity in result.stdout
        assert "UNRESOLVED" in result.stdout
    assert "--private-key" not in combined
    assert "BEGIN" not in combined
    assert "PRIVATE KEY" not in combined


def test_report_marks_existing_public_envelopes_without_reading_keys(
    tmp_path: Path,
) -> None:
    owner = tmp_path / "owner"
    owner.mkdir()
    stem = _SIGNABLE[0]
    _ = (owner / f"{stem}.owner-envelope.json").write_text("{}", encoding="utf-8")
    result = _run(str(owner))
    assert result.returncode == 0, result.stderr
    assert f"{stem}: owner envelope present" in result.stdout
    assert f"{stem}: approver envelope missing" in result.stdout
    assert "BEGIN" not in result.stdout + result.stderr


def test_report_refuses_symlink_envelope_directory(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "link"
    linked.symlink_to(real, target_is_directory=True)
    result = _run(str(linked))
    assert result.returncode == 2
    assert "symlink" in result.stderr
