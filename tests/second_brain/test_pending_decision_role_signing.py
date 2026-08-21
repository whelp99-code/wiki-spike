"""Pending decision role-signing runner covers every unsigned body except DB-05."""
from __future__ import annotations

from pathlib import Path

_RUNNER = Path("scripts/run_pending_decision_role_signing.sh")
_ASSEMBLE = Path("scripts/run_pending_decision_assemble.sh")
_BODY_DIR = Path("artifacts/product-release/second-brain-v1/decision-signing")
_REQUIRED = (
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


def test_role_signing_runner_lists_every_unsigned_body_except_db05() -> None:
    script = _RUNNER.read_text(encoding="utf-8")
    for stem in _REQUIRED:
        assert f'"{stem}"' in script
    assert "DB-05" not in script
    for stem in _REQUIRED:
        assert (_BODY_DIR / f"{stem}.body.json").is_file()


_ASSEMBLE_ONLY = (
    "DB-02-claude-memory-bank",
    "DB-02-codex",
    "DB-02-git",
    "DB-02-markdown",
    "DB-03-legacy-mem0-rag",
    "DB-07",
)
_UNRESOLVED = ("DB-01", "DB-03-me-wiki", "DB-03-unified-db")


def test_assemble_runner_lists_only_go_or_no_go_bodies() -> None:
    script = _ASSEMBLE.read_text(encoding="utf-8")
    for stem in _ASSEMBLE_ONLY:
        assert f'"{stem}"' in script
    for stem in _UNRESOLVED:
        assert f'"{stem}"' not in script
    assert "DB-05" not in script
