"""Production capture composition refuses before any DSN access."""
from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, get_type_hints

import pytest

from tests.second_brain.unified_db_postgres_capture_support import (
    CONFORMANCE_EVIDENCE,
    CONFORMANCE_SCHEMA,
)
from wiki_spike.composition.unified_db_postgres_capture import (
    refuse_postgres_identity_capture,
)
from wiki_spike.memory_core.unified_db_live_export_registry import (
    PRODUCTION_APPROVED_MAPPING_COUNT,
    PRODUCTION_MAPPER_REGISTRY,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

COMPOSITION = Path("src/wiki_spike/composition/unified_db_postgres_capture.py")
BANNED = {
    "psycopg",
    "psycopg2",
    "asyncpg",
    "pg8000",
    "socket",
    "http",
    "urllib",
    "requests",
    "subprocess",
    "multiprocessing",
    "importlib",
}


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"__import__", "eval", "exec"}:
                names.add(node.func.id)
    return names


def test_production_registry_remains_empty() -> None:
    assert PRODUCTION_APPROVED_MAPPING_COUNT == 0
    with pytest.raises(UnifiedDbExportError, match="unapproved mapper"):
        _ = PRODUCTION_MAPPER_REGISTRY.approved_mapping("unified-db-reviewed-notes", "v1")


def test_production_capture_refuses_without_owner_approval_and_leaves_dsn_unread() -> None:
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    with pytest.raises(UnifiedDbExportError, match="owner approval required"):
        refuse_postgres_identity_capture(dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload


def test_production_composition_has_no_dsn_query_or_mapper_override() -> None:
    text = COMPOSITION.read_text(encoding="utf-8")
    assert "os.environ" not in text
    assert "getenv" not in text
    assert "sys.argv" not in text
    assert "PRODUCTION_MAPPER_REGISTRY" not in text
    refuse = inspect.signature(refuse_postgres_identity_capture)
    assert "registry" not in refuse.parameters
    assert "sql" not in refuse.parameters
    assert "query" not in refuse.parameters
    imported = _imported(COMPOSITION)
    assert BANNED.isdisjoint(imported)
    assert get_type_hints(refuse_postgres_identity_capture)["return"] is NoReturn


def test_conformance_evidence_is_body_free_and_disconnected() -> None:
    evidence = decode_json_object(CONFORMANCE_EVIDENCE.read_text(encoding="utf-8"))
    assert evidence["body_present"] is False
    assert evidence["private_key_material"] is False
    assert evidence["dsn_read"] is False
    assert evidence["owner_approval_present"] is False
    assert evidence["application_row_query"] is False
    assert evidence["query_override"] is False
    assert evidence["production_mapper_created"] is False
    assert evidence["approved_mapping_count"] == "0"
    assert "body" not in evidence
    script = (
        "import json,sys,jsonschema;"
        "schema=json.load(open(sys.argv[1], encoding='utf-8'));"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(CONFORMANCE_SCHEMA), json.dumps(evidence)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    extra = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(CONFORMANCE_SCHEMA),
            json.dumps(evidence | {"extra": "no"}),
        ],
        capture_output=True,
        check=False,
        text=True,
    )
    assert extra.returncode != 0
