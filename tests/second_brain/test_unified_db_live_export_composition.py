"""Pre-DSN composition seam: hardcoded private store, banned imports, refuse."""
from __future__ import annotations

import ast
import inspect
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.second_brain.unified_db_export_authorization_support import SCRIPT
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

COMPOSITION = Path("src/wiki_spike/composition/unified_db_live_export.py")
STORE = Path("src/wiki_spike/infrastructure/export_authorization_nonce_store.py")
FS = Path("src/wiki_spike/infrastructure/export_authorization_nonce_fs.py")
SCHEMA = Path("src/wiki_spike/infrastructure/export_authorization_nonce_schema.py")
BACKUP = Path("src/wiki_spike/infrastructure/export_authorization_nonce_backup.py")
DECODE = Path("src/wiki_spike/infrastructure/export_authorization_nonce_decode.py")
PRE_DSN = (COMPOSITION, STORE, FS, SCHEMA, BACKUP, DECODE)
PRODUCTION_TAIL = (
    "Library/Application Support/wiki-spike/export-authority-v1/nonces.sqlite3"
)
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
EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/"
    + "unified-db-export-authorization-nonce-store-conformance-v1.json"
)
EVIDENCE_SCHEMA = Path(
    "schemas/second-brain/"
    + "unified-db-export-authorization-nonce-store-conformance-v1.schema.json"
)


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


def test_pre_dsn_seam_bans_postgres_socket_subprocess_and_dynamic_imports() -> None:
    for path in PRE_DSN:
        imported = _imported(path)
        assert BANNED.isdisjoint(imported), f"{path}: {sorted(imported & BANNED)}"
        text = path.read_text(encoding="utf-8")
        assert "postgresql" not in text.lower()
        assert "import_module" not in text
        assert "__import__" not in text


def test_production_opener_has_fixed_path_and_no_overrides() -> None:
    from wiki_spike.composition.unified_db_live_export import (
        open_production_export_authorization_nonce_store,
        refuse_live_unified_db_export,
    )

    text = COMPOSITION.read_text(encoding="utf-8")
    assert PRODUCTION_TAIL in text
    assert "os.environ" not in text
    assert "getenv" not in text
    opener = inspect.signature(open_production_export_authorization_nonce_store)
    assert list(opener.parameters) == []
    refuse = inspect.signature(refuse_live_unified_db_export)
    assert "path" not in refuse.parameters
    assert "dsn_fd" in refuse.parameters


def test_refuse_live_export_validates_store_and_leaves_dsn_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    support = tmp_path / "Library" / "Application Support"
    support.mkdir(parents=True)
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    dest = tmp_path / "live"
    refused = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "export",
            "--dsn-fd",
            str(read_fd),
            "--output",
            str(dest),
        ],
        capture_output=True,
        check=False,
        pass_fds=(read_fd,),
        env={**os.environ, "HOME": str(tmp_path)},
    )
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"executable mapping and signed authority" in refused.stderr
    assert leftover == payload
    assert not dest.exists()
    store = (
        tmp_path
        / "Library"
        / "Application Support"
        / "wiki-spike"
        / "export-authority-v1"
        / "nonces.sqlite3"
    )
    assert store.is_file()


def test_nonce_store_conformance_is_body_free_draft_2020_12() -> None:
    evidence = decode_json_object(EVIDENCE.read_text(encoding="utf-8"))
    schema_text = EVIDENCE_SCHEMA.read_text(encoding="utf-8")
    assert "https://json-schema.org/draft/2020-12/schema" in schema_text
    assert evidence["body_present"] is False
    assert evidence["private_key_material"] is False
    assert evidence["raw_nonce_persisted"] is False
    assert evidence["live_export_authorized"] is False
    assert "body" not in evidence
    script = (
        "import json,sys,jsonschema;"
        "schema=json.load(open(sys.argv[1], encoding='utf-8'));"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(EVIDENCE_SCHEMA), json.dumps(evidence)],
        capture_output=True,
        check=False,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
