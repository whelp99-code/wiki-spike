"""Claimed-only POSTGRES_METADATA_CAPTURE_ONLY executor tests."""
from __future__ import annotations

import ast
import copy
import os
from hashlib import sha256
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    CAPTURE_PLAN_DIGEST,
    NOW,
    OUTPUT_DIGEST,
    QUERY_MANIFEST_DIGEST,
    authorization_body,
    signed_request,
)
from tests.second_brain.unified_db_postgres_capture_result_support import (
    CAPTURE_ARTIFACT_NAMES,
    destination_body,
)
from tests.second_brain.unified_db_postgres_capture_support import (
    APPLICATION_TABLE_SQL,
    DATABASE_OID,
    SERVER_VERSION_NUM,
    SYSTEM_IDENTIFIER,
    FakePostgresCatalogQuery,
    closed_catalog_query_results,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
    verify_metadata_capture_authorization,
)
from wiki_spike.applications.unified_db_postgres_capture_service import (
    PostgresMetadataCaptureService,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_output import (
    PostgresMetadataCaptureOutputManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    CLOSED_QUERY_SQL,
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    PostgresMetadataCaptureReceiptV1,
    bind_capture_receipt,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

SERVICE = Path("src/wiki_spike/applications/unified_db_postgres_capture_service.py")
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
_DSN = b"postgresql://localhost:5433/unified"


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


def _dsn_pipe() -> tuple[int, bytes]:
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, _DSN)
    os.close(write_fd)
    return read_fd, _DSN


def _grant_pair(
    dest: Path,
) -> tuple[VerifiedUnifiedDbMetadataCaptureAuthorityV1, FakePostgresCatalogQuery]:
    dest_body = destination_body(str(dest))
    body = authorization_body(destination=dest_body)
    expected = ExpectedMetadataCaptureDigestsV1(
        QUERY_MANIFEST_DIGEST,
        CAPTURE_PLAN_DIGEST,
        OUTPUT_DIGEST,
        str(dest_body["destination_digest"]),
    )
    request, nonces = signed_request(body=body, expected=expected)
    token = verify_metadata_capture_authorization(request, nonces)
    return token, FakePostgresCatalogQuery(closed_catalog_query_results())


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def test_capture_executes_closed_eight_queries_in_order_when_claimed(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    read_fd, payload = _dsn_pipe()
    service = PostgresMetadataCaptureService(catalog)
    _ = service.capture(token.claim(), NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert tuple(catalog.executed) == tuple(sql for _kind, sql in CLOSED_QUERY_SQL)
    assert all(sql not in catalog.executed for sql in APPLICATION_TABLE_SQL)


def test_capture_writes_six_file_tree_and_receipt_binds_when_claimed(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    service = PostgresMetadataCaptureService(catalog)
    receipt = service.capture(token.claim(), NOW)
    names = tuple(sorted(path.name for path in dest.iterdir()))
    assert names == CAPTURE_ARTIFACT_NAMES
    files = {path.name: path.read_bytes() for path in dest.iterdir()}
    destination = PostgresMetadataCaptureDestinationV1.from_mapping(
        destination_body(str(dest))
    )
    manifest = PostgresMetadataCaptureOutputManifestV1.from_mapping(
        _load(dest / "output-manifest.json")
    )
    parsed = PostgresMetadataCaptureReceiptV1.from_mapping(_load(dest / "receipt.json"))
    identity = PostgresIdentityReceiptV1.from_mapping(_load(dest / "identity.json"))
    catalog_snapshot = PostgresCatalogSnapshotV1.from_mapping(_load(dest / "catalog.json"))
    query_manifest = PostgresCaptureQueryManifestV1.from_mapping(
        _load(dest / "query-manifest.json")
    )
    assert identity.system_identifier == SYSTEM_IDENTIFIER
    assert identity.database_oid == DATABASE_OID
    assert identity.server_version_num == SERVER_VERSION_NUM
    assert catalog_snapshot.catalog_digest == identity.catalog_digest
    assert query_manifest.manifest_digest == QUERY_MANIFEST_DIGEST
    assert parsed.receipt_digest == receipt.receipt_digest
    bind_capture_receipt(destination, manifest, parsed)
    hashed = {entry.relative_path: entry.content_digest for entry in manifest.entries}
    for name in ("capture-plan.json", "catalog.json", "identity.json", "query-manifest.json"):
        assert sha256(files[name]).hexdigest() == hashed[name]


def test_capture_refuses_when_authority_is_unclaimed_and_leaves_dest_and_dsn_unread(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    read_fd, payload = _dsn_pipe()
    service = PostgresMetadataCaptureService(catalog)
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = service.capture(token, NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert catalog.executed == []
    assert not dest.exists()


def test_capture_refuses_when_authority_already_claimed_and_leaves_dest_and_dsn_unread(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    _ = token.claim()
    read_fd, payload = _dsn_pipe()
    service = PostgresMetadataCaptureService(catalog)
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = service.capture(token, NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert catalog.executed == []
    assert not dest.exists()


def test_capture_refuses_when_copy_claims_after_original_and_leaves_dest_unread(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    clone = copy.copy(token)
    _ = token.claim()
    read_fd, payload = _dsn_pipe()
    service = PostgresMetadataCaptureService(catalog)
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = service.capture(clone, NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert catalog.executed == []
    assert not dest.exists()


def test_capture_refuses_when_destination_already_exists(tmp_path: Path) -> None:
    dest = tmp_path / "capture-out"
    dest.mkdir()
    token, catalog = _grant_pair(dest)
    service = PostgresMetadataCaptureService(catalog)
    with pytest.raises((InvalidContractValue, UnifiedDbExportError), match="exists|overwrite"):
        _ = service.capture(token.claim(), NOW)
    assert catalog.executed == []
    assert list(dest.iterdir()) == []


def test_capture_refuses_when_destination_is_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    dest = tmp_path / "link"
    dest.symlink_to(real)
    token, catalog = _grant_pair(dest)
    service = PostgresMetadataCaptureService(catalog)
    with pytest.raises((InvalidContractValue, UnifiedDbExportError), match="symlink"):
        _ = service.capture(token.claim(), NOW)
    assert catalog.executed == []
    assert list(real.iterdir()) == []


def test_capture_service_has_no_live_network_dsn_mapper_or_private_keys() -> None:
    text = SERVICE.read_text(encoding="utf-8")
    assert "SELECT" not in text
    assert "SHOW" not in text
    assert "public.notes" not in text
    assert "os.environ" not in text
    assert "getenv" not in text
    assert "PRODUCTION_MAPPER_REGISTRY" not in text
    assert "Ed25519PrivateKey" not in text
    assert "psycopg" not in text
    imported = _imported(SERVICE)
    assert BANNED.isdisjoint(imported)


def test_production_composition_still_refuses_unclaimed_without_service_wiring() -> None:
    text = COMPOSITION.read_text(encoding="utf-8")
    assert "PostgresMetadataCaptureService" not in text
    assert "unified_db_postgres_capture_service" not in text
    assert "refuse_postgres_identity_capture" in text
