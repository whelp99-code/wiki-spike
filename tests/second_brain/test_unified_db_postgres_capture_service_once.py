"""A Claimed grant may capture at most once."""
from __future__ import annotations

import os
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
    destination_body,
)
from tests.second_brain.unified_db_postgres_capture_support import (
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
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    PostgresMetadataCaptureReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_DSN = b"postgresql://localhost:5433/unified"


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


def test_capture_refuses_second_call_with_same_claimed_grant_and_does_not_rewrite_dest(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    service = PostgresMetadataCaptureService(catalog)
    claimed = token.claim()
    receipt = service.capture(claimed, NOW)
    files = {path.name: path.read_bytes() for path in dest.iterdir()}
    executed = list(catalog.executed)
    read_fd, payload = _dsn_pipe()
    with pytest.raises(UnifiedDbExportError, match="already captured"):
        _ = service.capture(claimed, NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert catalog.executed == executed
    assert {path.name: path.read_bytes() for path in dest.iterdir()} == files
    assert (
        PostgresMetadataCaptureReceiptV1.from_mapping(_load(dest / "receipt.json")).receipt_digest
        == receipt.receipt_digest
    )


def test_capture_refuses_replay_of_same_claimed_grant_after_dest_deleted(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    service = PostgresMetadataCaptureService(catalog)
    claimed = token.claim()
    _ = service.capture(claimed, NOW)
    executed = list(catalog.executed)
    for path in dest.iterdir():
        path.unlink()
    dest.rmdir()
    read_fd, payload = _dsn_pipe()
    with pytest.raises(UnifiedDbExportError, match="already captured"):
        _ = service.capture(claimed, NOW, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    assert catalog.executed == executed
    assert not dest.exists()
