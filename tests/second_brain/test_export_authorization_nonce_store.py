"""Durable SQLite nonce store: close/reopen, global identity, consume-on-attempt."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.second_brain.export_authorization_nonce_store_support import (
    NONCE,
    OTHER_NONCE,
    attempt,
    private_store_path,
)
from tests.second_brain.unified_db_export_authorization_support import signed_request
from wiki_spike.applications.unified_db_export_authorization_verify import (
    verify_export_only_authorization,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_missing_durable_store_module_is_required() -> None:
    assert SqliteExportAuthorizationNonceStore is not None


def test_close_reopen_replay_is_refused(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(path)
    store.reserve_and_consume(**attempt())
    store.close()
    reopened = SqliteExportAuthorizationNonceStore(path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        reopened.reserve_and_consume(**attempt())
    reopened.close()


def test_nonce_is_global_across_authorization_ids(tmp_path: Path) -> None:
    store = SqliteExportAuthorizationNonceStore(private_store_path(tmp_path))
    store.reserve_and_consume(**attempt(authorization_id="export-auth-aaa"))
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        store.reserve_and_consume(**attempt(authorization_id="export-auth-bbb"))
    store.reserve_and_consume(**attempt(nonce=OTHER_NONCE, authorization_id="export-auth-bbb"))
    store.close()


def test_failed_signature_attempt_remains_consumed(tmp_path: Path) -> None:
    store = SqliteExportAuthorizationNonceStore(private_store_path(tmp_path))
    request, _ignored = signed_request()
    forged = request.__class__(
        request.body_bytes,
        request.envelopes,
        request.trusted.__class__(
            request.trusted.approver_key_id,
            request.trusted.approver_public_key_b64,
            request.trusted.owner_key_id,
            "A" * 44,
        ),
        request.expected,
        request.now,
    )
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_export_only_authorization(forged, store)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_export_only_authorization(request, store)
    store.close()


def test_store_persists_digest_never_raw_nonce(tmp_path: Path) -> None:
    path = private_store_path(tmp_path)
    store = SqliteExportAuthorizationNonceStore(path)
    store.reserve_and_consume(**attempt())
    store.close()
    payload = path.read_bytes()
    assert NONCE.encode("ascii") not in payload
    digest = export_authorization_nonce_digest(NONCE).encode("ascii")
    assert digest in payload
