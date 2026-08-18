"""Happy-path verifier tests for LIVE_EXPORT_ONLY authority."""
from __future__ import annotations

import pytest

from tests.second_brain.unified_db_export_authorization_support import signed_request
from wiki_spike.applications.unified_db_export_authorization_verify import (
    VerifiedUnifiedDbExportAuthorityV1,
    verify_export_only_authorization,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError


def test_verifier_mints_process_local_authority_when_bindings_and_window_hold() -> None:
    request, nonces = signed_request()
    token = verify_export_only_authorization(request, nonces)
    assert isinstance(token, VerifiedUnifiedDbExportAuthorityV1)
    claimed = token.claim()
    assert claimed.authorization_id == "export-auth-001"
    with pytest.raises(UnifiedDbExportError, match="claimed"):
        _ = token.claim()
