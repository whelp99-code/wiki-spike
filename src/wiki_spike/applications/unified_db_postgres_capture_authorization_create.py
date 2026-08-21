"""Create-only unsigned POSTGRES_METADATA_CAPTURE_ONLY body helper."""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from wiki_spike.applications.unified_db_export_authorization_publish import (
    publish_exclusive_bytes,
)
from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
    CLOSED_QUERY_MANIFEST_DIGEST,
    DIGEST_DOMAIN,
    MAX_CAPTURE_WINDOW,
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    DESTINATION_DOMAIN,
    DESTINATION_VERSION,
    PATH_POLICY,
    PostgresMetadataCaptureDestinationV1,
    enforce_create_only_destination,
)

DEFAULT_CAPTURE_AUTHORITY_BODY_PATH: Final = Path(
    "artifacts/product-release/second-brain-v1/capture-authority-signing/POSTGRES_METADATA_CAPTURE_ONLY.body.json"
)
_UNBOUND_DIGEST: Final = "0" * 64
_STAMP: Final = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True, slots=True)
class CaptureAuthorityCreateRequestV1:
    destination_path: str
    out_path: Path
    now: datetime
    nonce: str


def run_capture_authority_create(destination: Path, out: Path) -> int:
    _ = write_unsigned_capture_authority(
        CaptureAuthorityCreateRequestV1(
            str(destination),
            out,
            datetime.now(UTC),
            secrets.token_hex(32),
        )
    )
    return 0


def write_unsigned_capture_authority(
    request: CaptureAuthorityCreateRequestV1,
) -> UnifiedDbMetadataCaptureOnlyAuthorizationV1:
    body = build_unsigned_capture_authority(request)
    publish_exclusive_bytes(
        request.out_path,
        canonical_bytes(body.to_mapping()) + b"\n",
    )
    return body


def build_unsigned_capture_authority(
    request: CaptureAuthorityCreateRequestV1,
) -> UnifiedDbMetadataCaptureOnlyAuthorizationV1:
    destination = _destination(request.destination_path)
    current = _trusted_now(request.now)
    issued = current.strftime(_STAMP)
    expires = (current + MAX_CAPTURE_WINDOW).strftime(_STAMP)
    unsigned: dict[str, JsonValue] = {
        "authorization_version": AUTHORIZATION_VERSION,
        "authorization_kind": AUTHORIZATION_KIND,
        "authorization_id": "capture-auth-" + request.nonce[:16],
        "nonce": request.nonce,
        "source_name": "unified-db",
        "operation": "METADATA_CAPTURE_ONLY",
        "query_manifest_digest": CLOSED_QUERY_MANIFEST_DIGEST,
        "capture_plan_digest": _UNBOUND_DIGEST,
        "output_digest": _UNBOUND_DIGEST,
        "destination": destination.to_mapping(),
        "max_captures": "1",
        "application_row_allowed": False,
        "source_body_read_allowed": False,
        "mutation_allowed": False,
        "export_allowed": False,
        "import_allowed": False,
        "register_allowed": False,
        "cohort_allowed": False,
        "serve_allowed": False,
        "promote_allowed": False,
        "cutover_allowed": False,
        "issued_at": issued,
        "not_before": issued,
        "expires_at": expires,
    }
    digest = canonical_ledger_digest(DIGEST_DOMAIN, unsigned)
    return UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
        unsigned | {"authorization_digest": digest}
    )


def _destination(path: str) -> PostgresMetadataCaptureDestinationV1:
    enforce_create_only_destination(path)
    unsigned: dict[str, JsonValue] = {
        "destination_version": DESTINATION_VERSION,
        "source_name": "unified-db",
        "operation": "METADATA_CAPTURE_ONLY",
        "authorization_kind": AUTHORIZATION_KIND,
        "destination_path": path,
        "path_policy": PATH_POLICY,
        "import_requested": False,
        "serve_requested": False,
        "promote_requested": False,
        "cutover_requested": False,
    }
    digest = canonical_ledger_digest(DESTINATION_DOMAIN, unsigned)
    return PostgresMetadataCaptureDestinationV1.from_mapping(
        unsigned | {"destination_digest": digest}
    )


def _trusted_now(now: datetime) -> datetime:
    if now.utcoffset() is None:
        raise InvalidContractValue("trusted now must carry a timezone utcoffset")
    return now.astimezone(UTC).replace(microsecond=0)
