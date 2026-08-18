"""Row and path fixtures for unified-db export tests."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.unified_db_snapshot_export import (
    AUTHORITY_KIND,
    AUTHORITY_VERSION,
    FixtureExportAuthorityV1,
    UnifiedDbExportRowV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

ALPHA = b"hello-alpha"
BETA = b"hello-beta"
GONE = b"gone-body"
ALPHA_HASH = sha256(ALPHA).hexdigest()
BETA_HASH = sha256(BETA).hexdigest()
GONE_HASH = sha256(GONE).hexdigest()
DB_COMMIT = sha256(b"db").hexdigest()
CATALOG_COMMIT = sha256(b"catalog").hexdigest()
SOURCE_COMMIT = sha256(b"source").hexdigest()
DATA_ROOT_COMMIT = sha256(b"data-root").hexdigest()
SCRIPT = Path("scripts/second_brain_unified_db_snapshot_export.py")
SCHEMA_DIR = Path("schemas/second-brain")
EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/unified-db-export-conformance-v1.json"
)
FIXTURE = Path("tests/fixtures/second_brain/unified_db_export/fixture-v1.json")


def load_mapping(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def digest_of(value: bytes | str) -> str:
    data = value.encode() if isinstance(value, str) else value
    return sha256(data).hexdigest()


def authority() -> FixtureExportAuthorityV1:
    return FixtureExportAuthorityV1.from_mapping(
        {
            "authority_version": AUTHORITY_VERSION,
            "authority_kind": AUTHORITY_KIND,
        }
    )


def row(
    native_id: str,
    body: bytes,
    watermark: str,
    *,
    tombstone: bool = False,
    source_id: str = "notes",
    revision: str | None = None,
) -> UnifiedDbExportRowV1:
    digest = sha256(body).hexdigest()
    return UnifiedDbExportRowV1.from_mapping(
        {
            "source_id": source_id,
            "native_id": native_id,
            "content_hash": digest,
            "revision": digest if revision is None else revision,
            "watermark": watermark,
            "tombstone": tombstone,
            "body_hex": None if tombstone else body.hex(),
        }
    )


def standard_rows() -> tuple[UnifiedDbExportRowV1, ...]:
    return (
        row("alpha", ALPHA, "cursor-alpha"),
        row("beta", BETA, "cursor-beta"),
        row("gone", GONE, "cursor-gone", tombstone=True),
    )
