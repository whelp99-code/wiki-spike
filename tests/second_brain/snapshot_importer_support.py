"""Typed shared fixtures for non-serving snapshot import tests."""
from __future__ import annotations

import sqlite3
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.applications.source_discovery_service import discover_source
from wiki_spike.applications.source_import_service import SourceImportService
from wiki_spike.infrastructure import crypto
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.persistence_profile import (
    VerifiedPersistenceProfile,
    verify_mac_persistence_profile,
)
from wiki_spike.infrastructure.snapshot_import_store import LifecycleSnapshotImportStore
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_persistence import (
    MAC_FIELD_AEAD_PROFILE_V1,
    PERSISTENCE_PROFILE_RECEIPT_V1,
    PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
    persistence_profile_authorization_payload,
)
from wiki_spike.memory_core.snapshot_import import (
    BOUNDED_SNAPSHOT_V1,
    SNAPSHOT_IMPORT_REQUEST_V1,
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
)
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
)

SQLCIPHER_ARTIFACT = Path(
    "artifacts/encrypted-lifecycle/sqlcipher-feasibility-darwin-arm64.json"
)


def digest_of(value: bytes | str) -> str:
    data = value.encode() if isinstance(value, str) else value
    return sha256(data).hexdigest()


def persistence_profile() -> MacPersistenceProfileV1:
    body: dict[str, JsonValue] = {
        "profile_version": MAC_FIELD_AEAD_PROFILE_V1,
        "profile_name": "mac-field-aead-v1",
        "sqlite_runtime": f"python-stdlib-sqlite3/{sqlite3.sqlite_version}",
        "state_authority": "LifecycleDatabase",
        "content_store": "EncryptedContentStore",
        "content_cipher": "AES-256-GCM",
        "database_page_cipher": "none",
        "sqlcipher_status": "platform_unavailable",
        "sqlcipher_must_verdict": "NOT_RUN",
        "sqlcipher_artifact_digest": digest_of(SQLCIPHER_ARTIFACT.read_bytes()),
    }
    return MacPersistenceProfileV1.from_mapping(
        body
        | {
            "profile_digest": canonical_ledger_digest(
                "mac-persistence-profile-v1",
                body,
            )
        }
    )


def persistence_receipt(
    profile: MacPersistenceProfileV1,
    owner: Ed25519PrivateKey,
    approver: Ed25519PrivateKey,
) -> PersistenceProfileReceiptV1:
    authorized_at = "2026-08-18T00:00:00Z"
    payload = persistence_profile_authorization_payload(
        receipt_version=PERSISTENCE_PROFILE_RECEIPT_V1,
        profile_digest=profile.profile_digest,
        owner_key_id="wiki-owner-2026",
        approver_key_id="wiki-approver-2026",
        authorized_at=authorized_at,
    )
    body: dict[str, JsonValue] = {
        "receipt_version": PERSISTENCE_PROFILE_RECEIPT_V1,
        "profile_digest": profile.profile_digest,
        "owner_key_id": "wiki-owner-2026",
        "approver_key_id": "wiki-approver-2026",
        "owner_signature": crypto.sign(
            owner,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
        ),
        "approver_signature": crypto.sign(
            approver,
            PERSISTENCE_PROFILE_SIGNATURE_DOMAIN,
            payload,
        ),
        "authorized_at": authorized_at,
    }
    return PersistenceProfileReceiptV1.from_mapping(
        body
        | {
            "receipt_digest": canonical_ledger_digest(
                "persistence-profile-receipt-v1",
                body,
            )
        }
    )


def verified_persistence(
    database: LifecycleDatabase,
    cas: EncryptedContentStore,
) -> VerifiedPersistenceProfile:
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    profile = persistence_profile()
    return verify_mac_persistence_profile(
        profile=profile,
        receipt=persistence_receipt(profile, owner, approver),
        owner_public_key=owner.public_key(),
        approver_public_key=approver.public_key(),
        sqlcipher_artifact_path=SQLCIPHER_ARTIFACT,
        database=database,
        cas=cas,
    )


def discovery_of(root: Path) -> SourceDiscoveryManifestV1:
    request = SourceDiscoveryRequestV1.from_mapping(
        {
            "request_version": SOURCE_DISCOVERY_REQUEST_V1,
            "source_name": "me-wiki",
            "source_root": str(root.resolve()),
        }
    )
    return discover_source(request)


def snapshot_from_records(
    records: list[dict[str, JsonValue]],
    watermark: str,
) -> BoundedSnapshotV1:
    encoded: list[JsonValue] = list(records)
    body: dict[str, JsonValue] = {
        "snapshot_version": BOUNDED_SNAPSHOT_V1,
        "source_name": "me-wiki",
        "native_namespace": "second-brain:import:me-wiki",
        "snapshot_watermark": watermark,
        "records": encoded,
    }
    return BoundedSnapshotV1.from_mapping(
        body
        | {
            "snapshot_digest": canonical_ledger_digest(
                "bounded-source-snapshot-v1",
                body,
            )
        }
    )


def snapshot_of(root: Path) -> BoundedSnapshotV1:
    first = root / "alpha.md"
    second = root / "beta.json"
    return snapshot_from_records(
        [
            {
                "native_id": "note-alpha",
                "revision": "7",
                "watermark": "watermark-11",
                "tombstone": False,
                "relative_path": "alpha.md",
                "content_digest": digest_of(first.read_bytes()),
            },
            {
                "native_id": "note-beta",
                "revision": "3",
                "watermark": "watermark-12",
                "tombstone": False,
                "relative_path": "beta.json",
                "content_digest": digest_of(second.read_bytes()),
            },
            {
                "native_id": "note-deleted",
                "revision": "9",
                "watermark": "watermark-13",
                "tombstone": True,
                "relative_path": None,
                "content_digest": None,
            },
        ],
        "watermark-13",
    )


def import_request(
    root: Path,
    discovery_digest: str,
    snapshot: BoundedSnapshotV1,
    *,
    source_name: str = "me-wiki",
    target_namespace: str = "second-brain:import:me-wiki",
    reconciliation_mode: str = "REQUIRED",
    serving_promotion_requested: bool = False,
    cohort_id: str = "cohort-me-wiki-001",
) -> SnapshotImportRequestV1:
    payload: dict[str, JsonValue] = {
        "request_version": SNAPSHOT_IMPORT_REQUEST_V1,
        "cohort_id": cohort_id,
        "source_name": source_name,
        "source_root": str(root.resolve()),
        "target_namespace": target_namespace,
        "resolved_scope_digest": digest_of("resolved-scope"),
        "discovery_manifest_digest": discovery_digest,
        "snapshot_digest": snapshot.snapshot_digest,
        "reconciliation_mode": reconciliation_mode,
        "serving_promotion_requested": serving_promotion_requested,
    }
    return SnapshotImportRequestV1.from_mapping(payload)


def import_service(
    tmp_path: Path,
) -> tuple[
    SourceImportService,
    LifecycleSnapshotImportStore,
    LifecycleDatabase,
    Path,
]:
    database = LifecycleDatabase(tmp_path / "target.sqlite")
    database.initialize()
    cas_root = tmp_path / "cas"
    cas = EncryptedContentStore(cas_root)
    store = LifecycleSnapshotImportStore(
        database=database,
        cas=cas,
        persistence_profile=verified_persistence(database, cas),
        encryption_key=b"\x13" * 32,
    )
    return SourceImportService(store=store, max_file_bytes=1024 * 1024), store, database, cas_root


def write_pair(root: Path) -> None:
    _ = (root / "alpha.md").write_text("alpha plaintext", encoding="utf-8")
    _ = (root / "beta.json").write_text('{"beta":"plaintext"}', encoding="utf-8")
