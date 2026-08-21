"""Existing-only Mac closed-artifact verification and SERVING_READY inspect."""
from __future__ import annotations

import os
import stat
import sys
from base64 import b64decode
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.applications.mac_signed_authority_bundle_verify import (
    verify_mac_signed_authority_bundle,
)
from wiki_spike.cli import main as run_authenticated_v2_cli
from wiki_spike.composition.mac_artifact_io import MacArtifactBundle
from wiki_spike.infrastructure.lifecycle_db_existing import (
    ExistingLifecycleDatabase,
    LifecycleDbError,
)
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    VerifiedPersistenceAuthorization,
    verify_mac_persistence_authorization,
)
from wiki_spike.memory_core.errors import CoreContractError, InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    ExpectedScopeManifestV1,
    TrustedDecisionKeyBindingsV1,
)
from wiki_spike.memory_core.second_brain_persistence import (
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_ARTIFACT_REFUSAL_TOKENS = (
    "signed authority is absent",
    "persistence profile is absent",
    "SERVING_READY is absent",
)
_CLOSED_ARTIFACT_NAMES = (
    "signed-authority.json",
    "persistence-profile.json",
    "persistence-receipt.json",
)


def refuse_unauthorized(argv: list[str] | None) -> int:
    """Print absent-artifact tokens, then run the authenticated CLI."""
    for token in _ARTIFACT_REFUSAL_TOKENS:
        print(token, file=sys.stderr)
    return run_authenticated_v2_cli(argv)


def closed_artifacts_are_regular(support: Path) -> bool:
    """Inspect only the closed artifact paths without creating or following them."""
    root = support / "second-brain-v1"
    try:
        root_meta = os.lstat(root)
    except OSError:
        return False
    if stat.S_ISLNK(root_meta.st_mode) or not stat.S_ISDIR(root_meta.st_mode):
        return False
    valid = True
    for name in _CLOSED_ARTIFACT_NAMES:
        try:
            artifact_meta = os.lstat(root / name)
        except OSError:
            valid = False
            continue
        if stat.S_ISLNK(artifact_meta.st_mode) or not stat.S_ISREG(
            artifact_meta.st_mode
        ):
            valid = False
    return valid


def _trusted_now(pinned: datetime | None) -> datetime:
    return datetime.now(UTC) if pinned is None else pinned


def verify_present_authority(
    artifacts: MacArtifactBundle,
    *,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    trusted_now: datetime | None,
    mint_authority: Callable[..., SecurityContextAuthority],
    expected_scope_manifest: ExpectedScopeManifestV1,
) -> tuple[SecurityContextAuthority | None, int | None]:
    """Verify a present authority bundle and mint opaque Stage-0 authority."""
    try:
        bundle = verify_mac_signed_authority_bundle(
            artifacts.authority,
            trusted_keys,
            now=_trusted_now(trusted_now),
        )
        if bundle.aggregate.contract.expected_scope_manifest != expected_scope_manifest:
            raise InvalidContractValue(
                "expected scope manifest does not match the pinned inventory"
            )
        return mint_authority(
            tuple(item.record for item in bundle.decision_records),
            bundle.aggregate.contract.resolved_scope,
            bundle.aggregate.contract.expected_scope_manifest,
            bundle.aggregate,
            trusted_keys,
            now=_trusted_now(trusted_now),
        ), None
    except CoreContractError as exc:
        print(str(exc), file=sys.stderr)
        return None, 1


def verify_existing_serving(
    support: Path,
    *,
    workspace_ref: str,
    open_database: Callable[[Path], ExistingLifecycleDatabase],
    inspect_serving: Callable[[ExistingLifecycleDatabase, str], object],
) -> tuple[ExistingLifecycleDatabase | None, int | None]:
    """Inspect an existing lifecycle DB after persistence verifies; never create."""
    sqlite_path = support / "second-brain-v1" / "lifecycle.sqlite3"
    try:
        meta = os.lstat(sqlite_path)
    except OSError:
        print(_ARTIFACT_REFUSAL_TOKENS[2], file=sys.stderr)
        return None, 1
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISREG(meta.st_mode):
        print(_ARTIFACT_REFUSAL_TOKENS[2], file=sys.stderr)
        return None, 1
    try:
        database = open_database(sqlite_path)
    except LifecycleDbError as exc:
        print(str(exc), file=sys.stderr)
        return None, 1
    try:
        _ = inspect_serving(database, workspace_ref)
    except LifecycleDbError as exc:
        database.close()
        print(str(exc), file=sys.stderr)
        return None, 1
    return database, None


def verify_present_persistence(
    artifacts: MacArtifactBundle,
    *,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    sqlcipher_artifact_bytes: bytes,
) -> tuple[VerifiedPersistenceAuthorization | None, int | None]:
    """Verify present profile/receipt bytes; return an exit code on refusal."""
    try:
        profile = MacPersistenceProfileV1.from_mapping(
            decode_json_object(artifacts.profile.decode("utf-8"))
        )
        receipt = PersistenceProfileReceiptV1.from_mapping(
            decode_json_object(artifacts.receipt.decode("utf-8"))
        )
        keys = trusted_keys.aggregate_bindings
        authorization = verify_mac_persistence_authorization(
            profile=profile,
            receipt=receipt,
            owner_key_id=keys.owner_key_id,
            owner_public_key=Ed25519PublicKey.from_public_bytes(
                b64decode(keys.owner_public_key_b64)
            ),
            approver_key_id=keys.approver_key_id,
            approver_public_key=Ed25519PublicKey.from_public_bytes(
                b64decode(keys.approver_public_key_b64)
            ),
            sqlcipher_artifact_bytes=sqlcipher_artifact_bytes,
        )
    except (
        UnicodeDecodeError,
        ValueError,
        InvalidContractValue,
        PersistenceProfileAuthorizationError,
        UnifiedDbExportError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return None, 1
    return authorization, None
