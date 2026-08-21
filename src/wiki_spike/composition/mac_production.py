"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

import os
import pwd
import stat
import sys
from base64 import b64decode, b64encode
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from wiki_spike.applications.mac_signed_authority_bundle_verify import (
    verify_mac_signed_authority_bundle,
)
from wiki_spike.cli import main as run_authenticated_v2_cli
from wiki_spike.composition.mac_artifact_io import (
    MacArtifactBundle,
    MacArtifactReadError,
    read_mac_artifact_bundle,
)
from wiki_spike.composition.mac_production_compose import (
    MacProductionComposeError,
    compose_existing_mac_product,
)
from wiki_spike.infrastructure.lifecycle_db_existing import (
    ExistingLifecycleDatabase,
    LifecycleDbError,
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    VerifiedPersistenceAuthorization,
    verify_mac_persistence_authorization,
)
from wiki_spike.memory_core.errors import CoreContractError, InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import (
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
)
from wiki_spike.memory_core.second_brain_persistence import (
    MacPersistenceProfileV1,
    PersistenceProfileReceiptV1,
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
PINNED_TRUSTED_KEYS = TrustedDecisionKeyBindingsV1(
    {},
    TrustedAuthorityBindingsV1(
        "approver",
        b64encode(bytes(32)).decode("ascii"),
        "owner",
        b64encode(bytes(32 * [1])).decode("ascii"),
    ),
)
PINNED_TRUSTED_NOW: datetime | None = None
PINNED_SQLCIPHER_ARTIFACT_BYTES: bytes = b""
PINNED_WORKSPACE_REF = ""


def _refuse_unauthorized(argv: list[str] | None) -> int:
    """Print absent-artifact tokens, then run the authenticated CLI."""
    for token in _ARTIFACT_REFUSAL_TOKENS:
        print(token, file=sys.stderr)
    return run_authenticated_v2_cli(argv)


def _closed_artifacts_are_regular(support: Path) -> bool:
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


def _trusted_now() -> datetime:
    return datetime.now(UTC) if PINNED_TRUSTED_NOW is None else PINNED_TRUSTED_NOW


def _verify_present_authority(artifacts: MacArtifactBundle) -> int | None:
    """Verify a present authority bundle; return an exit code on fail-closed refusal."""
    try:
        _ = verify_mac_signed_authority_bundle(
            artifacts.authority,
            PINNED_TRUSTED_KEYS,
            now=_trusted_now(),
        )
    except CoreContractError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return None


def _verify_existing_serving(
    support: Path,
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
        database = open_existing_lifecycle_database(sqlite_path)
    except LifecycleDbError as exc:
        print(str(exc), file=sys.stderr)
        return None, 1
    try:
        _ = inspect_existing_serving_ready(database, PINNED_WORKSPACE_REF)
    except LifecycleDbError as exc:
        database.close()
        print(str(exc), file=sys.stderr)
        return None, 1
    return database, None


def _verify_present_persistence(
    artifacts: MacArtifactBundle,
) -> tuple[VerifiedPersistenceAuthorization | None, int | None]:
    """Verify present profile/receipt bytes; return an exit code on refusal."""
    try:
        profile = MacPersistenceProfileV1.from_mapping(
            decode_json_object(artifacts.profile.decode("utf-8"))
        )
        receipt = PersistenceProfileReceiptV1.from_mapping(
            decode_json_object(artifacts.receipt.decode("utf-8"))
        )
        keys = PINNED_TRUSTED_KEYS.aggregate_bindings
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
            sqlcipher_artifact_bytes=PINNED_SQLCIPHER_ARTIFACT_BYTES,
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


def main(argv: list[str] | None = None) -> int:
    """Admit existing Mac stores after SERVING_READY; refuse closed otherwise."""
    support = (
        Path(pwd.getpwuid(os.getuid()).pw_dir)
        / "Library"
        / "Application Support"
        / "wiki-spike"
    )
    try:
        meta = os.lstat(support)
    except OSError:
        return _refuse_unauthorized(argv)
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        return _refuse_unauthorized(argv)
    if not _closed_artifacts_are_regular(support):
        return _refuse_unauthorized(argv)
    try:
        artifacts = read_mac_artifact_bundle(support / "second-brain-v1")
    except MacArtifactReadError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    refused = _verify_present_authority(artifacts)
    if refused is not None:
        return refused
    authorization, refused = _verify_present_persistence(artifacts)
    if refused is not None or authorization is None:
        return 1 if refused is None else refused
    database, refused = _verify_existing_serving(support)
    if refused is not None or database is None:
        return 1 if refused is None else refused
    try:
        try:
            product = compose_existing_mac_product(
                v1_dir=support / "second-brain-v1",
                database=database,
                authorization=authorization,
                workspace_ref=PINNED_WORKSPACE_REF,
                keychain_directory=support.parent.parent / "Keychains",
            )
        except MacProductionComposeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return run_authenticated_v2_cli(argv, product=product)
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
