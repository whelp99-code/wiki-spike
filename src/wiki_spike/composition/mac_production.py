"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

import os
import pwd
import stat
import sys
from base64 import b64encode
from datetime import UTC, datetime
from pathlib import Path

from wiki_spike.applications.mac_signed_authority_bundle_verify import (
    verify_mac_signed_authority_bundle,
)
from wiki_spike.cli import main as run_authenticated_v2_cli
from wiki_spike.composition.mac_artifact_io import (
    MacArtifactReadError,
    read_mac_artifact_bundle,
)
from wiki_spike.memory_core.errors import CoreContractError
from wiki_spike.memory_core.second_brain_contracts import (
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
)

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


def _verify_present_authority(support: Path) -> int | None:
    """Verify a present authority bundle; return an exit code on fail-closed refusal."""
    try:
        artifacts = read_mac_artifact_bundle(support / "second-brain-v1")
        _ = verify_mac_signed_authority_bundle(
            artifacts.authority,
            PINNED_TRUSTED_KEYS,
            now=_trusted_now(),
        )
    except (MacArtifactReadError, CoreContractError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return None


def main(argv: list[str] | None = None) -> int:
    """Refuse unauthorized Mac status before constructing DB, CAS, or Keychain."""
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
    refused = _verify_present_authority(support)
    if refused is not None:
        return refused
    return run_authenticated_v2_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
