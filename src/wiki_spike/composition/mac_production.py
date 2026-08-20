"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

import os
import pwd
import stat
import sys
from pathlib import Path

from wiki_spike.cli import main as run_authenticated_v2_cli

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
    return _refuse_unauthorized(argv)


if __name__ == "__main__":
    raise SystemExit(main())
