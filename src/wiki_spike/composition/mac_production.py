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


def _refuse_unauthorized(argv: list[str] | None) -> int:
    """Print absent-artifact tokens, then run the authenticated CLI."""
    for token in _ARTIFACT_REFUSAL_TOKENS:
        print(token, file=sys.stderr)
    return run_authenticated_v2_cli(argv)


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
    return _refuse_unauthorized(argv)


if __name__ == "__main__":
    raise SystemExit(main())
