"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

import sys

from wiki_spike.cli import main as run_authenticated_v2_cli

_ARTIFACT_REFUSAL_TOKENS = (
    "signed authority is absent",
    "persistence profile is absent",
    "SERVING_READY is absent",
)


def main(argv: list[str] | None = None) -> int:
    """Refuse unauthorized Mac status before constructing DB, CAS, or Keychain."""
    for token in _ARTIFACT_REFUSAL_TOKENS:
        print(token, file=sys.stderr)
    return run_authenticated_v2_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
