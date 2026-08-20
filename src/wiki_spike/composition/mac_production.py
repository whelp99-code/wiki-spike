"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

from wiki_spike.cli import main as run_authenticated_v2_cli


def main(argv: list[str] | None = None) -> int:
    """Refuse unauthorized Mac status before constructing DB, CAS, or Keychain."""
    return run_authenticated_v2_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())
