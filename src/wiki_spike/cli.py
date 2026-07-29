"""Installed CLI entry point for the authenticated V2 product."""
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .workspace_format import V2WorkspaceRoot, WorkspaceRootError


class ProductAuthorityError(PermissionError):
    """No authenticated V2 product authority was supplied to the entry point."""


class ProductAuthority(Protocol):
    def require(self) -> object: ...


class AuthenticatedV2Product(Protocol):
    authority: ProductAuthority


V2Dispatcher = Callable[[AuthenticatedV2Product, argparse.Namespace], int]


def _dispatch_v2(product: AuthenticatedV2Product, args: argparse.Namespace) -> int:
    """Dispatch the deliberately small installed-product command surface."""
    if args.cmd == "status":
        print("authenticated V2 product ready")
        return 0
    raise ValueError(f"unsupported V2 command: {args.cmd}")


def _root_from_argv(argv: list[str]) -> str:
    """Return argparse's effective root option without validating the command."""
    root = ".wiki-spike"
    index = 0
    while index < len(argv):
        token = argv[index]
        option, separator, value = token.partition("=")
        if len(option) > 2 and "--root".startswith(option):
            if separator:
                root = value
            elif index + 1 < len(argv):
                index += 1
                root = argv[index]
        index += 1
    return root


def main(
    argv: list[str] | None = None,
    *,
    product: AuthenticatedV2Product | None = None,
    dispatch: V2Dispatcher = _dispatch_v2,
) -> int:
    """Run only an already-authenticated V2 product.

    Root inspection happens before command parsing and product dispatch; it
    does not create a directory or initialize storage.  The installed entry
    point deliberately has no legacy fallback: compatibility callers must use
    their explicit factory rather than this product boundary.
    """
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(prog="wiki", description="authenticated wiki-spike V2")
    parser.add_argument("--root", default=".wiki-spike")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    if "-h" in effective_argv or "--help" in effective_argv:
        parser.print_help()
        return 0

    try:
        V2WorkspaceRoot.inspect(Path(_root_from_argv(effective_argv)))
    except WorkspaceRootError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    args = parser.parse_args(effective_argv)

    try:
        if product is None:
            raise ProductAuthorityError("authenticated V2 product authority is required")
        try:
            product.authority.require()
        except (AttributeError, PermissionError, TypeError, ValueError) as exc:
            raise ProductAuthorityError("authenticated V2 product authority is required") from exc
    except ProductAuthorityError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return dispatch(product, args)


if __name__ == "__main__":
    raise SystemExit(main())
