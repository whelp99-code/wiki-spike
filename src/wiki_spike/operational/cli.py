"""Support CLI for the same store used by the Wiki Memory desktop app.

Normal users should launch ``Wiki Memory.app``. This command exists for package
smoke tests, scripted backup, and support diagnostics only.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .desktop_service import DEFAULT_DATA_ROOT, DesktopMemoryService
from .store import LocalMemoryError, LocalMemoryStore, read_passphrase


def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_mapping"):
        return value.to_mapping()
    if isinstance(value, tuple):
        return [_jsonable(item) for item in value]
    if isinstance(value, list):
        return [_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    return value


def _print(value: Any, *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(_jsonable(value), ensure_ascii=False, indent=2, sort_keys=True))
        return
    if isinstance(value, tuple):
        for item in value:
            mapping = item.to_mapping() if hasattr(item, "to_mapping") else item
            print(json.dumps(mapping, ensure_ascii=False, sort_keys=True))
        return
    if hasattr(value, "to_mapping"):
        value = value.to_mapping()
    if isinstance(value, dict):
        print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print(value)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wiki",
        description="Wiki Memory support command; normal use is through Wiki Memory.app",
    )
    parser.add_argument("--root", type=Path, default=DEFAULT_DATA_ROOT)
    parser.add_argument("--json", action="store_true", dest="as_json")
    commands = parser.add_subparsers(dest="command", required=True)

    commands.add_parser("init")
    commands.add_parser("status")
    commands.add_parser("doctor")
    commands.add_parser("recent").add_argument("--limit", type=int, default=20)

    remember = commands.add_parser("remember")
    source = remember.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path)
    source.add_argument("--text")
    remember.add_argument("--title", default="새 메모")

    recall = commands.add_parser("recall")
    recall.add_argument("query")
    recall.add_argument("--limit", type=int, default=20)

    show = commands.add_parser("show")
    show.add_argument("memory_id")

    correct = commands.add_parser("correct")
    correct.add_argument("memory_id")
    correction = correct.add_mutually_exclusive_group(required=True)
    correction.add_argument("--file", type=Path)
    correction.add_argument("--text")
    correct.add_argument("--title", default="수정된 메모")

    forget = commands.add_parser("forget")
    forget.add_argument("memory_id")
    forget.add_argument("--yes", action="store_true")

    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    backup.add_argument("--passphrase-file", type=Path)
    backup.add_argument("--overwrite", action="store_true")

    restore = commands.add_parser("restore")
    restore.add_argument("backup", type=Path)
    restore.add_argument("--passphrase-file", type=Path)
    restore.add_argument("--replace", action="store_true")

    events = commands.add_parser("log")
    events.add_argument("--limit", type=int, default=20)
    return parser


def dispatch(args: argparse.Namespace) -> Any:
    root = args.root.expanduser()
    if args.command == "init":
        return DesktopMemoryService.open_or_initialize(root).service.status()
    if args.command == "restore":
        passphrase = read_passphrase(args.passphrase_file)
        return LocalMemoryStore.restore(
            args.backup,
            root,
            passphrase=passphrase,
            replace=args.replace,
        )

    service = DesktopMemoryService.open_or_initialize(root).service
    if args.command in {"status", "doctor"}:
        return service.status()
    if args.command == "recent":
        return service.browse("", limit=args.limit)
    if args.command == "remember":
        if args.file is not None:
            return service.import_file(args.file)
        return service.save(memory_id=None, title=args.title, body=args.text)
    if args.command == "recall":
        return service.browse(args.query, limit=args.limit)
    if args.command == "show":
        return service.get(args.memory_id)
    if args.command == "correct":
        if args.file is not None:
            return service.store.correct(args.memory_id, args.file, label=args.title)
        return service.save(memory_id=args.memory_id, title=args.title, body=args.text)
    if args.command == "forget":
        if not args.yes:
            raise LocalMemoryError("forget is irreversible; repeat with --yes")
        return service.delete(args.memory_id)
    if args.command == "backup":
        passphrase = read_passphrase(args.passphrase_file, confirm=args.passphrase_file is None)
        return service.backup(
            args.destination,
            passphrase=passphrase,
            overwrite=args.overwrite,
        )
    if args.command == "log":
        return service.events(limit=args.limit)
    raise LocalMemoryError(f"unsupported command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        value = dispatch(args)
    except (LocalMemoryError, OSError, ValueError) as exc:
        payload = {"status": "ERROR", "message": str(exc)}
        if args.as_json:
            _print(payload, as_json=True)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    _print(value, as_json=args.as_json)
    if isinstance(value, dict) and value.get("operational_ready") is False:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
