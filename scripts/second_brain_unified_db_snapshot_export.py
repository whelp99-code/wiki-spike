#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly:
#      uv run scripts/second_brain_unified_db_snapshot_export.py --help
# ──────────────────
"""Fixture-safe CLI for immutable unified-db snapshot package export."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ = sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


class UnifiedDbExportCliError(ValueError):
    """The CLI input or output boundary refused an operation."""


class _Arguments(argparse.Namespace):
    command: str = ""
    profile: Path = Path()
    plan: Path = Path()
    fixture: Path = Path()
    output: Path = Path()
    package: Path = Path()
    dsn_fd: int | None = None
    body: Path = Path()
    out: Path = Path()
    signing_bytes: Path = Path()
    role: str = ""
    key_id: str = ""
    public_key: Path = Path()
    signature: Path | list[str] | None = None
    kind: str = ""
    input_path: Path = Path()
    identity: Path = Path()
    mapping: Path = Path()
    adapter: Path = Path()
    destination: Path = Path()
    quiescence: Path = Path()
    authorization: Path = Path()
    catalog: Path = Path()
    query_manifest: Path = Path()


def _load_json(path: Path) -> dict[str, JsonValue]:
    from wiki_spike.applications.unified_db_snapshot_export_io import (
        HARD_CAP,
        read_bounded_path,
    )

    try:
        return decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))
    except OSError as exc:
        raise UnifiedDbExportCliError("JSON cannot be read") from exc


def _arguments() -> _Arguments:
    parser = argparse.ArgumentParser(
        description="Export or verify a fixture-only unified-db snapshot package."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    fixture = sub.add_parser("fixture", help="export a fixture-only snapshot package")
    _ = fixture.add_argument("--profile", required=True, type=Path)
    _ = fixture.add_argument("--plan", required=True, type=Path)
    _ = fixture.add_argument("--fixture", required=True, type=Path)
    _ = fixture.add_argument("--output", required=True, type=Path)
    verify = sub.add_parser("verify", help="offline-verify a snapshot package")
    _ = verify.add_argument("--package", required=True, type=Path)
    export = sub.add_parser("export", help="live export (refused in this increment)")
    _ = export.add_argument("--dsn-fd", type=int)
    _ = export.add_argument("--output", type=Path)
    signing = sub.add_parser("authority-signing-bytes", help="emit export-only signing bytes")
    _ = signing.add_argument("--body", required=True, type=Path)
    _ = signing.add_argument("--out", required=True, type=Path)
    inspect = sub.add_parser("authority-inspect", help="decode export-only signing bytes")
    _ = inspect.add_argument("--signing-bytes", required=True, type=Path)
    envelope = sub.add_parser("authority-envelope", help="wrap a public signature envelope")
    _ = envelope.add_argument("--role", required=True, choices=("owner", "approver"))
    _ = envelope.add_argument("--key-id", required=True)
    _ = envelope.add_argument("--public-key", required=True, type=Path)
    _ = envelope.add_argument("--signature", required=True, type=Path)
    assemble = sub.add_parser("authority-assemble", help="bind public envelopes to a body")
    _ = assemble.add_argument("--body", required=True, type=Path)
    _ = assemble.add_argument("--signature", action="append", required=True)
    _ = assemble.add_argument("--out", required=True, type=Path)
    auth_verify = sub.add_parser("authority-verify", help="verify public export-only envelopes")
    _ = auth_verify.add_argument("--body", required=True, type=Path)
    _ = auth_verify.add_argument("--signature", action="append", required=True)
    from wiki_spike.applications.unified_db_live_export_cli import register_live_parsers
    from wiki_spike.applications.unified_db_postgres_capture_cli import (
        register_capture_parsers,
    )

    register_live_parsers(sub)
    register_capture_parsers(sub)
    from wiki_spike.applications.unified_db_postgres_capture_authorization_cli import (
        register_capture_authority_parsers,
    )

    register_capture_authority_parsers(sub)
    arguments = _Arguments()
    _ = parser.parse_args(namespace=arguments)
    return arguments


def _sanitized(message: str) -> str:
    return "".join(character if character.isprintable() else "?" for character in message)


def main() -> int:
    from wiki_spike.applications.unified_db_snapshot_export_service import (
        StaticUnifiedDbFixtureReader,
        UnifiedDbSnapshotExportService,
        load_export_fixture,
        verify_export_package,
    )
    from wiki_spike.infrastructure.local_snapshot_package_writer import (
        LocalSnapshotPackageWriter,
    )
    from wiki_spike.memory_core.contracts import canonical_bytes
    from wiki_spike.memory_core.errors import CoreContractError
    from wiki_spike.memory_core.unified_db_snapshot_export import (
        AUTHORITY_KIND,
        AUTHORITY_VERSION,
        FixtureExportAuthorityV1,
        PackageDurabilityUncertain,
        UnifiedDbExportError,
    )
    from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
        UnifiedDbExportPlanV1,
        UnifiedDbExportProfileV1,
    )

    arguments = _arguments()
    try:
        from wiki_spike.applications.unified_db_export_authorization_cli import (
            AuthorityCliPaths,
            is_authority_command,
            run_authority_command,
        )

        if is_authority_command(arguments.command):
            return run_authority_command(
                arguments.command,
                AuthorityCliPaths(
                    arguments.body,
                    arguments.out,
                    arguments.signing_bytes,
                    arguments.role,
                    arguments.key_id,
                    arguments.public_key,
                    arguments.signature,
                ),
            )
        from wiki_spike.applications.unified_db_live_export_cli import (
            LiveExportCliPaths,
            is_live_contract_command,
            run_live_contract_command,
        )

        if is_live_contract_command(arguments.command):
            return run_live_contract_command(
                arguments.command,
                LiveExportCliPaths(
                    arguments.kind,
                    arguments.input_path,
                    arguments.plan,
                    arguments.identity,
                    arguments.mapping,
                    arguments.adapter,
                    arguments.destination,
                    arguments.quiescence,
                    arguments.authorization,
                ),
            )
        from wiki_spike.applications.unified_db_postgres_capture_authorization_cli import (
            CaptureAuthorityCliPaths,
            is_capture_authority_command,
            run_capture_authority_command,
        )
        if is_capture_authority_command(arguments.command):
            return run_capture_authority_command(
                arguments.command,
                CaptureAuthorityCliPaths(
                    arguments.body,
                    arguments.out,
                    arguments.signing_bytes,
                    arguments.role,
                    arguments.key_id,
                    arguments.public_key,
                    arguments.signature,
                ),
            )
        from wiki_spike.applications.unified_db_postgres_capture_cli import (
            CaptureCliPaths,
            is_capture_contract_command,
            run_capture_contract_command,
        )
        if is_capture_contract_command(arguments.command):
            return run_capture_contract_command(
                arguments.command,
                CaptureCliPaths(
                    arguments.kind,
                    arguments.input_path,
                    arguments.plan,
                    arguments.identity,
                    arguments.catalog,
                    arguments.query_manifest,
                ),
            )
        if arguments.command == "capture":
            from wiki_spike.composition.unified_db_postgres_capture import (
                refuse_postgres_identity_capture,
            )
            return refuse_postgres_identity_capture(dsn_fd=arguments.dsn_fd)
        if arguments.command == "export":
            from wiki_spike.composition.unified_db_live_export import (
                refuse_live_unified_db_export,
            )

            refuse_live_unified_db_export(dsn_fd=arguments.dsn_fd)
        if arguments.command == "verify":
            receipt = verify_export_package(str(arguments.package))
            _ = sys.stdout.buffer.write(canonical_bytes(receipt.to_mapping()) + b"\n")
            return 0
        profile = UnifiedDbExportProfileV1.from_mapping(_load_json(arguments.profile))
        plan = UnifiedDbExportPlanV1.from_mapping(_load_json(arguments.plan))
        loaded = load_export_fixture(arguments.fixture)
        receipt = UnifiedDbSnapshotExportService(
            reader=StaticUnifiedDbFixtureReader(
                loaded.rows,
                loaded.opening_proof,
                loaded.closing_proof,
                loaded.cursors,
                loaded.fixture_id,
                loaded.fixture_digest,
                loaded.row_set_digest,
            ),
            writer=LocalSnapshotPackageWriter(),
        ).export_fixture(
            FixtureExportAuthorityV1.from_mapping(
                {
                    "authority_version": AUTHORITY_VERSION,
                    "authority_kind": AUTHORITY_KIND,
                }
            ),
            profile,
            plan,
            str(arguments.output),
        )
        _ = sys.stdout.buffer.write(canonical_bytes(receipt.to_mapping()) + b"\n")
    except PackageDurabilityUncertain as exc:
        print(_sanitized(str(exc)), file=sys.stderr)
        return 3
    except OSError:
        print("unified-db export refused: filesystem operation failed", file=sys.stderr)
        return 2
    except (CoreContractError, UnifiedDbExportError, UnifiedDbExportCliError) as exc:
        print(f"unified-db export refused: {_sanitized(str(exc))}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
