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
    arguments = _Arguments()
    _ = parser.parse_args(namespace=arguments)
    return arguments


def _signature_paths(value: Path | list[str] | None) -> tuple[str, ...]:
    if isinstance(value, list) and value:
        return tuple(value)
    if isinstance(value, Path):
        return (str(value),)
    raise UnifiedDbExportCliError("signature is required")


def _run_authority(arguments: _Arguments) -> int:
    from wiki_spike.applications.unified_db_export_authorization_cli import (
        PublicEnvelopeFiles,
        assemble_authority_envelopes,
        emit_authority_signing_bytes,
        inspect_authority_signing_bytes,
        verify_authority_envelopes,
        wrap_authority_envelope,
    )

    command = arguments.command
    if command == "authority-signing-bytes":
        return emit_authority_signing_bytes(arguments.body, arguments.out)
    if command == "authority-inspect":
        return inspect_authority_signing_bytes(arguments.signing_bytes)
    if command == "authority-envelope":
        signature = arguments.signature
        if not isinstance(signature, Path):
            raise UnifiedDbExportCliError("signature must be a public file")
        return wrap_authority_envelope(
            PublicEnvelopeFiles(
                arguments.role, arguments.key_id, arguments.public_key, signature
            )
        )
    if command == "authority-assemble":
        return assemble_authority_envelopes(
            arguments.body, _signature_paths(arguments.signature), arguments.out
        )
    if command == "authority-verify":
        return verify_authority_envelopes(
            arguments.body, _signature_paths(arguments.signature)
        )
    raise UnifiedDbExportCliError("unknown authority command")


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
            is_authority_command,
        )

        if is_authority_command(arguments.command):
            return _run_authority(arguments)
        if arguments.command == "export":
            raise UnifiedDbExportError(
                "live export refused: executable mapping and signed authority are absent"
            )
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
