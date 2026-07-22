#!/usr/bin/env python3
"""Read-only Recovery Set verification CLI for P3-10.

Bundle layout:

    recovery-manifest.json
    items/<content-bound item_id>

The trust anchor is intentionally supplied from a separate path. The command
writes only minimized, hash-only RecoveryEvidence.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Mapping

try:
    from wiki_spike.memory_core import (
        RecoveryCoordinator,
        RecoveryError,
        RecoveryTrustAnchor,
        SignedRecoveryManifest,
        canonical_bytes,
    )
except ModuleNotFoundError:  # direct execution from a source checkout
    source_root = Path(__file__).resolve().parents[1] / "src"
    if str(source_root) not in sys.path:
        sys.path.insert(0, str(source_root))
    from wiki_spike.memory_core import (
        RecoveryCoordinator,
        RecoveryError,
        RecoveryTrustAnchor,
        SignedRecoveryManifest,
        canonical_bytes,
    )


class DryRunInputError(ValueError):
    pass


def _canonical_mapping(path: Path) -> dict[str, object]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise DryRunInputError(f"cannot read canonical JSON: {path}") from exc

    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise DryRunInputError(f"duplicate JSON key in {path}: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except DryRunInputError:
        raise
    except Exception as exc:
        raise DryRunInputError(f"invalid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise DryRunInputError(f"JSON root must be an object: {path}")
    try:
        encoded = canonical_bytes(value)
    except Exception as exc:
        raise DryRunInputError(f"non-canonical value: {path}") from exc
    if encoded != raw:
        raise DryRunInputError(f"JSON is not canonical UTF-8: {path}")
    return value


class FilesystemRecoverySource:
    def __init__(self, bundle_dir: Path) -> None:
        self.bundle_dir = bundle_dir.resolve()
        self.items_dir = (self.bundle_dir / "items").resolve()
        if not self.bundle_dir.is_dir() or not self.items_dir.is_dir():
            raise DryRunInputError("bundle directory and items/ are required")
        manifest_path = self.bundle_dir / "recovery-manifest.json"
        self._signed = SignedRecoveryManifest.from_mapping(_canonical_mapping(manifest_path))

    def signed_manifest(self, workspace_id: str) -> SignedRecoveryManifest:
        if self._signed.manifest.workspace_id != workspace_id:
            raise DryRunInputError("workspace does not match recovery manifest")
        return self._signed

    def read_item(self, workspace_id: str, item_id: str) -> bytes:
        if self._signed.manifest.workspace_id != workspace_id:
            raise DryRunInputError("workspace does not match recovery manifest")
        candidate = self.items_dir / item_id
        if candidate.is_symlink():
            raise DryRunInputError(f"symlinked Recovery Set item is forbidden: {item_id}")
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.items_dir)
        except ValueError as exc:
            raise DryRunInputError("Recovery Set item escapes items directory") from exc
        return resolved.read_bytes()


def load_trust_anchor(path: Path) -> RecoveryTrustAnchor:
    return RecoveryTrustAnchor.from_mapping(_canonical_mapping(path))


def run_dry_run(
    *,
    bundle_dir: Path,
    trust_anchor_path: Path,
    workspace_id: str,
    completed_at: str,
):
    source = FilesystemRecoverySource(bundle_dir)
    trust = load_trust_anchor(trust_anchor_path)
    coordinator = RecoveryCoordinator(
        source,
        trust,
        completed_at=completed_at,
    )
    return coordinator.dry_run(workspace_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="p3-10-recovery-dry-run")
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--trust-anchor", type=Path, required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--completed-at", required=True)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence = run_dry_run(
            bundle_dir=args.bundle_dir,
            trust_anchor_path=args.trust_anchor,
            workspace_id=args.workspace_id,
            completed_at=args.completed_at,
        )
    except (RecoveryError, DryRunInputError, OSError, ValueError) as exc:
        error_code = getattr(exc, "error_code", "invalid_recovery_input")
        print(
            json.dumps(
                {"status": "fail", "error_code": error_code, "message": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2

    output = evidence.canonical_bytes()
    if args.json_out is not None:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_bytes(output)
    sys.stdout.buffer.write(output + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
