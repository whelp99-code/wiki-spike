#!/usr/bin/env python3
"""Gate 8 attestation issuance, final-receipt write, and strict receipt
import for the Encrypted Single-Memory Lifecycle.

Closes the review-process gap after ``scripts/join_gate8_evidence.py``:
operators previously had to hand-write Python (docs/gate8-runbook.md §4) to
issue reviewer attestations, write the final review receipt, and strictly
import it. This CLI wraps exactly the ``wiki_spike.infrastructure.conformance``
APIs the runbook already documents; it never manufactures evidence, a
signature, or a verdict of its own.

Subcommands:

* ``attest``  -- issue one reviewer attestation over a pre-review manifest.
* ``receipt`` -- write the final review receipt from two attestations and
  strictly self-import it before ever writing it to disk.
* ``verify``  -- strictly import an existing final review receipt.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from wiki_spike.infrastructure.conformance import (  # noqa: E402
    REQUIRED_ROLES,
    ConformanceError,
    EvidenceJoin,
    PreReviewManifest,
    attest_manifest,
    build_pre_review_manifest,
    import_final_review_receipt,
    verify_evidence_join,
    write_final_review_receipt,
)

# The attestation wire validator is deliberately private to conformance.py: it is
# the single closed-wire check for a reviewer attestation. Reusing it keeps this
# CLI from growing a second, drifting copy of security validation.
from wiki_spike.infrastructure.conformance import (  # noqa: E402
    _attestation_from_mapping,  # noqa: SLF001
)
from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402

MANIFEST_FIELDS = {"schema", "workspace_id", "implementation_commit", "bundles", "manifest_digest"}
JOIN_FIELDS = {"schema", "workspace_id", "implementation_commit", "import_receipts", "manifest_digest", "join_digest"}


def _read_json(path: Path, kind: str) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConformanceError(f"cli_{kind}_unreadable", f"{kind} file could not be read: {path}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConformanceError(f"cli_{kind}_invalid_json", f"{kind} file is not valid JSON") from exc
    if not isinstance(data, dict):
        raise ConformanceError(f"cli_{kind}_invalid_shape", f"{kind} file must be a JSON object")
    return data


def _load_manifest(path: Path) -> PreReviewManifest:
    """Reload the pre-review manifest, strictly reconstruct it from its
    lane receipts, and reject unless manifest_digest recomputes exactly."""
    data = _read_json(path, "manifest")
    if set(data) != MANIFEST_FIELDS:
        raise ConformanceError("cli_manifest_fields_invalid", "manifest file must use the closed pre-review manifest wire")
    bundles_list = data["bundles"]
    if not isinstance(bundles_list, list):
        raise ConformanceError("cli_manifest_bundles_invalid", "manifest bundles must be a list")
    bundles: dict[str, dict] = {}
    for item in bundles_list:
        if not isinstance(item, dict) or set(item) != {"lane", "receipt"}:
            raise ConformanceError("cli_manifest_bundles_invalid", "each manifest bundle must be {lane, receipt}")
        lane = item["lane"]
        if not isinstance(lane, str) or lane in bundles:
            raise ConformanceError("cli_manifest_bundles_invalid", f"duplicate or invalid lane {lane!r} in manifest bundles")
        if not isinstance(item["receipt"], dict):
            raise ConformanceError("cli_manifest_bundles_invalid", f"lane {lane!r} receipt must be an object")
        bundles[lane] = item["receipt"]
    if not isinstance(data["workspace_id"], str) or not isinstance(data["implementation_commit"], str):
        raise ConformanceError("cli_manifest_fields_invalid", "manifest workspace_id/implementation_commit must be strings")
    manifest = build_pre_review_manifest(
        workspace_id=data["workspace_id"],
        implementation_commit=data["implementation_commit"],
        bundles=bundles,
    )
    if manifest.manifest_digest != data["manifest_digest"]:
        raise ConformanceError("cli_manifest_digest_mismatch", "manifest_digest does not recompute from the manifest file")
    return manifest


def _load_join(path: Path) -> EvidenceJoin:
    """Reload the evidence join verbatim; callers verify it against the
    manifest with ``verify_evidence_join`` before trusting it."""
    data = _read_json(path, "join")
    if set(data) != JOIN_FIELDS:
        raise ConformanceError("cli_join_fields_invalid", "join file must use the closed evidence-join wire")
    receipts_list = data["import_receipts"]
    if not isinstance(receipts_list, list):
        raise ConformanceError("cli_join_receipts_invalid", "join import_receipts must be a list")
    import_receipts: list[tuple[str, dict]] = []
    for item in receipts_list:
        if not isinstance(item, dict) or set(item) != {"lane", "receipt"} or not isinstance(item["receipt"], dict):
            raise ConformanceError("cli_join_receipts_invalid", "each join receipt must be {lane, receipt}")
        import_receipts.append((item["lane"], item["receipt"]))
    for field in ("schema", "workspace_id", "implementation_commit", "manifest_digest", "join_digest"):
        if not isinstance(data[field], str) or not data[field]:
            raise ConformanceError("cli_join_fields_invalid", f"join {field} must be a non-empty string")
    return EvidenceJoin(
        schema=data["schema"],
        workspace_id=data["workspace_id"],
        implementation_commit=data["implementation_commit"],
        import_receipts=tuple(import_receipts),
        manifest_digest=data["manifest_digest"],
        join_digest=data["join_digest"],
    )


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        raw = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except OSError as exc:
        raise ConformanceError("cli_private_key_unreadable", f"private key file could not be read: {path}") from exc
    except ValueError as exc:
        raise ConformanceError("cli_private_key_invalid", "private key file must contain raw ed25519 hex") from exc
    if len(raw) != 32:
        raise ConformanceError("cli_private_key_invalid", "private key must be exactly 32 raw bytes (64 hex characters)")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise ConformanceError("cli_private_key_invalid", "private key bytes are not a valid ed25519 key") from exc


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        raw = bytes.fromhex(path.read_text(encoding="utf-8").strip())
    except OSError as exc:
        raise ConformanceError("cli_public_key_unreadable", f"public key file could not be read: {path}") from exc
    except ValueError as exc:
        raise ConformanceError("cli_public_key_invalid", "public key file must contain raw ed25519 hex") from exc
    if len(raw) != 32:
        raise ConformanceError("cli_public_key_invalid", "public key must be exactly 32 raw bytes (64 hex characters)")
    try:
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:
        raise ConformanceError("cli_public_key_invalid", "public key bytes are not a valid ed25519 key") from exc


def _parse_trusted_reviewers(specs: list[str]) -> dict[str, tuple[str, Ed25519PublicKey]]:
    if len(specs) != len(REQUIRED_ROLES):
        raise ConformanceError("cli_trusted_reviewer_count", f"exactly {len(REQUIRED_ROLES)} --trusted-reviewer entries are required")
    trusted: dict[str, tuple[str, Ed25519PublicKey]] = {}
    for spec in specs:
        parts = spec.split("=", 2)
        if len(parts) != 3:
            raise ConformanceError("cli_trusted_reviewer_invalid", f"--trusted-reviewer must be ROLE=KEY_ID=path, got {spec!r}")
        role, key_id, path_str = parts
        if role not in REQUIRED_ROLES:
            raise ConformanceError("cli_trusted_reviewer_invalid_role", f"unknown reviewer role {role!r}")
        if role in trusted:
            raise ConformanceError("cli_trusted_reviewer_duplicate_role", f"duplicate trusted reviewer role {role!r}")
        if not key_id:
            raise ConformanceError("cli_trusted_reviewer_invalid", "trusted reviewer key id must be non-empty")
        trusted[role] = (key_id, _load_public_key(Path(path_str)))
    missing = [role for role in REQUIRED_ROLES if role not in trusted]
    if missing:
        raise ConformanceError("cli_trusted_reviewer_missing_role", f"missing trusted reviewer role(s): {missing}")
    return trusted


def _load_attestation(path: Path):
    return _attestation_from_mapping(_read_json(path, "attestation"))


def _cmd_attest(args: argparse.Namespace) -> int:
    manifest = _load_manifest(Path(args.manifest))
    private_key = _load_private_key(Path(args.private_key))
    attestation = attest_manifest(
        reviewer_role=args.role,
        reviewer_key_id=args.key_id,
        private_key=private_key,
        workspace_id=manifest.workspace_id,
        implementation_commit=manifest.implementation_commit,
        manifest_digest=manifest.manifest_digest,
        issued_at=args.issued_at,
        expires_at=args.expires_at,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(canonical_bytes(attestation.to_mapping()) + b"\n")
    print(f"reviewer_role={attestation.reviewer_role}")
    print(f"reviewer_key_id={attestation.reviewer_key_id}")
    print(f"manifest_digest={attestation.manifest_digest}")
    print(f"wrote {out_path}")
    return 0


def _cmd_receipt(args: argparse.Namespace) -> int:
    if len(args.attestation) != 2:
        raise ConformanceError("cli_attestation_count", "exactly 2 --attestation entries are required")
    manifest = _load_manifest(Path(args.manifest))
    join = _load_join(Path(args.join))
    verify_evidence_join(join, manifest.manifest_digest)
    trusted_reviewers = _parse_trusted_reviewers(args.trusted_reviewer)
    attestations = tuple(_load_attestation(Path(p)) for p in args.attestation)
    role_order = {role: index for index, role in enumerate(REQUIRED_ROLES)}
    attestations = tuple(sorted(attestations, key=lambda a: role_order.get(a.reviewer_role, len(role_order))))

    receipt_bytes = write_final_review_receipt(
        workspace_id=args.workspace_id,
        implementation_commit=args.implementation_commit,
        manifest=manifest,
        evidence_join=join,
        attestations=attestations,
        trusted_reviewers=trusted_reviewers,
        now=args.now,
    )
    # Never write a receipt that fails its own strict re-import.
    imported = import_final_review_receipt(
        receipt_bytes,
        trusted_reviewers=trusted_reviewers,
        workspace_id=args.workspace_id,
        implementation_commit=args.implementation_commit,
        manifest=manifest,
        evidence_join=join,
        now=args.now,
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(receipt_bytes)
    print(f"manifest_digest={manifest.manifest_digest}")
    print(f"reviewer_roles={sorted(a.reviewer_role for a in imported)}")
    print(f"wrote {out_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    manifest = _load_manifest(Path(args.manifest))
    join = _load_join(Path(args.join))
    trusted_reviewers = _parse_trusted_reviewers(args.trusted_reviewer)
    try:
        receipt_bytes = Path(args.receipt).read_bytes()
    except OSError as exc:
        raise ConformanceError("cli_receipt_unreadable", f"receipt file could not be read: {args.receipt}") from exc
    attestations = import_final_review_receipt(
        receipt_bytes,
        trusted_reviewers=trusted_reviewers,
        workspace_id=args.workspace_id,
        implementation_commit=args.implementation_commit,
        manifest=manifest,
        evidence_join=join,
        now=args.now,
    )
    for attestation in attestations:
        print(f"reviewer_role={attestation.reviewer_role} reviewer_key_id={attestation.reviewer_key_id}")
    print("VERIFIED")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    attest_p = sub.add_parser("attest", help="issue one reviewer attestation over a pre-review manifest")
    attest_p.add_argument("--manifest", required=True)
    attest_p.add_argument("--role", required=True, choices=REQUIRED_ROLES)
    attest_p.add_argument("--key-id", required=True)
    attest_p.add_argument("--private-key", required=True, help="path to a raw 32-byte ed25519 private key, hex-encoded")
    attest_p.add_argument("--issued-at", required=True)
    attest_p.add_argument("--expires-at", required=True)
    attest_p.add_argument("--out", required=True)

    receipt_p = sub.add_parser("receipt", help="write and strictly self-import the final review receipt")
    receipt_p.add_argument("--manifest", required=True)
    receipt_p.add_argument("--join", required=True)
    receipt_p.add_argument("--attestation", action="append", required=True, help="repeatable; exactly 2 attestation files")
    receipt_p.add_argument(
        "--trusted-reviewer", action="append", required=True,
        help="repeatable; ROLE=KEY_ID=<raw ed25519 public-key hex file>",
    )
    receipt_p.add_argument("--workspace-id", required=True)
    receipt_p.add_argument("--implementation-commit", required=True)
    receipt_p.add_argument("--now", required=True)
    receipt_p.add_argument("--out", required=True)

    verify_p = sub.add_parser("verify", help="strictly import an existing final review receipt")
    verify_p.add_argument("--receipt", required=True)
    verify_p.add_argument("--manifest", required=True)
    verify_p.add_argument("--join", required=True)
    verify_p.add_argument(
        "--trusted-reviewer", action="append", required=True,
        help="repeatable; ROLE=KEY_ID=<raw ed25519 public-key hex file>",
    )
    verify_p.add_argument("--workspace-id", required=True)
    verify_p.add_argument("--implementation-commit", required=True)
    verify_p.add_argument("--now", required=True)

    args = parser.parse_args(argv)
    try:
        if args.command == "attest":
            return _cmd_attest(args)
        if args.command == "receipt":
            return _cmd_receipt(args)
        return _cmd_verify(args)
    except ConformanceError as exc:
        print(f"REJECTED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
