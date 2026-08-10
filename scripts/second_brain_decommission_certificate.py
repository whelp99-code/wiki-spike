#!/usr/bin/env python3
"""Fail-closed, evidence-only Second Brain decommission certificate CLI.

The standalone program deliberately owns no signing key, trusted clock, public
key, registry, or deletion mechanism.  Production supplies those capabilities
only through :func:`run_with_authority`; a successful certificate remains
non-destructive evidence rather than a revocation or delete command.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Mapping


_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_contracts import (  # noqa: E402
    ActivationReceiptV1,
    ConsentTransferReceiptV1,
    DecommissionCertificateRequestV1,
    DecommissionCertificateV1,
)
from wiki_spike.memory_core.second_brain_cutover import CutoverDecisionV1  # noqa: E402
from wiki_spike.memory_core.second_brain_ports import DecommissionCertificateVerifierPort  # noqa: E402
from second_brain_reconcile import validate_reconciliation_receipt  # noqa: E402


_MAX_JSON_BYTES = 16 * 1024 * 1024
_ABSENT = "DEPLOYMENT_DECOMMISSION_AUTHORITY_ABSENT"
_REJECTED = "AUTHORIZED_DECOMMISSION_REJECTED"
_NINETY_DAYS = timedelta(days=90)


class DecommissionCertificateError(Exception):
    """Private cause marker; public failures intentionally disclose no details."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise DecommissionCertificateError("duplicate JSON key")
        value[key] = item
    return value


def _wire_bytes(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DecommissionCertificateError("uncanonical JSON") from exc


def _canonical_absolute_path(raw: str, *, output: bool = False) -> Path:
    if not isinstance(raw, str) or not os.path.isabs(raw) or raw.startswith("//") or raw != os.path.normpath(raw):
        raise DecommissionCertificateError("noncanonical path")
    if any(part in {"", ".", ".."} for part in raw.split(os.sep)[1:]):
        raise DecommissionCertificateError("path aliases")
    path = Path(raw)
    # Only ancestors must be directories.  The final input component is a
    # regular evidence file and is checked by _read_stable_file instead.
    components = path.parts[1:-1]
    current = Path(path.anchor)
    for component in components:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise DecommissionCertificateError("unreadable path component") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise DecommissionCertificateError("symlink or non-directory component")
    if output:
        try:
            parent = path.parent.lstat()
        except OSError as exc:
            raise DecommissionCertificateError("unreadable output parent") from exc
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise DecommissionCertificateError("unsafe output parent")
    return path


def _read_stable_file(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise DecommissionCertificateError("cannot stat input") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise DecommissionCertificateError("input must be a private regular file")
    if before.st_size > _MAX_JSON_BYTES:
        raise DecommissionCertificateError("oversized input")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != identity):
            raise DecommissionCertificateError("input changed before read")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > _MAX_JSON_BYTES:
                raise DecommissionCertificateError("oversized input")
            chunks.append(chunk)
        after = path.lstat()
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) != identity or
                after.st_nlink != 1 or total != before.st_size):
            raise DecommissionCertificateError("input changed while read")
        return b"".join(chunks)
    except OSError as exc:
        raise DecommissionCertificateError("cannot read input") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_canonical_object(raw: str) -> tuple[dict[str, Any], str]:
    payload = _read_stable_file(_canonical_absolute_path(raw))
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, ValueError, DecommissionCertificateError) as exc:
        raise DecommissionCertificateError("invalid JSON input") from exc
    if not isinstance(value, dict) or _wire_bytes(value) != payload:
        raise DecommissionCertificateError("noncanonical JSON input")
    return value, sha256(payload).hexdigest()


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str) or len(value) != 20 or not value.endswith("Z"):
        raise DecommissionCertificateError("noncanonical timestamp")
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise DecommissionCertificateError("invalid timestamp") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _assert_new_output(raw: str) -> Path:
    path = _canonical_absolute_path(raw, output=True)
    try:
        path.lstat()
    except FileNotFoundError:
        return path
    except OSError as exc:
        raise DecommissionCertificateError("cannot stat output") from exc
    raise DecommissionCertificateError("output collision")


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("short write")
        offset += written


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_create_only(path: Path, certificate: DecommissionCertificateV1) -> None:
    payload = canonical_bytes(certificate.to_mapping())
    temporary: str | None = None
    descriptor: int | None = None
    identity: tuple[int, int] | None = None
    linked = False
    committed = False
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        info = os.stat(temporary)
        identity = (info.st_dev, info.st_ino)
        os.link(temporary, path)
        linked = True
        _fsync_directory(path.parent)
        committed = True
    except FileExistsError as exc:
        raise DecommissionCertificateError("output collision") from exc
    except OSError as exc:
        if linked and identity is not None:
            try:
                published = path.stat()
                if (published.st_dev, published.st_ino) == identity:
                    os.unlink(path)
                    _fsync_directory(path.parent)
            except OSError:
                pass
        raise DecommissionCertificateError("cannot publish certificate") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            except OSError:
                if not committed:
                    raise DecommissionCertificateError("cannot clean private temporary output")


def _bound_request(args: argparse.Namespace) -> tuple[DecommissionCertificateRequestV1, ActivationReceiptV1, ConsentTransferReceiptV1]:
    activation_data, _ = _load_canonical_object(args.activation)
    decision_data, _ = _load_canonical_object(args.decision)
    conservation_data, conservation_sha256 = _load_canonical_object(args.conservation)
    consent_data, _ = _load_canonical_object(args.consent_transfer)
    try:
        activation = ActivationReceiptV1.from_mapping(activation_data)
        decision = CutoverDecisionV1.from_mapping(decision_data)
        conservation = validate_reconciliation_receipt(conservation_data)
        consent = ConsentTransferReceiptV1.from_mapping(consent_data)
    except Exception as exc:
        raise DecommissionCertificateError("closed evidence validation failed") from exc

    retention_end = _timestamp(args.retention_end)
    if retention_end != _timestamp(activation.activated_at) + _NINETY_DAYS:
        raise DecommissionCertificateError("retention interval is not exactly ninety days")
    if (activation.workspace_ref != decision.workspace_ref or
            activation.cutover_decision_digest != decision.decision_digest or
            activation.cohort_manifest_digest != decision.cohort_manifest_digest):
        raise DecommissionCertificateError("activation does not bind cutover decision")
    if conservation.verification_mode != "RESTORE_RECALL_VERIFIED":
        raise DecommissionCertificateError("conservation verification mode is insufficient")
    if (conservation.result.result != "PASS" or conservation.result.no_import or
            conservation.result.live_operation_authorized or
            conservation.request.backup_manifest_digest is None or
            conservation.isolated_restore_target_digest is None or
            conservation.deterministic_recall_digest is None):
        raise DecommissionCertificateError("conservation evidence is not a non-live restore-recall pass")
    if (consent.workspace_ref != activation.workspace_ref or consent.source_ref != activation.source_ref or
            consent.activation_digest != activation.activation_digest or
            consent.cutover_decision_digest != decision.decision_digest or
            consent.conservation_receipt_sha256 != conservation_sha256 or
            consent.allowlist_digest != args.allowlist_digest):
        raise DecommissionCertificateError("consent transfer does not bind evidence")
    # Construct then reparse: the Core DTO remains the sole closed wire parser.
    body = {
        "decommission_certificate_request_version": "second-brain-decommission-certificate-request-v1",
        "workspace_ref": activation.workspace_ref, "source_ref": activation.source_ref,
        "activation_digest": activation.activation_digest, "retention_end": args.retention_end,
        "cutover_decision_digest": decision.decision_digest, "conservation_receipt_sha256": conservation_sha256,
        "backup_manifest_digest": conservation.request.backup_manifest_digest,
        "isolated_restore_target_digest": conservation.isolated_restore_target_digest,
        "deterministic_recall_digest": conservation.deterministic_recall_digest,
        "allowlist_digest": args.allowlist_digest, "consent_transfer_receipt_digest": consent.receipt_digest,
        "approval_digests": [entry.to_mapping() for entry in activation.approval_digests],
        "requested_state": "ROLLBACK_CLOSED", "destructive_action_authorized": False,
    }
    request = DecommissionCertificateRequestV1.from_mapping(
        body | {"request_digest": sha256(canonical_bytes(body)).hexdigest()}
    )
    return request, activation, consent


def _run_authorized(args: argparse.Namespace, authority: DecommissionCertificateVerifierPort) -> int:
    if not isinstance(authority, DecommissionCertificateVerifierPort):
        raise DecommissionCertificateError("invalid deployment authority")
    output = _assert_new_output(args.out)
    request, activation, consent = _bound_request(args)
    try:
        returned = authority.issue_decommission_certificate(request, activation=activation, consent_transfer=consent)
    except Exception as exc:
        raise DecommissionCertificateError("deployment authority rejected request") from exc
    # A frozen DTO can still be fabricated with ``dataclasses.replace`` or
    # ``object.__new__``.  Check its actual fields before ``to_mapping``
    # normalizes non-authorizing constants, then reparse the closed wire.
    if type(returned) is not DecommissionCertificateV1:
        raise DecommissionCertificateError("authority returned non-certificate")
    if (type(returned.request) is not DecommissionCertificateRequestV1 or
            returned.destructive_action_authorized is not False or
            returned.request.destructive_action_authorized is not False or
            returned.state != "ROLLBACK_CLOSED" or
            returned.retention_seconds != "7776000"):
        raise DecommissionCertificateError("authority returned unsafe certificate object")
    # Reparse catches an object fabricated through unsafe construction as well as
    # validating the self-binding digest before anything reaches disk.
    try:
        certificate = DecommissionCertificateV1.from_mapping(returned.to_mapping())
    except Exception as exc:
        raise DecommissionCertificateError("authority returned malformed certificate") from exc
    try:
        if authority.verify_issued_decommission_certificate(certificate) is not True:
            raise DecommissionCertificateError("authority did not verify returned certificate")
    except DecommissionCertificateError:
        raise
    except Exception as exc:
        raise DecommissionCertificateError("authority certificate verification failed") from exc
    verified_at = _timestamp(certificate.verified_at)
    retention_end = _timestamp(request.retention_end)
    consent_issued_at = _timestamp(consent.issued_at)
    consent_expires_at = _timestamp(consent.expires_at)
    if (certificate.request.to_mapping() != request.to_mapping() or
            certificate.request_digest != request.request_digest or
            verified_at < retention_end or
            not (consent_issued_at <= verified_at < consent_expires_at) or
            certificate.retention_seconds != "7776000" or
            certificate.state != "ROLLBACK_CLOSED" or
            certificate.destructive_action_authorized is not False):
        raise DecommissionCertificateError("authority certificate is not bound to request")
    _publish_create_only(output, certificate)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed Second Brain decommission evidence certificate.")
    commands = parser.add_subparsers(dest="command", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--activation", required=True)
    verify.add_argument("--retention-end", required=True)
    verify.add_argument("--decision", required=True)
    verify.add_argument("--conservation", required=True)
    verify.add_argument("--allowlist-digest", required=True)
    verify.add_argument("--consent-transfer", required=True)
    verify.add_argument("--out", required=True)
    return parser


def run_with_authority(argv: list[str] | None, *, authority: DecommissionCertificateVerifierPort) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        return _run_authorized(args, authority)
    except SystemExit as exc:
        # ``argparse`` is an implementation detail of the internal seam too:
        # callers receive the normal rc 2 refusal rather than an exception.
        return int(exc.code) if isinstance(exc.code, int) else 2
    except (DecommissionCertificateError, ValueError):
        print(f"FAIL: {_REJECTED}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    """Public entry point: parses text only, then refuses before any I/O."""
    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit:
        raise
    print(f"FAIL: {_ABSENT}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
