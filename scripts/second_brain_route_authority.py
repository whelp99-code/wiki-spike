#!/usr/bin/env python3
"""Fail-closed CLI for rehearsing and checking a deployment-injected route switch.

The public executable intentionally has no endpoint/key constructor.  It can
parse only evidence and returns rc 2 until a deployment injects a trusted
``RouteSwitchAuthority`` through :func:`run_with_authority`.  That seam keeps
tests local and prevents argv text from becoming a live authority.
"""
from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any, Mapping, Protocol, cast


sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_contracts import (  # noqa: E402
    CutoverRunbookV1,
    PreMutationRollbackReceiptV1,
    RouteSwitchReceiptV1,
    route_switch_digest,
)
from wiki_spike.memory_core.second_brain_cutover import (  # noqa: E402
    CutoverDecisionV1,
    MigrationCohortManifestV1,
    assert_cohort_transition,
    assert_live_route_switch_authorized,
    assert_pre_mutation_rollback_allowed,
)
from wiki_spike.memory_core.second_brain_ports import RouteSwitchAuthority  # noqa: E402


_MAX_JSON_BYTES = 16 * 1024 * 1024


class RouteAuthorityCliError(Exception):
    """A public input, binding, or publish refusal (never emits source data)."""


class _VerifyingRouteAuthority(RouteSwitchAuthority, Protocol):
    route_authority: str

    def validate_preflight(
        self,
        *,
        runbook_digest: str,
        cutover_decision_digest: str,
        cohort_manifest_digest: str,
        target: str,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt_digest: str,
    ) -> None: ...

    def bind_switch_output(
        self,
        *,
        output_path: str | Path,
        runbook_digest: str,
        cutover_decision_digest: str,
        cohort_manifest_digest: str,
        target: str,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt_digest: str,
    ) -> RouteSwitchReceiptV1 | None: ...

    def load_canonical_switch_receipt(self, *, receipt_path: str | Path) -> RouteSwitchReceiptV1: ...

    def verify_atomic(self, *, receipt: RouteSwitchReceiptV1) -> RouteSwitchReceiptV1: ...


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RouteAuthorityCliError("duplicate JSON key in canonical input")
        result[key] = value
    return result


def _wire_bytes(value: Mapping[str, Any]) -> bytes:
    """Canonical JSON for closed evidence wires, including Stage-6 integers."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RouteAuthorityCliError("route evidence cannot be canonicalized") from exc


def _canonical_absolute_path(raw: str, label: str, *, output: bool = False) -> Path:
    if not isinstance(raw, str) or not os.path.isabs(raw) or raw.startswith("//") or raw != os.path.normpath(raw):
        raise RouteAuthorityCliError(f"{label} must be a canonical absolute path")
    if any(part in {"", ".", ".."} for part in raw.split(os.sep)[1:]):
        raise RouteAuthorityCliError(f"{label} must not contain path aliases")
    path = Path(raw)
    checked = path.parts[1:-1] if output else path.parts[1:]
    current = Path(path.anchor)
    for part in checked:
        current /= part
        try:
            info = current.lstat()
        except OSError as exc:
            raise RouteAuthorityCliError(f"cannot stat {label} path component") from exc
        if stat.S_ISLNK(info.st_mode):
            raise RouteAuthorityCliError(f"{label} must not traverse a symlink")
    if output:
        parent = path.parent
        try:
            info = parent.lstat()
        except OSError as exc:
            raise RouteAuthorityCliError(f"cannot stat {label} parent") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise RouteAuthorityCliError(f"{label} parent must be a real directory")
        return path
    return path


def _read_stable_file(path: Path, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise RouteAuthorityCliError(f"cannot stat {label}") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RouteAuthorityCliError(f"{label} must be a private regular non-symlink file")
    if before.st_size > _MAX_JSON_BYTES:
        raise RouteAuthorityCliError(f"{label} exceeds the maximum supported size")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
        opened_identity = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or opened_identity != identity:
            raise RouteAuthorityCliError(f"{label} changed before it could be read")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            total += len(chunk)
            if total > _MAX_JSON_BYTES:
                raise RouteAuthorityCliError(f"{label} exceeds the maximum supported size")
            chunks.append(chunk)
        after = path.lstat()
        after_identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if after_identity != identity or total != before.st_size or after.st_nlink != 1:
            raise RouteAuthorityCliError(f"{label} changed while it was read")
        return b"".join(chunks)
    except OSError as exc:
        raise RouteAuthorityCliError(f"cannot read {label}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _load_canonical_object(raw: str, label: str) -> dict[str, Any]:
    path = _canonical_absolute_path(raw, label)
    payload = _read_stable_file(path, label)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise RouteAuthorityCliError(f"cannot parse {label} as canonical JSON") from exc
    if not isinstance(value, dict):
        raise RouteAuthorityCliError(f"{label} must contain an object")
    try:
        if _wire_bytes(value) != payload:
            raise RouteAuthorityCliError(f"{label} is not canonical JSON")
    except RouteAuthorityCliError:
        raise
    except Exception as exc:
        raise RouteAuthorityCliError(f"{label} cannot be canonicalized") from exc
    return value


def _inode_identity(stat_result: os.stat_result) -> tuple[int, int]:
    return (stat_result.st_dev, stat_result.st_ino)


def _published_receipt_is_complete(path: Path, payload: bytes, published_inode: tuple[int, int]) -> bool:
    """Return true only when ``path`` still names this invocation's receipt."""
    try:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or _inode_identity(before) != published_inode:
            return False
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return False
    try:
        if _inode_identity(os.fstat(descriptor)) != published_inode:
            return False
        received = bytearray()
        while len(received) <= len(payload):
            chunk = os.read(descriptor, len(payload) - len(received) + 1)
            if not chunk:
                break
            received.extend(chunk)
        after = path.lstat()
        return (
            stat.S_ISREG(after.st_mode)
            and _inode_identity(after) == published_inode
            and bytes(received) == payload
        )
    except OSError:
        return False
    finally:
        os.close(descriptor)


def _unlink_published_receipt(path: Path, published_inode: tuple[int, int]) -> bool:
    """Remove the published name only when it still points at our inode."""
    try:
        current = path.lstat()
        if not stat.S_ISREG(current.st_mode) or _inode_identity(current) != published_inode:
            return False
        os.unlink(path)
    except FileNotFoundError:
        return False
    return True


def _write_new_receipt(raw: str, receipt: RouteSwitchReceiptV1) -> None:
    path = _canonical_absolute_path(raw, "--out", output=True)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RouteAuthorityCliError("cannot stat receipt output") from exc
    else:
        raise RouteAuthorityCliError("receipt output already exists; refuse collision")
    payload = canonical_bytes(receipt.to_mapping())
    descriptor = -1
    temporary: str | None = None
    published_inode: tuple[int, int] | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("short receipt write")
            offset += written
        os.fsync(descriptor)
        published_inode = _inode_identity(os.fstat(descriptor))
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        except OSError:
            # A failed directory fsync occurs after create-only publication.  Do
            # not report failure while leaving an ambiguous committed receipt.
            if _published_receipt_is_complete(path, payload, published_inode):
                return
            if _unlink_published_receipt(path, published_inode):
                os.fsync(directory)
            raise
        finally:
            os.close(directory)
    except FileExistsError as exc:
        raise RouteAuthorityCliError("receipt output already exists; refuse collision") from exc
    except OSError as exc:
        raise RouteAuthorityCliError("cannot atomically publish route receipt") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def _assert_injected_authority(authority: RouteSwitchAuthority | None, route_authority: str) -> _VerifyingRouteAuthority:
    if authority is None:
        raise RouteAuthorityCliError("deployment-injected route authority is required")
    candidate = cast(_VerifyingRouteAuthority, authority)
    if not isinstance(getattr(candidate, "route_authority", None), str) or candidate.route_authority != route_authority:
        raise RouteAuthorityCliError("injected route authority identity is not trusted")
    if not all(callable(getattr(candidate, name, None)) for name in (
        "validate_preflight", "bind_switch_output", "load_canonical_switch_receipt", "verify_atomic",
    )):
        raise RouteAuthorityCliError("injected route authority does not expose the trusted deployment seam")
    return candidate


@dataclass(frozen=True, slots=True)
class BoundCutoverV1:
    runbook: CutoverRunbookV1
    decision: CutoverDecisionV1
    cohort: MigrationCohortManifestV1
    rollback: PreMutationRollbackReceiptV1


def _bind_cutover(args: argparse.Namespace) -> BoundCutoverV1:
    try:
        runbook = CutoverRunbookV1.from_mapping(_load_canonical_object(args.runbook, "runbook"))
        decision = CutoverDecisionV1.from_mapping(_load_canonical_object(args.decision, "cutover decision"))
        cohort = MigrationCohortManifestV1.from_mapping(_load_canonical_object(args.cohort_manifest, "cohort manifest"))
        rollback = PreMutationRollbackReceiptV1.from_mapping(
            _load_canonical_object(args.rollback_receipt, "pre-mutation rollback receipt")
        )
    except RouteAuthorityCliError:
        raise
    except Exception as exc:
        raise RouteAuthorityCliError("route evidence contracts are invalid") from exc

    if args.route_authority != runbook.route_authority or args.target != runbook.target:
        raise RouteAuthorityCliError("route authority or target does not match the signed runbook")
    if args.generation != runbook.generation_digest or args.route_version != runbook.route_version:
        raise RouteAuthorityCliError("generation or route version does not match the signed runbook")
    if (
        cohort.manifest_digest != runbook.cohort_manifest_digest
        or decision.decision_digest != runbook.cutover_decision_digest
        or decision.cohort_manifest_digest != cohort.manifest_digest
        or decision.resolved_scope_digest != cohort.resolved_scope_digest
        or decision.source_manifest_digest != cohort.source_manifest_digest
    ):
        raise RouteAuthorityCliError("runbook, decision, and cohort do not form one exact cutover")
    if (
        decision.generation_digest != runbook.generation_digest
        or decision.route_version != runbook.route_version
        or runbook.postcheck_contract_digest != decision.contract_digest
    ):
        raise RouteAuthorityCliError("runbook and cutover decision digest bindings do not match")
    if (
        rollback.rollback_receipt_digest != runbook.pre_mutation_rollback_receipt_digest
        or rollback.cohort_manifest_digest != cohort.manifest_digest
        or rollback.route_authority != runbook.route_authority
        or rollback.target != runbook.target
        or rollback.generation_digest != runbook.generation_digest
        or rollback.route_version != runbook.route_version
        or rollback.rollback_target != runbook.pre_mutation_rollback_target
    ):
        raise RouteAuthorityCliError("pre-mutation rollback receipt does not bind the signed runbook")
    try:
        assert_cohort_transition("CUTOVER_READY", "ROUTE_SWITCHED_NO_MUTATION")
        if cohort.cohort_state != "CUTOVER_READY":
            raise RouteAuthorityCliError("cohort must be CUTOVER_READY before a route rehearsal")
        assert_pre_mutation_rollback_allowed(rollback.state)
        # Runbook parsing proves an exact four-role list.  Stage-6 keeps the
        # corresponding quantitative/formula gate authoritative.
        assert_live_route_switch_authorized(decision, human_external_approvals_present=True)
    except RouteAuthorityCliError:
        raise
    except Exception as exc:
        raise RouteAuthorityCliError("Stage-6 cutover gate refused this route action") from exc
    return BoundCutoverV1(runbook, decision, cohort, rollback)


def _receipt_from_bound(bound: BoundCutoverV1, *, operation: str, route_state_digest: str, authority_revision: str) -> RouteSwitchReceiptV1:
    return RouteSwitchReceiptV1.create(
        operation=operation,
        state="ROUTE_SWITCHED_NO_MUTATION" if operation == "REHEARSE" else "CANONICAL_MUTATED",
        route_authority=bound.runbook.route_authority,
        cohort_manifest_digest=bound.cohort.manifest_digest,
        cutover_decision_digest=bound.decision.decision_digest,
        target=bound.runbook.target,
        resolved_scope_digest=bound.decision.resolved_scope_digest,
        contract_digest=bound.decision.contract_digest,
        source_manifest_digest=bound.decision.source_manifest_digest,
        capability_manifest_digest=bound.decision.capability_manifest_digest,
        benchmark_manifest_digest=bound.decision.benchmark_manifest_digest,
        generation_digest=bound.decision.generation_digest,
        checkpoint_digest=bound.decision.checkpoint_digest,
        route_version=bound.decision.route_version,
        capability_epoch=bound.runbook.capability_epoch,
        visibility=bound.runbook.visibility,
        pre_mutation_rollback_receipt_digest=bound.rollback.rollback_receipt_digest,
        route_state_digest=route_state_digest,
        authority_revision=authority_revision,
    )


def _validate_deployment_preflight(authority: _VerifyingRouteAuthority, bound: BoundCutoverV1) -> None:
    """Make the adapter prove the exact runbook/decision anchor before output or mutation."""
    authority.validate_preflight(
        runbook_digest=bound.runbook.runbook_digest,
        cutover_decision_digest=bound.decision.decision_digest,
        cohort_manifest_digest=bound.cohort.manifest_digest,
        target=bound.runbook.target,
        resolved_scope_digest=bound.decision.resolved_scope_digest,
        contract_digest=bound.decision.contract_digest,
        source_manifest_digest=bound.decision.source_manifest_digest,
        capability_manifest_digest=bound.decision.capability_manifest_digest,
        benchmark_manifest_digest=bound.decision.benchmark_manifest_digest,
        generation_digest=bound.decision.generation_digest,
        checkpoint_digest=bound.decision.checkpoint_digest,
        route_version=bound.decision.route_version,
        capability_epoch=bound.runbook.capability_epoch,
        visibility=bound.runbook.visibility,
        pre_mutation_rollback_receipt_digest=bound.rollback.rollback_receipt_digest,
    )


def _bind_deployment_output(
    authority: _VerifyingRouteAuthority, bound: BoundCutoverV1, output_path: str
) -> RouteSwitchReceiptV1 | None:
    return authority.bind_switch_output(
        output_path=output_path,
        runbook_digest=bound.runbook.runbook_digest,
        cutover_decision_digest=bound.decision.decision_digest,
        cohort_manifest_digest=bound.cohort.manifest_digest,
        target=bound.runbook.target,
        resolved_scope_digest=bound.decision.resolved_scope_digest,
        contract_digest=bound.decision.contract_digest,
        source_manifest_digest=bound.decision.source_manifest_digest,
        capability_manifest_digest=bound.decision.capability_manifest_digest,
        benchmark_manifest_digest=bound.decision.benchmark_manifest_digest,
        generation_digest=bound.decision.generation_digest,
        checkpoint_digest=bound.decision.checkpoint_digest,
        route_version=bound.decision.route_version,
        capability_epoch=bound.runbook.capability_epoch,
        visibility=bound.runbook.visibility,
        pre_mutation_rollback_receipt_digest=bound.rollback.rollback_receipt_digest,
    )


def _cmd_rehearse(authority: RouteSwitchAuthority | None, args: argparse.Namespace) -> int:
    bound = _bind_cutover(args)
    injected = _assert_injected_authority(authority, bound.runbook.route_authority)
    _validate_deployment_preflight(injected, bound)
    # No adapter method is invoked: this receipt is a read-only Stage-6 proof.
    rehearsal_head = sha256(canonical_bytes({
        "runbook_digest": bound.runbook.runbook_digest,
        "rollback_receipt_digest": bound.rollback.rollback_receipt_digest,
        "state": "ROUTE_SWITCHED_NO_MUTATION",
    })).hexdigest()
    _write_new_receipt(args.out, _receipt_from_bound(bound, operation="REHEARSE", route_state_digest=rehearsal_head, authority_revision="1"))
    return 0


def _cmd_switch_atomic(authority: RouteSwitchAuthority | None, args: argparse.Namespace) -> int:
    bound = _bind_cutover(args)
    injected = _assert_injected_authority(authority, bound.runbook.route_authority)
    recovered = _bind_deployment_output(injected, bound, args.out)
    if recovered is not None:
        expected = _receipt_from_bound(
            bound, operation="SWITCH_ATOMIC", route_state_digest=recovered.route_state_digest,
            authority_revision=recovered.authority_revision,
        )
        if recovered.to_mapping() != expected.to_mapping():
            raise RouteAuthorityCliError("recovered route output does not bind the requested transaction")
        return 0
    receipt = injected.switch_atomic(
        cohort_manifest=bound.cohort,
        resolved_scope_digest=bound.decision.resolved_scope_digest,
        contract_digest=bound.decision.contract_digest,
        source_manifest_digest=bound.decision.source_manifest_digest,
        capability_manifest_digest=bound.decision.capability_manifest_digest,
        benchmark_manifest_digest=bound.decision.benchmark_manifest_digest,
        generation_digest=bound.decision.generation_digest,
        checkpoint_digest=bound.decision.checkpoint_digest,
        route_version=bound.decision.route_version,
        capability_epoch=bound.runbook.capability_epoch,
        visibility=bound.runbook.visibility,
        pre_mutation_rollback_receipt=bound.rollback.rollback_receipt_digest,
    )
    if not isinstance(receipt, RouteSwitchReceiptV1) or receipt.to_mapping() != _receipt_from_bound(
        bound,
        operation="SWITCH_ATOMIC",
        route_state_digest=receipt.route_state_digest if isinstance(receipt, RouteSwitchReceiptV1) else "0" * 64,
        authority_revision=receipt.authority_revision if isinstance(receipt, RouteSwitchReceiptV1) else "1",
    ).to_mapping():
        raise RouteAuthorityCliError("injected authority returned an unbound route switch receipt")
    published = injected.load_canonical_switch_receipt(receipt_path=args.out)
    if published.to_mapping() != receipt.to_mapping():
        raise RouteAuthorityCliError("canonical route output does not match the atomic switch receipt")
    return 0


def _cmd_verify(authority: RouteSwitchAuthority | None, args: argparse.Namespace) -> int:
    injected = _assert_injected_authority(authority, args.route_authority)
    receipt = injected.load_canonical_switch_receipt(receipt_path=args.receipt)
    if receipt.operation != "SWITCH_ATOMIC":
        raise RouteAuthorityCliError("verify requires a canonical switch receipt")
    if (
        receipt.route_authority != args.route_authority
        or receipt.target != args.target
        or receipt.generation_digest != args.generation
        or receipt.route_version != args.route_version
    ):
        raise RouteAuthorityCliError("verify argv does not match the canonical switch receipt")
    _canonical_absolute_path(args.out, "--out", output=True)
    try:
        Path(args.out).lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise RouteAuthorityCliError("cannot stat receipt output") from exc
    else:
        raise RouteAuthorityCliError("receipt output already exists; refuse collision")
    postcheck = injected.verify_atomic(receipt=receipt)
    if not isinstance(postcheck, RouteSwitchReceiptV1) or postcheck.operation != "VERIFY":
        raise RouteAuthorityCliError("injected authority returned an invalid postcheck receipt")
    for field in (
        "route_authority", "cohort_manifest_digest", "cutover_decision_digest", "target",
        "resolved_scope_digest", "contract_digest", "source_manifest_digest",
        "capability_manifest_digest", "benchmark_manifest_digest", "generation_digest",
        "checkpoint_digest", "route_version", "capability_epoch", "visibility",
        "pre_mutation_rollback_receipt_digest", "route_state_digest", "authority_revision",
    ):
        if getattr(postcheck, field) != getattr(receipt, field):
            raise RouteAuthorityCliError("postcheck receipt does not bind canonical switch state")
    _write_new_receipt(args.out, postcheck)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed Second Brain route authority evidence CLI.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("rehearse", "switch-atomic"):
        command = commands.add_parser(name)
        command.add_argument("--runbook", required=True)
        command.add_argument("--decision", required=True)
        command.add_argument("--cohort-manifest", required=True)
        command.add_argument("--route-authority", required=True)
        command.add_argument("--target", required=True)
        command.add_argument("--generation", required=True)
        command.add_argument("--route-version", required=True)
        command.add_argument("--rollback-receipt", required=True)
        command.add_argument("--out", required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--route-authority", required=True)
    verify.add_argument("--target", required=True)
    verify.add_argument("--generation", required=True)
    verify.add_argument("--route-version", required=True)
    verify.add_argument("--receipt", required=True)
    verify.add_argument("--out", required=True)
    return parser


def run_with_authority(authority: RouteSwitchAuthority | None, argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
        if args.command == "rehearse":
            return _cmd_rehearse(authority, args)
        if args.command == "switch-atomic":
            return _cmd_switch_atomic(authority, args)
        return _cmd_verify(authority, args)
    except (RouteAuthorityCliError, RuntimeError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2


def main(argv: list[str] | None = None) -> int:
    """Public entry point: no route authority is created from untrusted argv."""
    return run_with_authority(None, argv)


if __name__ == "__main__":
    raise SystemExit(main())
