#!/usr/bin/env python3
"""Offline, fail-closed resolver for the signed Second Brain Stage-0 contract.

The command accepts only canonical JSON documents.  It does not fetch evidence,
read credentials, derive keys, or make a route decision; it binds the supplied
evidence snapshot and trusted public-key bindings to the Core resolution result.

``evidence-manifest`` is a canonical signed envelope.  Its signed body has this
exact shape::

    {
      "evidence_manifest_version": "second-brain-evidence-manifest-v1",
      "observed_at": "YYYY-MM-DDTHH:MM:SSZ",
      "expires_at": "YYYY-MM-DDTHH:MM:SSZ",
      "decision_evidence": [
        {"decision_id": "DB-01", "scope_kind": "global",
         "scope_name": null, "evidence_digest": "<sha256>"}
      ]
    }

The envelope must carry exactly one approver and one owner signature over
``EVIDENCE_SIGNING_DOMAIN + canonical_bytes(signing payload)``.  Both are bound
to the injected, pinned aggregate authority.  Only after that verification is
freshness evaluated against the injected trusted clock:
``observed_at <= now < expires_at``.
The manifest must identify exactly the same decision evidence as the records
directory.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import tempfile
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from dataclasses import dataclass
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_contracts import (  # noqa: E402
    DECISION_IDS,
    FATAL_DECISIONS,
    DecisionRecordV1,
    Ed25519SignatureEnvelopeV1,
    ExpectedScopeManifestV1,
    ResolvedScopeV1,
    SignedSecondBrainContractEnvelopeV1,
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
    _SCOPE_KIND_BY_DECISION,
    resolve_second_brain_contract,
)

EVIDENCE_MANIFEST_VERSION = "second-brain-evidence-manifest-v1"
EVIDENCE_ENVELOPE_VERSION = "second-brain-evidence-manifest-envelope-v1"
EVIDENCE_SIGNATURE_VERSION = "second-brain-evidence-manifest-signature-v1"
EVIDENCE_SIGNING_DOMAIN = b"wiki-spike.second-brain.evidence-manifest.v1\x00"
RESOLUTION_RECEIPT_VERSION = "second-brain-contract-resolution-receipt-v1"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UTC_SECONDS_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")


class ResolverError(Exception):
    """A caller-visible input or output rejection."""


@dataclass(frozen=True)
class TrustedResolverAuthority:
    """Non-CLI deployment authority for a single resolver invocation.

    The resolver intentionally has no file or command-line mechanism for
    establishing this authority.  A deployment embedding the resolver must
    pin the key registry and provide its trusted clock out of band.
    """

    trusted_bindings: TrustedDecisionKeyBindingsV1
    now: datetime

    def __post_init__(self) -> None:
        if self.now.tzinfo is None:
            raise ValueError("trusted resolver time must include a timezone")
        object.__setattr__(self, "now", self.now.astimezone(timezone.utc))

    @property
    def now_text(self) -> str:
        return self.now.strftime("%Y-%m-%dT%H:%M:%SZ")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ResolverError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _regular_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ResolverError(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise ResolverError(f"{label} must be a regular non-symlink file")


def _canonical_absolute_path(raw: str, label: str, *, include_leaf: bool) -> Path:
    """Reject lexical and filesystem aliases before opening a public CLI path."""
    if not os.path.isabs(raw) or raw.startswith("//") or raw != os.path.normpath(raw):
        raise ResolverError(f"{label} must be a canonical absolute path")
    if any(component in {".", ".."} for component in raw.split(os.sep)):
        raise ResolverError(f"{label} must not contain path aliases")
    path = Path(raw)
    parts = path.parts
    current = Path(path.anchor)
    checked = parts[1:] if include_leaf else parts[1:-1]
    for component in checked:
        current /= component
        try:
            info = current.lstat()
        except OSError as exc:
            raise ResolverError(f"cannot stat {label} path component {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise ResolverError(f"{label} must not traverse a symlink: {current}")
    return path


def _load_canonical_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    _regular_file(path, label)
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ResolverError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ResolverError(f"{label} must contain a JSON object")
    try:
        if canonical_bytes(value) != raw:
            raise ResolverError(f"{label} is not canonical JSON")
    except ResolverError:
        raise
    except Exception as exc:
        raise ResolverError(f"{label} cannot be canonicalized: {exc}") from exc
    return value, raw


def _strict(data: Mapping[str, Any], fields: set[str], label: str) -> dict[str, Any]:
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown or missing:
        raise ResolverError(f"{label} fields are wrong; missing={sorted(missing)} unknown={sorted(unknown)}")
    return dict(data)


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ResolverError(f"{label} must be a non-empty string")
    return value


def _digest(value: Any, label: str) -> str:
    value = _text(value, label)
    if _SHA256_RE.fullmatch(value) is None:
        raise ResolverError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _timestamp(value: Any, label: str) -> datetime:
    value = _text(value, label)
    if _UTC_SECONDS_RE.fullmatch(value) is None:
        raise ResolverError(f"{label} must be a canonical RFC3339 UTC timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ResolverError(f"{label} must be a canonical RFC3339 UTC timestamp") from exc


def _identity(value: Mapping[str, Any], label: str, *, allow_global_null: bool) -> tuple[str, str, str | None]:
    data = _strict(value, {"decision_id", "scope_kind", "scope_name"}, label)
    decision_id = _text(data["decision_id"], f"{label}.decision_id")
    scope_kind = _text(data["scope_kind"], f"{label}.scope_kind")
    scope_name = data["scope_name"]
    expected_kind = _SCOPE_KIND_BY_DECISION.get(decision_id, "global")
    if decision_id not in DECISION_IDS or scope_kind != expected_kind:
        raise ResolverError(f"{label} has an invalid decision scope identity")
    if scope_kind == "global":
        if scope_name is not None:
            raise ResolverError(f"{label} global scope_name must be null")
    elif not isinstance(scope_name, str) or not scope_name:
        raise ResolverError(f"{label} scoped scope_name must be a non-empty string")
    if not allow_global_null and scope_name is None:
        raise ResolverError(f"{label} cannot be global")
    return decision_id, scope_kind, scope_name


def _load_records(path: Path) -> tuple[tuple[DecisionRecordV1, ...], str]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ResolverError(f"cannot stat records directory: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ResolverError("--records-dir must be a directory, not a symlink")
    try:
        paths = tuple(sorted(path.iterdir(), key=lambda item: item.name))
    except OSError as exc:
        raise ResolverError(f"cannot list records directory: {exc}") from exc
    if not paths:
        raise ResolverError("records directory is empty")
    records: list[DecisionRecordV1] = []
    input_hashes: list[dict[str, str]] = []
    for item in paths:
        if item.suffix != ".json":
            raise ResolverError(f"records directory contains non-JSON input: {item.name}")
        data, raw = _load_canonical_object(item, f"record {item.name}")
        try:
            records.append(DecisionRecordV1.from_mapping(data))
        except Exception as exc:
            raise ResolverError(f"invalid record {item.name}: {exc}") from exc
        # The Stage-0 Core accepts a broader ISO-8601 range to remain usable by
        # internal callers.  This public receipt wire has a deliberately tighter
        # contract: a textual timestamp must have exactly one UTC representation.
        _timestamp(data["decided_at"], f"record {item.name}.decided_at")
        _timestamp(data["expires_at"], f"record {item.name}.expires_at")
        input_hashes.append({"name": item.name, "sha256": sha256(raw).hexdigest()})
    return tuple(records), sha256(canonical_bytes({"records": input_hashes})).hexdigest()


def _authority(data: Mapping[str, Any], label: str) -> TrustedAuthorityBindingsV1:
    values = _strict(
        data,
        {"approver_key_id", "approver_public_key_b64", "owner_key_id", "owner_public_key_b64"},
        label,
    )
    approver_key_id = _text(values["approver_key_id"], f"{label}.approver_key_id")
    approver_public_key_b64 = _text(values["approver_public_key_b64"], f"{label}.approver_public_key_b64")
    owner_key_id = _text(values["owner_key_id"], f"{label}.owner_key_id")
    owner_public_key_b64 = _text(values["owner_public_key_b64"], f"{label}.owner_public_key_b64")
    if approver_key_id == owner_key_id or approver_public_key_b64 == owner_public_key_b64:
        raise ResolverError(f"{label} owner and approver identities must be distinct")
    return TrustedAuthorityBindingsV1(
        approver_key_id,
        approver_public_key_b64,
        owner_key_id,
        owner_public_key_b64,
    )


def _load_trusted_bindings(
    data: Mapping[str, Any], expected: ExpectedScopeManifestV1
) -> TrustedDecisionKeyBindingsV1:
    values = _strict(
        data,
        {"trusted_bindings_version", "decision_bindings", "aggregate_binding"},
        "trusted bindings",
    )
    if values["trusted_bindings_version"] != "second-brain-trusted-decision-key-bindings-v1":
        raise ResolverError("unsupported trusted_bindings_version")
    entries = values["decision_bindings"]
    if not isinstance(entries, list):
        raise ResolverError("trusted bindings.decision_bindings must be an array")
    bindings: dict[tuple[str, str, str | None], TrustedAuthorityBindingsV1] = {}
    identities: list[tuple[str, str, str]] = []
    fields = {
        "decision_id", "scope_kind", "scope_name", "approver_key_id", "approver_public_key_b64",
        "owner_key_id", "owner_public_key_b64",
    }
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            raise ResolverError("trusted bindings.decision_bindings entries must be objects")
        item = _strict(entry, fields, f"trusted bindings.decision_bindings[{index}]")
        identity = _identity(
            {key: item[key] for key in ("decision_id", "scope_kind", "scope_name")},
            f"trusted bindings.decision_bindings[{index}]",
            allow_global_null=True,
        )
        if identity in bindings:
            raise ResolverError("trusted bindings contains a duplicate decision identity")
        identities.append((identity[0], identity[1], identity[2] or ""))
        bindings[identity] = _authority(
            {key: item[key] for key in fields - {"decision_id", "scope_kind", "scope_name"}},
            f"trusted bindings.decision_bindings[{index}]",
        )
    if tuple(sorted(identities)) != tuple(identities):
        raise ResolverError("trusted bindings.decision_bindings must be sorted")
    required = {(decision_id, "global", None) for decision_id in FATAL_DECISIONS}
    required.update(expected.expected_scopes)
    if set(bindings) != required:
        raise ResolverError("trusted bindings must exactly cover the expected decision identities")
    aggregate = values["aggregate_binding"]
    if not isinstance(aggregate, Mapping):
        raise ResolverError("trusted bindings.aggregate_binding must be an object")
    return TrustedDecisionKeyBindingsV1(bindings, _authority(aggregate, "trusted bindings.aggregate_binding"))


def _load_evidence_manifest(
    data: Mapping[str, Any], decisions: Sequence[DecisionRecordV1],
    trusted: TrustedDecisionKeyBindingsV1, now: datetime,
) -> dict[str, Any]:
    envelope = _strict(
        data,
        {
            "evidence_envelope_version", "evidence_manifest_digest", "evidence_body",
            "signatures",
        },
        "evidence manifest envelope",
    )
    if envelope["evidence_envelope_version"] != EVIDENCE_ENVELOPE_VERSION:
        raise ResolverError("unsupported evidence_envelope_version")
    if not isinstance(envelope["evidence_body"], Mapping):
        raise ResolverError("evidence manifest envelope.evidence_body must be an object")
    manifest_digest = _digest(
        envelope["evidence_manifest_digest"], "evidence manifest envelope.evidence_manifest_digest"
    )
    body = dict(envelope["evidence_body"])
    if sha256(canonical_bytes(body)).hexdigest() != manifest_digest:
        raise ResolverError("evidence manifest digest does not match its body")
    signatures = envelope["signatures"]
    if not isinstance(signatures, list) or len(signatures) != 2:
        raise ResolverError("evidence manifest requires exactly approver and owner signatures")
    try:
        parsed_signatures = tuple(
            Ed25519SignatureEnvelopeV1.from_mapping(item, version=EVIDENCE_SIGNATURE_VERSION)
            for item in signatures
            if isinstance(item, Mapping)
        )
    except Exception as exc:
        raise ResolverError(f"invalid evidence manifest signature: {exc}") from exc
    if len(parsed_signatures) != 2 or tuple(item.role for item in parsed_signatures) != ("approver", "owner"):
        raise ResolverError("evidence manifest signatures must be canonically ordered approver then owner")
    if (
        parsed_signatures[0].key_id == parsed_signatures[1].key_id
        or parsed_signatures[0].public_key_b64 == parsed_signatures[1].public_key_b64
    ):
        raise ResolverError("evidence manifest owner and approver must have distinct identities")
    signing_payload = {
        "evidence_envelope_version": EVIDENCE_ENVELOPE_VERSION,
        "evidence_manifest_digest": manifest_digest,
        "evidence_body": body,
    }
    if not all(
        trusted.matches_aggregate(signature)
        and signature.verify(EVIDENCE_SIGNING_DOMAIN, signing_payload)
        for signature in parsed_signatures
    ):
        raise ResolverError("evidence manifest has an untrusted or invalid signature")
    values = _strict(
        body,
        {"evidence_manifest_version", "observed_at", "expires_at", "decision_evidence"},
        "evidence manifest",
    )
    if values["evidence_manifest_version"] != EVIDENCE_MANIFEST_VERSION:
        raise ResolverError("unsupported evidence_manifest_version")
    observed_at = _timestamp(values["observed_at"], "evidence manifest.observed_at")
    expires_at = _timestamp(values["expires_at"], "evidence manifest.expires_at")
    if expires_at <= observed_at:
        raise ResolverError("evidence manifest expires_at must be after observed_at")
    evidence = values["decision_evidence"]
    if not isinstance(evidence, list):
        raise ResolverError("evidence manifest.decision_evidence must be an array")
    entries: dict[tuple[str, str, str | None], str] = {}
    ordering: list[tuple[str, str, str]] = []
    for index, entry in enumerate(evidence):
        if not isinstance(entry, Mapping):
            raise ResolverError("evidence manifest.decision_evidence entries must be objects")
        item = _strict(
            entry,
            {"decision_id", "scope_kind", "scope_name", "evidence_digest"},
            f"evidence manifest.decision_evidence[{index}]",
        )
        identity = _identity(
            {key: item[key] for key in ("decision_id", "scope_kind", "scope_name")},
            f"evidence manifest.decision_evidence[{index}]",
            allow_global_null=True,
        )
        if identity in entries:
            raise ResolverError("evidence manifest contains a duplicate decision identity")
        ordering.append((identity[0], identity[1], identity[2] or ""))
        entries[identity] = _digest(item["evidence_digest"], "evidence manifest evidence_digest")
    if tuple(sorted(ordering)) != tuple(ordering):
        raise ResolverError("evidence manifest.decision_evidence must be sorted")
    record_evidence = {
        (record.decision_id, record.scope_kind, record.scope_name): record.evidence_digest
        for record in decisions
    }
    if entries != record_evidence or len(entries) != len(decisions):
        raise ResolverError("evidence manifest must exactly bind the supplied decision evidence")
    if now < observed_at:
        raise ResolverError("evidence manifest is from the future")
    if now >= expires_at:
        raise ResolverError("evidence manifest is stale")
    return {
        "state": "FRESH",
        "signed_manifest_digest": manifest_digest,
        "observed_at": values["observed_at"],
        "expires_at": values["expires_at"],
        "evaluated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def _write_new_receipt(path: Path, receipt: Mapping[str, Any]) -> None:
    """Durably publish a receipt without overwriting an existing destination."""
    payload = canonical_bytes(receipt)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ResolverError(f"cannot stat receipt output: {exc}") from exc
    else:
        raise ResolverError("receipt output already exists; refuse collision or tampering")
    temporary: str | None = None
    published_identity: tuple[int, int] | None = None
    directory: int | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        temporary_info = os.stat(temporary, follow_symlinks=False)
        os.link(temporary, path)
        published_identity = (temporary_info.st_dev, temporary_info.st_ino)
        directory = os.open(path.parent, os.O_RDONLY)
        os.fsync(directory)
    except FileExistsError as exc:
        raise ResolverError("receipt output already exists; refuse collision or tampering") from exc
    except OSError as exc:
        # A link can succeed before the directory fsync fails.  Never return a
        # failure while leaving a receipt that this invocation published.  The
        # identity check prevents cleanup of a colliding replacement.
        if published_identity is not None:
            try:
                current = path.lstat()
                if (current.st_dev, current.st_ino) == published_identity:
                    os.unlink(path)
                    if directory is None:
                        directory = os.open(path.parent, os.O_RDONLY)
                    os.fsync(directory)
            except FileNotFoundError:
                pass
            except OSError as cleanup_exc:
                raise ResolverError(
                    f"cannot clean up unpublished receipt: {cleanup_exc}"
                ) from exc
        raise ResolverError(f"cannot atomically publish receipt: {exc}") from exc
    finally:
        if directory is not None:
            os.close(directory)
        if temporary is not None:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass


def cmd_resolve(
    args: argparse.Namespace, *, trusted_authority: TrustedResolverAuthority | None = None,
) -> int:
    # This guard must precede *all* input path validation and reads.  The
    # argparse surface remains stable for callers, but argv cannot establish a
    # key registry or a clock trust root.
    if trusted_authority is None:
        raise ResolverError("resolver requires injected trusted authority and clock")
    supplied_now = _timestamp(args.now, "--now")
    if supplied_now != trusted_authority.now:
        raise ResolverError("--now does not match the injected trusted clock")
    now = trusted_authority.now
    records_path = _canonical_absolute_path(args.records_dir, "--records-dir", include_leaf=True)
    scope_path = _canonical_absolute_path(args.resolved_scope, "--resolved-scope", include_leaf=True)
    expected_path = _canonical_absolute_path(args.expected_scopes, "--expected-scopes", include_leaf=True)
    aggregate_path = _canonical_absolute_path(args.aggregate, "--aggregate", include_leaf=True)
    bindings_path = _canonical_absolute_path(args.trusted_bindings, "--trusted-bindings", include_leaf=True)
    evidence_path = _canonical_absolute_path(args.evidence_manifest, "--evidence-manifest", include_leaf=True)
    output_path = _canonical_absolute_path(args.out, "--out", include_leaf=False)
    decisions, records_dir_digest = _load_records(records_path)
    scope_data, scope_raw = _load_canonical_object(scope_path, "resolved scope")
    expected_data, expected_raw = _load_canonical_object(expected_path, "expected scopes")
    aggregate_data, aggregate_raw = _load_canonical_object(aggregate_path, "aggregate")
    bindings_data, bindings_raw = _load_canonical_object(bindings_path, "trusted bindings")
    evidence_data, evidence_raw = _load_canonical_object(evidence_path, "evidence manifest")
    try:
        scope = ResolvedScopeV1.from_mapping(scope_data)
        expected = ExpectedScopeManifestV1.from_mapping(expected_data)
        aggregate = SignedSecondBrainContractEnvelopeV1.from_mapping(aggregate_data)
    except Exception as exc:
        raise ResolverError(f"invalid canonical resolver input: {exc}") from exc
    supplied_bindings = _load_trusted_bindings(bindings_data, expected)
    if supplied_bindings != trusted_authority.trusted_bindings:
        raise ResolverError("trusted bindings do not match the injected pinned registry")
    trusted = trusted_authority.trusted_bindings
    evidence_freshness = _load_evidence_manifest(evidence_data, decisions, trusted, now)
    try:
        resolution = resolve_second_brain_contract(
            decisions,
            scope,
            expected,
            aggregate,
            trusted_keys=trusted,
            now=now,
        )
    except Exception as exc:
        raise ResolverError(f"Core resolution rejected input: {exc}") from exc
    contract_digest = resolution.contract.digest if resolution.contract is not None else None
    blocked = [
        {
            "decision_id": item.decision_id,
            "scope_kind": item.scope_kind,
            "scope_name": item.scope_name,
            "decision_digest": item.digest,
        }
        for item in resolution.blocked_decisions
    ]
    receipt = {
        "resolution_receipt_version": RESOLUTION_RECEIPT_VERSION,
        "resolver_outcome": resolution.outcome,
        "stage0_contract_usable": resolution.outcome == "RESOLVED",
        "live_operation_authorized": False,
        "next_governance_gate": "GOV-03" if resolution.outcome == "RESOLVED" else None,
        "resolved_at": trusted_authority.now_text,
        "input_sha256": {
            "records_dir": records_dir_digest,
            "resolved_scope": sha256(scope_raw).hexdigest(),
            "expected_scopes": sha256(expected_raw).hexdigest(),
            "aggregate": sha256(aggregate_raw).hexdigest(),
            "trusted_bindings": sha256(bindings_raw).hexdigest(),
            "evidence_manifest": sha256(evidence_raw).hexdigest(),
        },
        "evidence_freshness": evidence_freshness,
        "contract_digest": contract_digest,
        "blocked_decisions": blocked,
    }
    _write_new_receipt(output_path, receipt)
    print(json.dumps({"out": args.out, "resolver_outcome": resolution.outcome}, sort_keys=True))
    return 0


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ResolverError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("--records-dir", required=True)
    resolve.add_argument("--resolved-scope", required=True)
    resolve.add_argument("--expected-scopes", required=True)
    resolve.add_argument("--aggregate", required=True)
    resolve.add_argument("--trusted-bindings", required=True)
    resolve.add_argument("--evidence-manifest", required=True)
    resolve.add_argument("--now", required=True)
    resolve.add_argument("--out", required=True)
    resolve.set_defaults(func=cmd_resolve)
    return parser


def main(
    argv: list[str] | None = None, *, trusted_authority: TrustedResolverAuthority | None = None,
) -> int:
    try:
        args = build_parser().parse_args(argv)
        return int(args.func(args, trusted_authority=trusted_authority))
    except ResolverError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("FAIL: RESOLVER_INTERNAL_REJECTED", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
