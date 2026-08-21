#!/usr/bin/env python3
"""Build the precise fail-closed owner-evidence wall."""

from __future__ import annotations

import argparse
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import Final

from wiki_spike.memory_core.contracts import JsonValue, canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNATURE_VERSION,
    DECISION_SIGNING_DOMAIN,
    FATAL_DECISIONS,
    DecisionRecordV1,
    Ed25519SignatureEnvelopeV1,
    ExpectedScopeManifestV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import (
    decode_json_object,
)

RELEASE: Final = Path("artifacts/product-release/second-brain-v1")
EXPECTED_MISSING: Final = (("DB-05", "global", None),)
DB05_REASON: Final = (
    "Benchmark and holdout corpus evidence is absent. Owner-reviewed labels, "
    "consent, and separate benchmark and holdout digests are required before "
    "an evidence-backed GO or NO_GO record can be signed."
)

type Identity = tuple[str, str, str | None]
type JsonObject = dict[str, JsonValue]


class AuthorityWallError(Exception):
    """The authority wall could not be proven."""


def _load_json(path: Path) -> JsonObject:
    try:
        return decode_json_object(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise AuthorityWallError(f"{path} cannot be read safely") from exc


def _identity(value: JsonObject) -> Identity:
    decision_id = value.get("decision_id")
    scope_kind = value.get("scope_kind")
    scope_name = value.get("scope_name")
    if not isinstance(decision_id, str) or not isinstance(scope_kind, str):
        raise AuthorityWallError("decision identity is incomplete")
    if scope_name is not None and not isinstance(scope_name, str):
        raise AuthorityWallError("decision scope_name is invalid")
    return decision_id, scope_kind, scope_name


def _expected(release: Path) -> set[Identity]:
    manifest = ExpectedScopeManifestV1.from_mapping(
        _load_json(release / "governance/expected-scopes.json")
    )
    identities: set[Identity] = {
        (decision_id, "global", None) for decision_id in FATAL_DECISIONS
    }
    identities.update(manifest.expected_scopes)
    return identities


def _actual(release: Path) -> set[Identity]:
    return {
        (record.decision_id, record.scope_kind, record.scope_name)
        for record in (
            DecisionRecordV1.from_mapping(_load_json(path))
            for path in sorted((release / "decisions").glob("*.json"))
        )
    }


def _trusted_bindings(release: Path) -> dict[Identity, JsonObject]:
    document = _load_json(release / "governance/trusted-bindings.json")
    entries = document.get("decision_bindings")
    if not isinstance(entries, list):
        raise AuthorityWallError("trusted decision bindings are missing")
    bindings: dict[Identity, JsonObject] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise AuthorityWallError("trusted decision binding is invalid")
        bindings[_identity(entry)] = entry
    return bindings


def _unresolved_bodies(release: Path) -> dict[Identity, tuple[str, JsonObject, bytes]]:
    bodies: dict[Identity, tuple[str, JsonObject, bytes]] = {}
    for path in sorted((release / "decision-signing").glob("*.body.json")):
        body = _load_json(path)
        if body.get("outcome") != "UNRESOLVED":
            continue
        raw = path.read_bytes()
        bodies[_identity(body)] = (path.name.removesuffix(".body.json"), body, raw)
    return bodies


def _verified_signature(
    release: Path,
    stem: str,
    role: str,
    body: JsonObject,
    binding: JsonObject,
) -> str:
    path = release / "authority-wall-signatures" / f"{stem}.{role}-envelope.json"
    raw = path.read_bytes()
    signature = Ed25519SignatureEnvelopeV1.from_mapping(
        _load_json(path),
        version=DECISION_SIGNATURE_VERSION,
    )
    expected_id = binding.get(f"{role}_key_id")
    expected_public = binding.get(f"{role}_public_key_b64")
    if (
        signature.role != role
        or signature.key_id != expected_id
        or signature.public_key_b64 != expected_public
        or not signature.verify(DECISION_SIGNING_DOMAIN, body)
    ):
        raise AuthorityWallError(f"{stem} {role} envelope is invalid or untrusted")
    return sha256(raw).hexdigest()


def _unresolved_item(
    release: Path,
    identity: Identity,
    body_entry: tuple[str, JsonObject, bytes],
    binding: JsonObject,
) -> JsonObject:
    stem, body, raw = body_entry
    reason = body.get("reason")
    evidence_refs = body.get("evidence_refs")
    evidence_digest = body.get("evidence_digest")
    if (
        not isinstance(reason, str)
        or not isinstance(evidence_refs, list)
        or not isinstance(evidence_digest, str)
    ):
        raise AuthorityWallError(f"{stem} unresolved body is incomplete")
    return {
        "approver_envelope_sha256": _verified_signature(
            release, stem, "approver", body, binding
        ),
        "decision_id": identity[0],
        "evidence_digest": evidence_digest,
        "evidence_refs": evidence_refs,
        "owner_envelope_sha256": _verified_signature(
            release, stem, "owner", body, binding
        ),
        "reason": reason,
        "scope_kind": identity[1],
        "scope_name": identity[2],
        "state": "SIGNED_UNRESOLVED",
        "unsigned_body_sha256": sha256(raw).hexdigest(),
    }


def build(root: Path) -> JsonObject:
    release = root / RELEASE
    expected = _expected(release)
    actual = _actual(release)
    missing = tuple(
        sorted(expected - actual, key=lambda item: (item[0], item[1], item[2] or ""))
    )
    if missing != EXPECTED_MISSING:
        raise AuthorityWallError(f"unexpected missing decision identities: {missing}")
    bodies = _unresolved_bodies(release)
    bindings = _trusted_bindings(release)
    items: list[JsonValue] = []
    for identity in missing:
        body = bodies.get(identity)
        binding = bindings.get(identity)
        if body is not None and binding is not None:
            items.append(_unresolved_item(release, identity, body, binding))
            continue
        if identity != ("DB-05", "global", None):
            raise AuthorityWallError(f"missing unresolved evidence binding: {identity}")
        items.append(
            {
                "decision_id": "DB-05",
                "evidence_digest": None,
                "evidence_refs": [],
                "reason": DB05_REASON,
                "scope_kind": "global",
                "scope_name": None,
                "state": "OWNER_EVIDENCE_REQUIRED",
            }
        )
    resolver = release / "resolver"
    return {
        "authority_wall_version": "second-brain-authority-wall-v1",
        "complete_signed_decision_records": str(len(actual)),
        "expected_decision_records": str(len(expected)),
        "live_operation_authorized": False,
        "missing_decisions": items,
        "outcome": "FAIL_CLOSED_OWNER_EVIDENCE_REQUIRED",
        "resolver_error": (
            "Core resolution rejected input: decision evidence does not exactly "
            "match the expected-scope manifest"
        ),
        "resolver_input_sha256": {
            name: sha256((resolver / name).read_bytes()).hexdigest()
            for name in (
                "aggregate-envelope.json",
                "evidence-manifest-envelope.json",
                "resolved-scope.json",
            )
        },
        "signing_boundary": "/Users/jmpark/sign-pending",
    }


class _Parsed(argparse.Namespace):
    root: Path = Path()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("--root", type=Path, default=Path("."))
    parsed = _Parsed()
    _ = parser.parse_args(argv, namespace=parsed)
    try:
        root = parsed.root.resolve()
        output = root / RELEASE / "resolver/authority-wall.json"
        if output.exists():
            _ = os.chmod(output, 0o644)
        _ = output.write_bytes(canonical_bytes(build(root)))
        _ = os.chmod(output, 0o444)
    except (AuthorityWallError, OSError, ValueError) as exc:
        print(f"authority wall build refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
