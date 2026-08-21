#!/usr/bin/env python3
"""Prepare and assemble canonical resolver inputs without reading private keys."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Literal

from wiki_spike.applications.resolver_input_material import (
    EVIDENCE_SIGNATURE_VERSION,
    EVIDENCE_SIGNING_DOMAIN,
    RELEASE,
    BuilderError,
    JsonObject,
    load_json,
    prepare,
    write_canonical,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_ENVELOPE_VERSION,
    CONTRACT_SIGNATURE_VERSION,
    CONTRACT_SIGNING_DOMAIN,
    Ed25519SignatureEnvelopeV1,
    TrustedAuthorityBindingsV1,
)

type Command = Literal["assemble", "prepare"]


def _authority(root: Path) -> TrustedAuthorityBindingsV1:
    bindings = load_json(root / RELEASE / "governance/trusted-bindings.json")
    raw = bindings.get("aggregate_binding")
    if not isinstance(raw, dict):
        raise BuilderError("aggregate_binding must be an object")
    try:
        return TrustedAuthorityBindingsV1(
            approver_key_id=str(raw["approver_key_id"]),
            approver_public_key_b64=str(raw["approver_public_key_b64"]),
            owner_key_id=str(raw["owner_key_id"]),
            owner_public_key_b64=str(raw["owner_public_key_b64"]),
        )
    except KeyError as exc:
        raise BuilderError("aggregate_binding is incomplete") from exc


def _signature(
    directory: Path,
    stem: str,
    role: str,
    version: str,
    authority: TrustedAuthorityBindingsV1,
    domain: bytes,
    payload: JsonObject,
) -> JsonObject:
    path = directory / f"{stem}.{role}-envelope.json"
    signature = Ed25519SignatureEnvelopeV1.from_mapping(
        load_json(path),
        version=version,
    )
    if (
        signature.role != role
        or not authority.matches(signature)
        or not signature.verify(domain, payload)
    ):
        raise BuilderError(f"{stem} {role} signature is invalid or untrusted")
    result: JsonObject = {}
    result.update(signature.to_mapping())
    return result


def assemble(root: Path, owner_dir: Path, approver_dir: Path) -> None:
    prepare(root)
    release = root / RELEASE
    signing = release / "resolver-signing"
    aggregate = load_json(signing / "aggregate.payload.json")
    evidence = load_json(signing / "evidence-manifest.payload.json")
    authority = _authority(root)
    aggregate_signatures: list[JsonValue] = [
        _signature(
            approver_dir,
            "aggregate",
            "approver",
            CONTRACT_SIGNATURE_VERSION,
            authority,
            CONTRACT_SIGNING_DOMAIN,
            aggregate,
        ),
        _signature(
            owner_dir,
            "aggregate",
            "owner",
            CONTRACT_SIGNATURE_VERSION,
            authority,
            CONTRACT_SIGNING_DOMAIN,
            aggregate,
        ),
    ]
    evidence_signatures: list[JsonValue] = [
        _signature(
            approver_dir,
            "evidence-manifest",
            "approver",
            EVIDENCE_SIGNATURE_VERSION,
            authority,
            EVIDENCE_SIGNING_DOMAIN,
            evidence,
        ),
        _signature(
            owner_dir,
            "evidence-manifest",
            "owner",
            EVIDENCE_SIGNATURE_VERSION,
            authority,
            EVIDENCE_SIGNING_DOMAIN,
            evidence,
        ),
    ]
    write_canonical(
        release / "resolver/aggregate-envelope.json",
        {
            "contract_envelope_version": CONTRACT_ENVELOPE_VERSION,
            **aggregate,
            "signatures": aggregate_signatures,
        },
    )
    write_canonical(
        release / "resolver/evidence-manifest-envelope.json",
        {**evidence, "signatures": evidence_signatures},
    )


class _Parsed(argparse.Namespace):
    command: Command = "prepare"
    root: Path = Path()
    owner_envelope_dir: Path = Path()
    approver_envelope_dir: Path = Path()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare")
    _ = prepare_parser.add_argument("--root", type=Path, default=Path("."))
    assemble_parser = commands.add_parser("assemble")
    _ = assemble_parser.add_argument("--root", type=Path, default=Path("."))
    _ = assemble_parser.add_argument(
        "--owner-envelope-dir", required=True, type=Path
    )
    _ = assemble_parser.add_argument(
        "--approver-envelope-dir", required=True, type=Path
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        parsed = _Parsed()
        _ = _parser().parse_args(argv, namespace=parsed)
        root = parsed.root.resolve()
        if parsed.command == "prepare":
            prepare(root)
            return 0
        assemble(
            root,
            parsed.owner_envelope_dir.resolve(),
            parsed.approver_envelope_dir.resolve(),
        )
    except (BuilderError, OSError, ValueError) as exc:
        print(f"resolver input build refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
