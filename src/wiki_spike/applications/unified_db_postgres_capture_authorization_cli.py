"""Public-only CLI for POSTGRES_METADATA_CAPTURE_ONLY artifacts."""
from __future__ import annotations

import json
from base64 import b64encode
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final

from wiki_spike.applications.unified_db_export_authorization_publish import (
    publish_exclusive_bytes,
)
from wiki_spike.applications.unified_db_postgres_capture_cli import SubparserRegistrar
from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    read_bounded_path,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_sign import (
    METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN,
    METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
    metadata_capture_authorization_signing_bytes,
    parse_metadata_capture_envelopes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

AUTHORITY_COMMANDS: Final = frozenset(
    {
        "capture-authority-signing-bytes",
        "capture-authority-inspect",
        "capture-authority-envelope",
        "capture-authority-assemble",
        "capture-authority-verify",
    }
)


def is_capture_authority_command(command: str) -> bool:
    return command in AUTHORITY_COMMANDS


def register_capture_authority_parsers(sub: SubparserRegistrar) -> None:
    signing = sub.add_parser(
        "capture-authority-signing-bytes", help="emit metadata-capture signing bytes"
    )
    _ = signing.add_argument("--body", required=True, type=Path)
    _ = signing.add_argument("--out", required=True, type=Path)
    inspect = sub.add_parser(
        "capture-authority-inspect", help="decode metadata-capture signing bytes"
    )
    _ = inspect.add_argument("--signing-bytes", required=True, type=Path)
    envelope = sub.add_parser(
        "capture-authority-envelope", help="wrap a public metadata-capture envelope"
    )
    _ = envelope.add_argument("--role", required=True, choices=("owner", "approver"))
    _ = envelope.add_argument("--key-id", required=True)
    _ = envelope.add_argument("--public-key", required=True, type=Path)
    _ = envelope.add_argument("--signature", required=True, type=Path)
    assemble = sub.add_parser(
        "capture-authority-assemble", help="bind public metadata-capture envelopes"
    )
    _ = assemble.add_argument("--body", required=True, type=Path)
    _ = assemble.add_argument("--signature", action="append", required=True)
    _ = assemble.add_argument("--out", required=True, type=Path)
    verify = sub.add_parser(
        "capture-authority-verify", help="verify public metadata-capture envelopes"
    )
    _ = verify.add_argument("--body", required=True, type=Path)
    _ = verify.add_argument("--signature", action="append", required=True)


@dataclass(frozen=True, slots=True)
class CaptureAuthorityCliPaths:
    body: Path
    out: Path
    signing_bytes: Path
    role: str
    key_id: str
    public_key: Path
    signature: Path | list[str] | None


def _signature_paths(value: Path | list[str] | None) -> tuple[str, ...]:
    if isinstance(value, list) and value:
        return tuple(value)
    if isinstance(value, Path):
        return (str(value),)
    raise UnifiedDbExportError("signature is required")


def run_capture_authority_command(command: str, paths: CaptureAuthorityCliPaths) -> int:
    match command:
        case "capture-authority-signing-bytes":
            return emit_authority_signing_bytes(paths.body, paths.out)
        case "capture-authority-inspect":
            return inspect_authority_signing_bytes(paths.signing_bytes)
        case "capture-authority-envelope":
            signature = paths.signature
            if not isinstance(signature, Path):
                raise UnifiedDbExportError("signature must be a public file")
            return wrap_authority_envelope(
                PublicEnvelopeFiles(paths.role, paths.key_id, paths.public_key, signature)
            )
        case "capture-authority-assemble":
            return assemble_authority_envelopes(
                paths.body, _signature_paths(paths.signature), paths.out
            )
        case "capture-authority-verify":
            return verify_authority_envelopes(
                paths.body, _signature_paths(paths.signature)
            )
        case _ as unreachable:
            raise UnifiedDbExportError(f"unknown capture authority command: {unreachable}")


def _load_body(path: Path) -> dict[str, JsonValue]:
    parsed = decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))
    _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(parsed)
    return parsed


def _load_envelope(path: Path) -> Mapping[str, JsonValue]:
    return decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))


def _ordered_envelopes(paths: Sequence[str]) -> tuple[Ed25519SignatureEnvelopeV1, ...]:
    loaded = [
        Ed25519SignatureEnvelopeV1.from_mapping(
            _load_envelope(Path(path)), version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION
        )
        for path in paths
    ]
    ordered = tuple(sorted(loaded, key=lambda item: 0 if item.role == "approver" else 1))
    return parse_metadata_capture_envelopes(tuple(item.to_mapping() for item in ordered))


def _verify_envelopes(
    body: Mapping[str, JsonValue],
    envelopes: Sequence[Ed25519SignatureEnvelopeV1],
) -> None:
    parsed = parse_metadata_capture_envelopes(tuple(item.to_mapping() for item in envelopes))
    for envelope in parsed:
        if not envelope.verify(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN, body):
            raise UnifiedDbExportError("metadata capture signature does not verify")


def emit_authority_signing_bytes(body_path: Path, out_path: Path) -> int:
    body = _load_body(body_path)
    payload = metadata_capture_authorization_signing_bytes(body)
    publish_exclusive_bytes(out_path, payload)
    report = {
        "domain": METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN.decode("utf-8").rstrip("\x00"),
        "bytes": str(len(payload)),
        "sha256": sha256(payload).hexdigest(),
        "written_to": str(out_path),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def inspect_authority_signing_bytes(signing_bytes_path: Path) -> int:
    payload = read_bounded_path(signing_bytes_path, HARD_CAP)
    if not payload.startswith(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN):
        raise UnifiedDbExportError("signing bytes do not begin with the metadata-capture domain")
    encoded = payload[len(METADATA_CAPTURE_ONLY_AUTHORIZATION_DOMAIN) :]
    body = decode_json_object(encoded.decode("utf-8"))
    _ = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(body)
    if metadata_capture_authorization_signing_bytes(body) != payload:
        raise UnifiedDbExportError("signing bytes are not the canonical metadata-capture encoding")
    print(json.dumps(body, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


@dataclass(frozen=True, slots=True)
class PublicEnvelopeFiles:
    role: str
    key_id: str
    public_key_path: Path
    signature_path: Path


def wrap_authority_envelope(files: PublicEnvelopeFiles) -> int:
    signature = read_bounded_path(files.signature_path, HARD_CAP)
    public_key = read_bounded_path(files.public_key_path, HARD_CAP)
    if len(signature) != 64:
        raise UnifiedDbExportError("Ed25519 signature must be 64 bytes")
    if len(public_key) != 32:
        raise UnifiedDbExportError("Ed25519 public key must be 32 raw bytes")
    envelope = {
        "signature_version": METADATA_CAPTURE_ONLY_SIGNATURE_VERSION,
        "role": files.role,
        "key_id": files.key_id,
        "public_key_b64": b64encode(public_key).decode("ascii"),
        "signature_b64": b64encode(signature).decode("ascii"),
    }
    _ = Ed25519SignatureEnvelopeV1.from_mapping(
        envelope, version=METADATA_CAPTURE_ONLY_SIGNATURE_VERSION
    )
    print(json.dumps(envelope, indent=2, sort_keys=True))
    return 0


def assemble_authority_envelopes(
    body_path: Path, signature_paths: tuple[str, ...], out_path: Path
) -> int:
    body = _load_body(body_path)
    envelopes = _ordered_envelopes(signature_paths)
    _verify_envelopes(body, envelopes)
    record = {**body, "signatures": [item.to_mapping() for item in envelopes]}
    publish_exclusive_bytes(
        out_path,
        (json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
    )
    return 0


def verify_authority_envelopes(body_path: Path, signature_paths: tuple[str, ...]) -> int:
    body = _load_body(body_path)
    envelopes = _ordered_envelopes(signature_paths)
    _verify_envelopes(body, envelopes)
    print(json.dumps({"signatures_verified": True}, indent=2, sort_keys=True))
    return 0
