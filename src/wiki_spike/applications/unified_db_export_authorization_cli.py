"""Public-only CLI commands for LIVE_EXPORT_ONLY authorization artifacts."""
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
from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    read_bounded_path,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_contracts import Ed25519SignatureEnvelopeV1
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_export_authorization_sign import (
    EXPORT_ONLY_AUTHORIZATION_DOMAIN,
    EXPORT_ONLY_SIGNATURE_VERSION,
    export_only_authorization_signing_bytes,
    parse_export_only_envelopes,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

AUTHORITY_COMMANDS: Final = frozenset(
    {
        "authority-signing-bytes",
        "authority-inspect",
        "authority-envelope",
        "authority-assemble",
        "authority-verify",
    }
)


def is_authority_command(command: str) -> bool:
    return command in AUTHORITY_COMMANDS


def _load_body(path: Path) -> dict[str, JsonValue]:
    parsed = decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))
    _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(parsed)
    return parsed


def _load_envelope(path: Path) -> Mapping[str, JsonValue]:
    return decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))


def _ordered_envelopes(paths: Sequence[str]) -> tuple[Ed25519SignatureEnvelopeV1, ...]:
    loaded = [
        Ed25519SignatureEnvelopeV1.from_mapping(
            _load_envelope(Path(path)), version=EXPORT_ONLY_SIGNATURE_VERSION
        )
        for path in paths
    ]
    ordered = tuple(sorted(loaded, key=lambda item: 0 if item.role == "approver" else 1))
    return parse_export_only_envelopes(tuple(item.to_mapping() for item in ordered))


def _verify_envelopes(
    body: Mapping[str, JsonValue],
    envelopes: Sequence[Ed25519SignatureEnvelopeV1],
) -> None:
    parsed = parse_export_only_envelopes(tuple(item.to_mapping() for item in envelopes))
    for envelope in parsed:
        if not envelope.verify(EXPORT_ONLY_AUTHORIZATION_DOMAIN, body):
            raise UnifiedDbExportError("export authorization signature does not verify")


def emit_authority_signing_bytes(body_path: Path, out_path: Path) -> int:
    body = _load_body(body_path)
    payload = export_only_authorization_signing_bytes(body)
    publish_exclusive_bytes(out_path, payload)
    report = {
        "domain": EXPORT_ONLY_AUTHORIZATION_DOMAIN.decode("utf-8").rstrip("\x00"),
        "bytes": str(len(payload)),
        "sha256": sha256(payload).hexdigest(),
        "written_to": str(out_path),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def inspect_authority_signing_bytes(signing_bytes_path: Path) -> int:
    payload = read_bounded_path(signing_bytes_path, HARD_CAP)
    if not payload.startswith(EXPORT_ONLY_AUTHORIZATION_DOMAIN):
        raise UnifiedDbExportError("signing bytes do not begin with the export-only domain")
    encoded = payload[len(EXPORT_ONLY_AUTHORIZATION_DOMAIN) :]
    body = decode_json_object(encoded.decode("utf-8"))
    _ = UnifiedDbExportOnlyAuthorizationV1.from_mapping(body)
    if export_only_authorization_signing_bytes(body) != payload:
        raise UnifiedDbExportError("signing bytes are not the canonical export-only encoding")
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
        "signature_version": EXPORT_ONLY_SIGNATURE_VERSION,
        "role": files.role,
        "key_id": files.key_id,
        "public_key_b64": b64encode(public_key).decode("ascii"),
        "signature_b64": b64encode(signature).decode("ascii"),
    }
    _ = Ed25519SignatureEnvelopeV1.from_mapping(
        envelope, version=EXPORT_ONLY_SIGNATURE_VERSION
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
