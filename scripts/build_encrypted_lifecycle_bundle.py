#!/usr/bin/env python3
"""Build an exact immutable encrypted-lifecycle evidence bundle."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import stat
import tarfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ENVELOPE_SCHEMA = "wiki-artifact-bundle-envelope-v1"
MANIFEST_SCHEMA = "wiki-artifact-bundle-manifest-v1"
ENVELOPE_ENTRY_PATH = "artifact-envelope.json"
MANIFEST_ENTRY_PATH = "bundle-manifest.json"
KIND_PAYLOADS = {
    "SQLCIPHER_FEASIBILITY": ("payload/sqlcipher-feasibility.json",),
    "GATE1_DECISION": ("payload/gate1-decision.json", "payload/macos/sqlcipher-feasibility.json", "payload/ubuntu/import-receipt.json", "payload/vector-validation.json"),
    "CONFORMANCE_PRE_CANARY": ("payload/conformance-pre-canary.json",),
    "CANARY_24H": ("payload/rollout-evidence.json",),
}
PLATFORMS = frozenset(("github-hosted/ubuntu-24.04/x86_64", "self-hosted/macos-26/arm64/wiki-gate1-workstation", "self-hosted/macos-26/arm64/wiki-conformance-workstation", "self-hosted/macos-26/arm64/wiki-canary-workstation"))
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DECIMAL = re.compile(r"^(0|[1-9][0-9]*)$")
TIMESTAMP = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    def normalize(v: Any, path: str) -> Any:
        if v is None or isinstance(v, bool): return v
        if isinstance(v, str): return unicodedata.normalize("NFC", v)
        if isinstance(v, (int, float)): raise ValueError(f"raw numeric token forbidden at {path}")
        if isinstance(v, list): return [normalize(x, f"{path}[{i}]") for i, x in enumerate(v)]
        if isinstance(v, Mapping):
            out: dict[str, Any] = {}
            for key, item in v.items():
                if not isinstance(key, str): raise ValueError(f"non-string key at {path}")
                key = unicodedata.normalize("NFC", key)
                if key in out: raise ValueError(f"duplicate NFC key at {path}")
                out[key] = normalize(item, f"{path}.{key}")
            return {key: out[key] for key in sorted(out)}
        raise ValueError(f"unsupported value at {path}")
    return json.dumps(normalize(value, "$"), ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha256_hex(data: bytes) -> str: return hashlib.sha256(data).hexdigest()


def validate_path(path: str) -> None:
    if not isinstance(path, str) or not path or len(path.encode()) > 240 or path != unicodedata.normalize("NFC", path): raise ValueError("payload path must be NFC UTF-8")
    if "\\" in path or path.startswith("/") or "//" in path or any(ord(c) < 32 or ord(c) == 127 for c in path): raise ValueError("invalid payload path")
    if any(part in ("", ".", "..") for part in path.split("/")): raise ValueError("invalid payload path")


def validate_inputs(**values: str) -> None:
    if not SHA40.fullmatch(values["producer_commit"]): raise ValueError("producer_commit must be 40 lowercase hex characters")
    for field in ("contract_digest", "toolchain_lock_digest", "workflow_file_digest"):
        if not HEX64.fullmatch(values[field]): raise ValueError(f"{field} must be 64 lowercase hex characters")
    for field in ("workflow_run_id", "workflow_run_attempt"):
        if not DECIMAL.fullmatch(values[field]): raise ValueError(f"{field} must be a canonical decimal string")
    if not REPOSITORY.fullmatch(values["repository"]) or values["repository"] != unicodedata.normalize("NFC", values["repository"]): raise ValueError("repository must be canonical owner/repository")
    if values["platform_token"] not in PLATFORMS: raise ValueError("platform is not a closed token")
    if not TIMESTAMP.fullmatch(values["produced_at"]): raise ValueError("produced_at must be UTC second timestamp")


def build_bundle(*, input_dir: Path, payload_names: list[str], artifact_kind: str, repository: str, producer_commit: str, contract_digest: str, toolchain_lock_digest: str, workflow_file_digest: str, workflow_run_id: str, workflow_run_attempt: str, platform_token: str, produced_at: str) -> dict[str, Any]:
    if artifact_kind not in KIND_PAYLOADS: raise ValueError("unknown artifact kind")
    validate_inputs(repository=repository, producer_commit=producer_commit, contract_digest=contract_digest, toolchain_lock_digest=toolchain_lock_digest, workflow_file_digest=workflow_file_digest, workflow_run_id=workflow_run_id, workflow_run_attempt=workflow_run_attempt, platform_token=platform_token, produced_at=produced_at)
    for path in payload_names: validate_path(path)
    expected_paths = KIND_PAYLOADS[artifact_kind]
    if tuple(sorted(payload_names, key=lambda p: p.encode())) != expected_paths or len(set(payload_names)) != len(payload_names): raise ValueError(f"payload paths must exactly equal {expected_paths}")
    payload_bytes: dict[str, bytes] = {}
    for path in expected_paths:
        source = input_dir / path
        if not source.is_file() or source.is_symlink(): raise ValueError(f"payload must be a regular file: {path}")
        payload_bytes[path] = source.read_bytes()
    payload_hashes = [sha256_hex(payload_bytes[path]) for path in expected_paths]
    template = {"schema": ENVELOPE_SCHEMA, "artifact_kind": artifact_kind, "repository": repository, "producer_commit": producer_commit, "contract_digest": contract_digest, "toolchain_lock_digest": toolchain_lock_digest, "workflow_file_digest": workflow_file_digest, "workflow_run_id": workflow_run_id, "workflow_run_attempt": workflow_run_attempt, "platform": platform_token, "artifact_name": "", "payload_paths": list(expected_paths), "payload_sha256": payload_hashes, "bundle_sha256": "", "produced_at": produced_at}
    projected_bytes = canonical_bytes(template)
    entries = [{"path": ENVELOPE_ENTRY_PATH, "sha256": sha256_hex(projected_bytes), "size": str(len(projected_bytes))}] + [{"path": path, "sha256": sha256_hex(payload_bytes[path]), "size": str(len(payload_bytes[path]))} for path in expected_paths]
    entries.sort(key=lambda entry: entry["path"].encode())
    manifest = {"schema": MANIFEST_SCHEMA, "entries": entries}
    manifest_bytes = canonical_bytes(manifest)
    digest = sha256_hex(manifest_bytes)
    name = f"encrypted-lifecycle-{artifact_kind.lower().replace('_', '-')}-{workflow_run_id}-{workflow_run_attempt}-{digest[:16]}"
    envelope = dict(template, artifact_name=name, bundle_sha256=digest)
    return {"envelope": envelope, "envelope_bytes": canonical_bytes(envelope), "manifest": manifest, "manifest_bytes": manifest_bytes, "payload_bytes": payload_bytes, "artifact_name": name}


def write_deterministic_tar(path: Path, files: list[tuple[str, bytes]]) -> None:
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(files, key=lambda item: item[0].encode()):
            info = tarfile.TarInfo(name); info.size = len(data); info.mtime = 0; info.uid = info.gid = 0; info.uname = info.gname = ""; info.mode = 0o644; info.type = tarfile.REGTYPE
            tar.addfile(info, io.BytesIO(data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True); parser.add_argument("--output", required=True); parser.add_argument("--payload", action="append", required=True); parser.add_argument("--artifact-kind", choices=tuple(KIND_PAYLOADS), required=True)
    for option in ("repository", "producer-commit", "contract-digest", "toolchain-lock-digest", "workflow-file-digest", "workflow-run-id", "workflow-run-attempt", "platform"): parser.add_argument(f"--{option}", required=True)
    parser.add_argument("--produced-at", default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")); args = parser.parse_args(argv)
    output = Path(args.output); output.mkdir(parents=True, exist_ok=True)
    built = build_bundle(input_dir=Path(args.input), payload_names=args.payload, artifact_kind=args.artifact_kind, repository=args.repository, producer_commit=args.producer_commit, contract_digest=args.contract_digest, toolchain_lock_digest=args.toolchain_lock_digest, workflow_file_digest=args.workflow_file_digest, workflow_run_id=args.workflow_run_id, workflow_run_attempt=args.workflow_run_attempt, platform_token=args.platform, produced_at=args.produced_at)
    archive = output / f"{built['artifact_name']}.tar"
    write_deterministic_tar(archive, [(ENVELOPE_ENTRY_PATH, built["envelope_bytes"]), (MANIFEST_ENTRY_PATH, built["manifest_bytes"]), *built["payload_bytes"].items()])
    print(f"built bundle {archive} artifact_name={built['artifact_name']} bundle_sha256={built['envelope']['bundle_sha256']}")
    return 0

if __name__ == "__main__": raise SystemExit(main())
