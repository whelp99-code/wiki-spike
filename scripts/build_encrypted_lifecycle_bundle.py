#!/usr/bin/env python3
"""Build a Gate 1 encrypted-lifecycle cross-run evidence bundle.

Independent implementation of the acyclic bundle contract in
`schemas/encrypted-lifecycle/bundle-manifest-v1.schema.json`. This script
owns encoding only; `import_encrypted_lifecycle_bundle.py` re-implements
canonicalization from scratch (no shared helper module) so the builder can
never be its own oracle.

Digest projection (frozen, acyclic):
  1. Build the envelope with every field set except the two self-fields,
     which are held at the fixed empty string `""` (`artifact_name`,
     `bundle_sha256`) -- this is `ProjectEnvelopeForBundleDigestV1`.
  2. Manifest entries list every payload file plus one entry for the
     *projected* envelope bytes (`bundle-envelope.json`, hash/size of the
     projected form).
  3. `bundle_sha256 = SHA-256(canonical_bytes(manifest))`.
  4. `artifact_name` is derived from that digest.
  5. Pass 2: the *final* (non-projected) envelope is serialized with the
     real `artifact_name`/`bundle_sha256`, and `stored_size_bytes` records
     that final envelope's own byte length -- never the projected size.
  6. A deterministic tar (sorted entries, zeroed mtimes/uids/gids) is
     written containing the final envelope, the manifest, and the payload
     files at their manifest-declared relative paths.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import stat
import tarfile
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

ENVELOPE_SCHEMA = "wiki-artifact-bundle-envelope-v1"
MANIFEST_SCHEMA = "wiki-artifact-bundle-manifest-v1"
ENVELOPE_ENTRY_PATH = "bundle-envelope.json"
MANIFEST_ENTRY_PATH = "bundle-manifest.json"


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Independent re-implementation: NFC strings, sorted keys, no raw numbers."""

    def normalize(v: Any, path: str) -> Any:
        if v is None or isinstance(v, bool):
            return v
        if isinstance(v, str):
            return unicodedata.normalize("NFC", v)
        if isinstance(v, (int, float)):
            raise ValueError(f"raw numeric token forbidden at {path}; use a decimal string")
        if isinstance(v, list):
            return [normalize(item, f"{path}[{i}]") for i, item in enumerate(v)]
        if isinstance(v, Mapping):
            out: dict[str, Any] = {}
            for k, item in v.items():
                if not isinstance(k, str):
                    raise ValueError(f"object key must be a string at {path}")
                nk = unicodedata.normalize("NFC", k)
                if nk in out:
                    raise ValueError(f"duplicate key after NFC normalization at {path}: {k!r}")
                out[nk] = normalize(item, f"{path}.{nk}")
            return {k: out[k] for k in sorted(out)}
        raise ValueError(f"unsupported value type at {path}: {type(v).__name__}")

    normalized = normalize(value, "$")
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def project_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    projected = dict(envelope)
    projected["artifact_name"] = ""
    projected["bundle_sha256"] = ""
    return projected


def build_bundle(
    *,
    input_dir: Path,
    payload_names: list[str],
    artifact_kind: str,
    repository: str,
    producer_commit: str,
    contract_digest: str,
    toolchain_lock_digest: str,
    workflow_file_digest: str,
    workflow_run_id: str,
    workflow_run_attempt: str,
    platform_token: str,
    produced_at: str,
) -> dict[str, Any]:
    payload_paths = sorted(payload_names)
    payload_bytes: dict[str, bytes] = {}
    payload_sha256: list[str] = []
    for rel in payload_paths:
        data = (input_dir / rel).read_bytes()
        payload_bytes[rel] = data
        payload_sha256.append(sha256_hex(data))

    lower_kind = artifact_kind.lower().replace("_", "-")
    name_placeholder = f"encrypted-lifecycle-{lower_kind}-{workflow_run_id}-{workflow_run_attempt}-{'0' * 16}"
    digest_placeholder = "0" * 64

    envelope_base: dict[str, Any] = {
        "schema": ENVELOPE_SCHEMA,
        "artifact_kind": artifact_kind,
        "repository": repository,
        "producer_commit": producer_commit,
        "contract_digest": contract_digest,
        "toolchain_lock_digest": toolchain_lock_digest,
        "workflow_file_digest": workflow_file_digest,
        "workflow_run_id": workflow_run_id,
        "workflow_run_attempt": workflow_run_attempt,
        "platform": platform_token,
        "artifact_name": "",
        "payload_paths": payload_paths,
        "payload_sha256": payload_sha256,
        "bundle_sha256": "",
        "stored_size_bytes": "0",
        "produced_at": produced_at,
    }

    # stored_size_bytes describes the FINAL (non-projected) envelope's own
    # byte length. Its value is knowable before the real digest exists
    # because artifact_name/bundle_sha256 have fixed string lengths
    # regardless of their actual hex content -- only stored_size_bytes'
    # own decimal-string width can move the total, so resolve it by fixed
    # point (converges in 1-2 iterations for any realistic envelope size).
    guess = "0"
    for _ in range(8):
        sized = dict(envelope_base)
        sized["artifact_name"] = name_placeholder
        sized["bundle_sha256"] = digest_placeholder
        sized["stored_size_bytes"] = guess
        length = len(canonical_bytes(sized))
        new_guess = str(length)
        if new_guess == guess:
            break
        guess = new_guess
    else:
        raise RuntimeError("stored_size_bytes fixed point did not converge")
    stored_size_bytes = guess
    envelope_base["stored_size_bytes"] = stored_size_bytes

    # Pass 1: projected envelope (self-fields "") feeds the manifest entry.
    # stored_size_bytes is NOT a self-field and is kept at its real,
    # already-resolved value in the projected form.
    projected = project_envelope(envelope_base)
    projected_bytes = canonical_bytes(projected)

    manifest_entries = [
        {"path": rel, "sha256": payload_sha256[i], "size": str(len((input_dir / rel).read_bytes()))}
        for i, rel in enumerate(payload_paths)
    ]
    manifest_entries.append(
        {"path": ENVELOPE_ENTRY_PATH, "sha256": sha256_hex(projected_bytes), "size": str(len(projected_bytes))}
    )
    manifest_entries.sort(key=lambda e: e["path"])
    manifest = {"schema": MANIFEST_SCHEMA, "entries": manifest_entries}
    manifest_bytes = canonical_bytes(manifest)
    bundle_sha256 = sha256_hex(manifest_bytes)

    artifact_name = f"encrypted-lifecycle-{lower_kind}-{workflow_run_id}-{workflow_run_attempt}-{bundle_sha256[:16]}"
    assert len(artifact_name) == len(name_placeholder), "artifact_name length drifted from sizing placeholder"

    # Pass 2: final (non-projected) envelope with the real self-fields;
    # stored_size_bytes is unchanged from the resolved fixed point because
    # both self-fields keep exactly their placeholder lengths.
    final_envelope = dict(envelope_base)
    final_envelope["artifact_name"] = artifact_name
    final_envelope["bundle_sha256"] = bundle_sha256
    final_bytes = canonical_bytes(final_envelope)
    assert len(final_bytes) == int(stored_size_bytes), "stored_size_bytes did not match final envelope byte length"

    return {
        "envelope": final_envelope,
        "envelope_bytes": final_bytes,
        "manifest": manifest,
        "manifest_bytes": manifest_bytes,
        "payload_bytes": payload_bytes,
        "artifact_name": artifact_name,
    }


def write_deterministic_tar(tar_path: Path, files: list[tuple[str, bytes]]) -> None:
    files_sorted = sorted(files, key=lambda f: f[0])
    with tarfile.open(tar_path, "w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in files_sorted:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mode = stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            info.type = tarfile.REGTYPE

            tar.addfile(info, io.BytesIO(data))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="directory containing payload files")
    parser.add_argument("--output", required=True, help="directory to write bundle.tar + side files")
    parser.add_argument("--payload", action="append", required=True, help="payload file relative path (repeatable)")
    parser.add_argument("--artifact-kind", required=True, choices=["SQLCIPHER_FEASIBILITY", "GATE1_DECISION", "CONFORMANCE_PRE_CANARY", "CANARY_24H"])
    parser.add_argument("--repository", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--contract-digest", required=True)
    parser.add_argument("--toolchain-lock-digest", required=True)
    parser.add_argument("--workflow-file-digest", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--produced-at", default=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
    args = parser.parse_args(argv)

    input_dir = Path(args.input)
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    built = build_bundle(
        input_dir=input_dir,
        payload_names=args.payload,
        artifact_kind=args.artifact_kind,
        repository=args.repository,
        producer_commit=args.producer_commit,
        contract_digest=args.contract_digest,
        toolchain_lock_digest=args.toolchain_lock_digest,
        workflow_file_digest=args.workflow_file_digest,
        workflow_run_id=args.workflow_run_id,
        workflow_run_attempt=args.workflow_run_attempt,
        platform_token=args.platform,
        produced_at=args.produced_at,
    )

    (output_dir / ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
    (output_dir / MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])

    tar_files = [(ENVELOPE_ENTRY_PATH, built["envelope_bytes"]), (MANIFEST_ENTRY_PATH, built["manifest_bytes"])]
    for rel, data in built["payload_bytes"].items():
        tar_files.append((rel, data))

    tar_path = output_dir / f"{built['artifact_name']}.tar"
    write_deterministic_tar(tar_path, tar_files)

    print(f"built bundle {tar_path} artifact_name={built['artifact_name']} bundle_sha256={built['envelope']['bundle_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
