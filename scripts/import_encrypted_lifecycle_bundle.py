#!/usr/bin/env python3
"""Independently verify + import a Gate 1 encrypted-lifecycle bundle.

Deliberately does NOT share a helper module with
`build_encrypted_lifecycle_bundle.py`: canonicalization, projection, and
digesting are re-implemented from scratch here so the builder can never be
its own oracle. Any deviation from the frozen acyclic bundle contract in
`schemas/encrypted-lifecycle/bundle-manifest-v1.schema.json` is rejected
with a distinct, stable error code.

Verification order (fail-closed, first violation wins):
  1. Read raw `bundle-manifest.json` bytes. Reject invalid UTF-8, a BOM, and
     duplicate keys with a strict re-implemented parser -- BEFORE any
     digest is computed.
  2. Require the raw manifest bytes to be byte-identical to
     `canonical_bytes(parsed_manifest)` (rejects whitespace, key order,
     escaped-equivalent, and trailing-byte mutations).
  3. `bundle_sha256 = SHA-256(raw manifest bytes)` (now proven == canonical).
  4. Recompute the *projected* envelope from the stored envelope and check
     its hash/size against the manifest's `bundle-envelope.json` entry.
  5. Recompute `artifact_name` from `bundle_sha256` and require exact
     equality with the stored envelope's `artifact_name`.
  6. Require the stored envelope's own `bundle_sha256` field equals the
     recomputed digest.
  7. Verify every payload file's bytes against its manifest entry.
  8. Verify `stored_size_bytes` equals the actual on-disk envelope byte
     length.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tarfile
import unicodedata
from pathlib import Path
from typing import Any, Mapping

ENVELOPE_SCHEMA = "wiki-artifact-bundle-envelope-v1"
MANIFEST_SCHEMA = "wiki-artifact-bundle-manifest-v1"
ENVELOPE_ENTRY_PATH = "bundle-envelope.json"
MANIFEST_ENTRY_PATH = "bundle-manifest.json"

ARTIFACT_NAME_RE = re.compile(r"^encrypted-lifecycle-[a-z0-9-]+-[1-9][0-9]*-[1-9][0-9]*-[0-9a-f]{16}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")


class BundleImportError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    """Independent re-implementation (deliberately duplicated, not shared)."""

    def normalize(v: Any, path: str) -> Any:
        if v is None or isinstance(v, bool):
            return v
        if isinstance(v, str):
            return unicodedata.normalize("NFC", v)
        if isinstance(v, (int, float)):
            raise BundleImportError("RAW_NUMERIC_TOKEN", f"raw numeric token at {path}")
        if isinstance(v, list):
            return [normalize(item, f"{path}[{i}]") for i, item in enumerate(v)]
        if isinstance(v, Mapping):
            out: dict[str, Any] = {}
            for k, item in v.items():
                if not isinstance(k, str):
                    raise BundleImportError("NON_STRING_KEY", f"non-string key at {path}")
                nk = unicodedata.normalize("NFC", k)
                if nk in out:
                    raise BundleImportError("MANIFEST_DUPLICATE_KEY", f"duplicate key after NFC at {path}: {k!r}")
                out[nk] = normalize(item, f"{path}.{nk}")
            return {k: out[k] for k in sorted(out)}
        raise BundleImportError("UNSUPPORTED_VALUE", f"unsupported value type at {path}: {type(v).__name__}")

    normalized = normalize(value, "$")
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise BundleImportError("MANIFEST_DUPLICATE_KEY", f"duplicate raw JSON key: {key!r}")
        seen[key] = value
    return seen


def strict_parse_manifest(raw: bytes) -> dict[str, Any]:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise BundleImportError("MANIFEST_BOM", "manifest bytes begin with a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise BundleImportError("MANIFEST_INVALID_UTF8", str(exc)) from exc
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except BundleImportError:
        raise
    except json.JSONDecodeError as exc:
        raise BundleImportError("MANIFEST_INVALID_JSON", str(exc)) from exc
    if not isinstance(parsed, dict):
        raise BundleImportError("MANIFEST_NOT_OBJECT", "manifest top level is not a JSON object")
    return parsed


def project_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    projected = dict(envelope)
    projected["artifact_name"] = ""
    projected["bundle_sha256"] = ""
    return projected


def load_bundle_files(input_dir: Path) -> dict[str, bytes]:
    tar_candidates = sorted(input_dir.glob("*.tar"))
    files: dict[str, bytes] = {}
    if tar_candidates:
        with tarfile.open(tar_candidates[0], "r") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                extracted = tar.extractfile(member)
                if extracted is None:
                    continue
                files[member.name] = extracted.read()
    else:
        for path in input_dir.rglob("*"):
            if path.is_file():
                files[str(path.relative_to(input_dir))] = path.read_bytes()
    return files


def import_bundle(input_dir: Path) -> dict[str, Any]:
    files = load_bundle_files(input_dir)

    if MANIFEST_ENTRY_PATH not in files:
        raise BundleImportError("MANIFEST_MISSING", f"{MANIFEST_ENTRY_PATH} not found in bundle")
    if ENVELOPE_ENTRY_PATH not in files:
        raise BundleImportError("ENVELOPE_MISSING", f"{ENVELOPE_ENTRY_PATH} not found in bundle")

    raw_manifest = files[MANIFEST_ENTRY_PATH]

    # Step 1-2: strict parse, then require raw bytes == canonical bytes.
    parsed_manifest = strict_parse_manifest(raw_manifest)
    if parsed_manifest.get("schema") != MANIFEST_SCHEMA:
        raise BundleImportError("MANIFEST_SCHEMA_MISMATCH", f"expected schema {MANIFEST_SCHEMA!r}")
    canonical_manifest_bytes = canonical_bytes(parsed_manifest)
    if canonical_manifest_bytes != raw_manifest:
        raise BundleImportError(
            "MANIFEST_NOT_CANONICAL",
            "raw manifest bytes are not byte-identical to canonical_bytes(parsed manifest) "
            "(whitespace, key order, escaped-equivalent, or trailing-byte mutation)",
        )

    # Step 3: digest over the now-proven-canonical raw bytes.
    bundle_sha256 = sha256_hex(raw_manifest)

    entries = parsed_manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise BundleImportError("MANIFEST_ENTRIES_INVALID", "manifest entries missing or empty")
    entry_by_path: dict[str, dict[str, Any]] = {}
    for entry in entries:
        path = entry.get("path")
        if path in entry_by_path:
            raise BundleImportError("MANIFEST_DUPLICATE_ENTRY_PATH", f"duplicate manifest entry path: {path!r}")
        entry_by_path[path] = entry

    if ENVELOPE_ENTRY_PATH not in entry_by_path:
        raise BundleImportError("MANIFEST_MISSING_ENVELOPE_ENTRY", "manifest has no entry for bundle-envelope.json")

    # Load stored (final, non-projected) envelope.
    raw_envelope = files[ENVELOPE_ENTRY_PATH]
    envelope = strict_parse_manifest(raw_envelope)  # reuse strict duplicate-key parser
    if envelope.get("schema") != ENVELOPE_SCHEMA:
        raise BundleImportError("ENVELOPE_SCHEMA_MISMATCH", f"expected schema {ENVELOPE_SCHEMA!r}")

    for field, pattern in (("bundle_sha256", HEX64_RE), ("artifact_name", ARTIFACT_NAME_RE)):
        value = envelope.get(field, "")
        if value == "":
            raise BundleImportError("ENVELOPE_SELF_FIELD_UNPROJECTED", f"stored envelope must have a non-empty {field}")
        if not pattern.match(value):
            raise BundleImportError("ENVELOPE_SELF_FIELD_MALFORMED", f"stored envelope {field} does not match its required pattern")

    # Step 4: recompute projected envelope and compare to manifest entry.
    projected = project_envelope(envelope)
    projected_bytes = canonical_bytes(projected)
    envelope_entry = entry_by_path[ENVELOPE_ENTRY_PATH]
    if envelope_entry.get("sha256") != sha256_hex(projected_bytes):
        raise BundleImportError(
            "ENVELOPE_SELF_FIELD_MISMATCH",
            "projected envelope hash does not match the manifest's bundle-envelope.json entry "
            "(a self-field or another envelope field was mutated after digesting)",
        )
    if envelope_entry.get("size") != str(len(projected_bytes)):
        raise BundleImportError("ENVELOPE_PROJECTED_SIZE_MISMATCH", "projected envelope size does not match manifest entry")

    # Step 5-6: derive artifact_name and compare digest/name to stored envelope.
    lower_kind = str(envelope.get("artifact_kind", "")).lower().replace("_", "-")
    derived_name = f"encrypted-lifecycle-{lower_kind}-{envelope.get('workflow_run_id')}-{envelope.get('workflow_run_attempt')}-{bundle_sha256[:16]}"
    if envelope.get("bundle_sha256") != bundle_sha256:
        raise BundleImportError("DIGEST_MISMATCH", "stored envelope bundle_sha256 does not equal SHA-256(canonical manifest bytes)")
    if envelope.get("artifact_name") != derived_name:
        raise BundleImportError("ARTIFACT_NAME_MISMATCH", f"expected derived artifact_name {derived_name!r}")

    # Step 7: verify payload bytes.
    payload_paths = envelope.get("payload_paths") or []
    payload_sha256 = envelope.get("payload_sha256") or []
    if len(payload_paths) != len(payload_sha256):
        raise BundleImportError("PAYLOAD_LIST_LENGTH_MISMATCH", "payload_paths and payload_sha256 length mismatch")
    for rel, expected_hash in zip(payload_paths, payload_sha256):
        if rel not in entry_by_path:
            raise BundleImportError("PAYLOAD_MANIFEST_ENTRY_MISSING", f"no manifest entry for payload {rel!r}")
        if rel not in files:
            raise BundleImportError("PAYLOAD_FILE_MISSING", f"payload file {rel!r} absent from bundle archive")
        actual = files[rel]
        actual_hash = sha256_hex(actual)
        if actual_hash != expected_hash or actual_hash != entry_by_path[rel]["sha256"]:
            raise BundleImportError("PAYLOAD_HASH_MISMATCH", f"payload {rel!r} bytes do not match declared sha256")
        if entry_by_path[rel]["size"] != str(len(actual)):
            raise BundleImportError("PAYLOAD_SIZE_MISMATCH", f"payload {rel!r} size does not match manifest entry")

    # Step 8: stored_size_bytes describes the final envelope's own bytes,
    # never the projected form -- and must never be compared to the
    # manifest's projected-envelope size entry (which was already checked
    # separately above).
    stored_size = envelope.get("stored_size_bytes")
    if stored_size != str(len(raw_envelope)):
        raise BundleImportError("STORED_SIZE_MISMATCH", "stored_size_bytes does not equal the actual stored envelope byte length")

    return {
        "artifact_name": envelope["artifact_name"],
        "bundle_sha256": bundle_sha256,
        "payload_paths": payload_paths,
        "verified": True,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="directory containing the bundle tar or exploded files")
    parser.add_argument("--output", required=True, help="directory to write validated payload files + receipt")
    args = parser.parse_args(argv)

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    try:
        result = import_bundle(input_dir)
    except BundleImportError as exc:
        print(f"REJECTED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1

    output_dir.mkdir(parents=True, exist_ok=True)
    files = load_bundle_files(input_dir)
    for rel in result["payload_paths"]:
        dest = output_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(files[rel])
    (output_dir / "import-receipt.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"imported bundle artifact_name={result['artifact_name']} bundle_sha256={result['bundle_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
