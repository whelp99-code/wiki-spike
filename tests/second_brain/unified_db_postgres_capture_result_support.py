"""Builders for POSTGRES_METADATA_CAPTURE_ONLY output-binding tests."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest

DESTINATION_VERSION = (
    "second-brain-unified-db-postgres-metadata-capture-destination-v1"
)
DESTINATION_DOMAIN = "unified-db-postgres-metadata-capture-destination-v1"
OUTPUT_MANIFEST_VERSION = (
    "second-brain-unified-db-postgres-metadata-capture-output-manifest-v1"
)
OUTPUT_MANIFEST_DOMAIN = "unified-db-postgres-metadata-capture-output-manifest-v1"
RECEIPT_VERSION = "second-brain-unified-db-postgres-metadata-capture-receipt-v1"
RECEIPT_DOMAIN = "unified-db-postgres-metadata-capture-receipt-v1"
OUTPUT_DOMAIN = "unified-db-postgres-metadata-capture-output-v1"
RECEIPT_STATE = "METADATA_CAPTURED_NOT_AUTHORIZED"
PATH_POLICY = "create-only-exclusive"
DESTINATION_PATH = "/captured/postgres-metadata"
CAPTURE_ARTIFACT_NAMES = (
    "capture-plan.json",
    "catalog.json",
    "identity.json",
    "output-manifest.json",
    "query-manifest.json",
    "receipt.json",
)
DESTINATION_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-destination-v1.schema.json"
)
OUTPUT_MANIFEST_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-output-manifest-v1.schema.json"
)
RECEIPT_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-receipt-v1.schema.json"
)
CONFORMANCE_SCHEMA = Path(
    "schemas/second-brain/unified-db-postgres-metadata-capture-output-conformance-v1.schema.json"
)
CONFORMANCE_EVIDENCE = Path(
    "artifacts/product-release/second-brain-v1/evidence/"
    + "unified-db-postgres-metadata-capture-output-conformance-v1.json"
)


def rebind(
    domain: str, body: Mapping[str, JsonValue], field: str
) -> dict[str, JsonValue]:
    unsigned = {key: value for key, value in body.items() if key != field}
    return unsigned | {field: canonical_ledger_digest(domain, unsigned)}


def destination_body(
    path: str = DESTINATION_PATH, **overrides: JsonValue
) -> dict[str, JsonValue]:
    body: dict[str, JsonValue] = {
        "destination_version": DESTINATION_VERSION,
        "source_name": "unified-db",
        "operation": "METADATA_CAPTURE_ONLY",
        "authorization_kind": "POSTGRES_METADATA_CAPTURE_ONLY",
        "destination_path": path,
        "path_policy": PATH_POLICY,
        "import_requested": False,
        "serve_requested": False,
        "promote_requested": False,
        "cutover_requested": False,
    }
    body.update(overrides)
    if "destination_digest" not in overrides:
        return rebind(DESTINATION_DOMAIN, body, "destination_digest")
    return body


def artifact_files() -> dict[str, bytes]:
    return {name: name.encode("ascii") + b"\n" for name in CAPTURE_ARTIFACT_NAMES}


def manifest_entries(
    files: Mapping[str, bytes] | None = None,
) -> list[JsonValue]:
    payload = artifact_files() if files is None else files
    entries: list[JsonValue] = []
    for name in CAPTURE_ARTIFACT_NAMES:
        entries.append(
            {
                "relative_path": name,
                "size_bytes": str(len(payload[name])),
                "content_digest": sha256(payload[name]).hexdigest(),
            }
        )
    return entries


def named_entries(manifest: Mapping[str, JsonValue]) -> dict[str, Mapping[str, JsonValue]]:
    raw = manifest["entries"]
    if not isinstance(raw, list):
        return {}
    named: dict[str, Mapping[str, JsonValue]] = {}
    for item in raw:
        if isinstance(item, dict):
            path = item["relative_path"]
            if isinstance(path, str):
                named[path] = item
    return named


def output_manifest_body(
    destination_digest: str,
    files: Mapping[str, bytes] | None = None,
    **overrides: JsonValue,
) -> dict[str, JsonValue]:
    entries = manifest_entries(files)
    body: dict[str, JsonValue] = {
        "manifest_version": OUTPUT_MANIFEST_VERSION,
        "source_name": "unified-db",
        "operation": "METADATA_CAPTURE_ONLY",
        "destination_digest": destination_digest,
        "entry_count": str(len(entries)),
        "entries": entries,
    }
    body.update(overrides)
    if "manifest_digest" not in overrides:
        return rebind(OUTPUT_MANIFEST_DOMAIN, body, "manifest_digest")
    return body


def output_digest_for(
    destination_digest: str, manifest: Mapping[str, JsonValue]
) -> str:
    return canonical_ledger_digest(
        OUTPUT_DOMAIN,
        {
            "destination_digest": destination_digest,
            "output_manifest_digest": manifest["manifest_digest"],
            "entries": manifest["entries"],
        },
    )


def receipt_body(
    destination_digest: str,
    manifest: Mapping[str, JsonValue],
    **overrides: JsonValue,
) -> dict[str, JsonValue]:
    entries = named_entries(manifest)
    byte_count = str(sum(int(str(item["size_bytes"])) for item in entries.values()))
    body: dict[str, JsonValue] = {
        "receipt_version": RECEIPT_VERSION,
        "state": RECEIPT_STATE,
        "operation": "METADATA_CAPTURE_ONLY",
        "source_name": "unified-db",
        "authorization_kind": "POSTGRES_METADATA_CAPTURE_ONLY",
        "application_row_present": False,
        "source_body_present": False,
        "source_mutation": False,
        "export_invoked": False,
        "import_invoked": False,
        "serving_promotion": False,
        "cutover_eligible": False,
        "query_manifest_digest": entries["query-manifest.json"]["content_digest"],
        "capture_plan_digest": entries["capture-plan.json"]["content_digest"],
        "catalog_digest": entries["catalog.json"]["content_digest"],
        "identity_digest": entries["identity.json"]["content_digest"],
        "destination_digest": destination_digest,
        "output_manifest_digest": manifest["manifest_digest"],
        "output_digest": output_digest_for(destination_digest, manifest),
        "byte_count": byte_count,
    }
    body.update(overrides)
    if "receipt_digest" not in overrides:
        return rebind(RECEIPT_DOMAIN, body, "receipt_digest")
    return body


def draft_status(schema_path: Path, instance: Mapping[str, JsonValue]) -> int:
    script = (
        "import json,sys,jsonschema;"
        "schema=json.load(open(sys.argv[1], encoding='utf-8'));"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(schema_path), json.dumps(dict(instance))],
        capture_output=True,
        check=False,
        text=True,
    )
    return completed.returncode
