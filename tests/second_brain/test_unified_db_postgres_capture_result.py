"""Output-manifest and receipt binding tests for metadata capture."""
from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import pytest

from tests.second_brain.unified_db_postgres_capture_result_support import (
    CAPTURE_ARTIFACT_NAMES,
    CONFORMANCE_EVIDENCE,
    CONFORMANCE_SCHEMA,
    OUTPUT_MANIFEST_DOMAIN,
    OUTPUT_MANIFEST_SCHEMA,
    RECEIPT_DOMAIN,
    RECEIPT_SCHEMA,
    RECEIPT_STATE,
    artifact_files,
    destination_body,
    draft_status,
    output_manifest_body,
    rebind,
    receipt_body,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_output import (
    CAPTURE_ARTIFACT_NAMES as RESULT_ARTIFACT_NAMES,
)
from wiki_spike.memory_core.unified_db_postgres_capture_output import (
    OUTPUT_MANIFEST_VERSION,
    PostgresMetadataCaptureOutputManifestV1,
    verify_capture_artifact_bytes,
)
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    RECEIPT_VERSION,
    PostgresMetadataCaptureReceiptV1,
    bind_capture_receipt,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _destination() -> PostgresMetadataCaptureDestinationV1:
    return PostgresMetadataCaptureDestinationV1.from_mapping(destination_body())


def _manifest(
    destination: PostgresMetadataCaptureDestinationV1,
) -> PostgresMetadataCaptureOutputManifestV1:
    return PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, artifact_files()
    )


def test_artifact_names_are_the_closed_lexicographic_set() -> None:
    assert RESULT_ARTIFACT_NAMES == CAPTURE_ARTIFACT_NAMES
    assert CAPTURE_ARTIFACT_NAMES == tuple(sorted(CAPTURE_ARTIFACT_NAMES))


def test_output_manifest_binds_six_sorted_artifacts() -> None:
    destination = _destination()
    files = artifact_files()
    parsed = PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, files
    )
    assert parsed.manifest_version == OUTPUT_MANIFEST_VERSION
    assert parsed.entry_count == "6"
    assert tuple(entry.relative_path for entry in parsed.entries) == CAPTURE_ARTIFACT_NAMES
    assert parsed.manifest_digest == parsed.computed_digest()
    verify_capture_artifact_bytes(parsed, files)


def test_output_manifest_rejects_missing_extra_and_unsupported_version() -> None:
    destination = _destination()
    body = output_manifest_body(destination.destination_digest)
    missing = dict(body)
    del missing["entries"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(body | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(
            output_manifest_body(
                destination.destination_digest, manifest_version="manifest-v0"
            )
        )


def test_output_manifest_rejects_reordered_or_duplicate_files() -> None:
    destination = _destination()
    body = output_manifest_body(destination.destination_digest)
    entries = list(body["entries"]) if isinstance(body["entries"], list) else []
    reordered = output_manifest_body(
        destination.destination_digest, entries=list(reversed(entries))
    )
    with pytest.raises(InvalidContractValue, match="sorted|order"):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(reordered)
    duplicate = output_manifest_body(
        destination.destination_digest, entries=[entries[0], *entries]
    )
    with pytest.raises(InvalidContractValue, match="duplicate|unique|six"):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(duplicate)


def test_output_manifest_rejects_missing_or_extra_artifact_names() -> None:
    destination = _destination()
    files = artifact_files()
    missing = dict(files)
    del missing["catalog.json"]
    with pytest.raises(InvalidContractValue, match="artifact"):
        _ = PostgresMetadataCaptureOutputManifestV1.create(
            destination.destination_digest, missing
        )
    extra = dict(files)
    extra["notes.json"] = b"no\n"
    with pytest.raises(InvalidContractValue, match="artifact"):
        _ = PostgresMetadataCaptureOutputManifestV1.create(
            destination.destination_digest, extra
        )


def test_output_manifest_rejects_digest_and_byte_count_tamper() -> None:
    destination = _destination()
    files = artifact_files()
    parsed = PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, files
    )
    body = parsed.to_mapping()
    body["manifest_digest"] = "ab" * 32
    with pytest.raises(InvalidContractValue, match="manifest_digest"):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(body)
    tampered_files = dict(files)
    original = files["catalog.json"]
    tampered_files["catalog.json"] = original[:-1] + b"X"
    with pytest.raises(InvalidContractValue, match="content_digest"):
        verify_capture_artifact_bytes(parsed, tampered_files)
    mapping = parsed.to_mapping()
    raw_entries = mapping["entries"]
    sized_entries: list[JsonValue] = []
    if isinstance(raw_entries, list):
        for item in raw_entries:
            if isinstance(item, dict):
                updated: dict[str, JsonValue] = dict(item)
                if not sized_entries:
                    size = updated["size_bytes"]
                    updated["size_bytes"] = str(int(str(size)) + 1)
                sized_entries.append(updated)
    sized: dict[str, JsonValue] = {**mapping, "entries": sized_entries}
    rebound = PostgresMetadataCaptureOutputManifestV1.from_mapping(
        rebind(OUTPUT_MANIFEST_DOMAIN, sized, "manifest_digest")
    )
    with pytest.raises(InvalidContractValue, match="size_bytes"):
        verify_capture_artifact_bytes(rebound, files)


def test_output_manifest_rejects_raw_numeric_counts() -> None:
    destination = _destination()
    body = output_manifest_body(destination.destination_digest)
    broken: dict[str, object] = dict(body)
    broken["entry_count"] = 6
    with pytest.raises(InvalidContractValue):
        _ = PostgresMetadataCaptureOutputManifestV1.from_mapping(
            cast(Mapping[str, JsonValue], broken)
        )
    with pytest.raises(UnifiedDbExportError, match="raw numbers"):
        _ = decode_json_object('{"manifest_version":"x","entry_count":6}')


def test_receipt_cross_binds_destination_and_manifest() -> None:
    destination = _destination()
    manifest = _manifest(destination)
    receipt = PostgresMetadataCaptureReceiptV1.create(destination, manifest)
    assert receipt.receipt_version == RECEIPT_VERSION
    assert receipt.state == RECEIPT_STATE
    assert receipt.destination_digest == destination.destination_digest
    assert receipt.output_manifest_digest == manifest.manifest_digest
    assert receipt.receipt_digest == receipt.computed_digest()
    bind_capture_receipt(destination, manifest, receipt)


def test_receipt_rejects_missing_extra_and_unsupported_version() -> None:
    destination = _destination()
    manifest = _manifest(destination)
    body = receipt_body(destination.destination_digest, manifest.to_mapping())
    missing = dict(body)
    del missing["output_digest"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = PostgresMetadataCaptureReceiptV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = PostgresMetadataCaptureReceiptV1.from_mapping(body | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = PostgresMetadataCaptureReceiptV1.from_mapping(
            receipt_body(
                destination.destination_digest,
                manifest.to_mapping(),
                receipt_version="receipt-v0",
            )
        )


def test_receipt_rejects_digest_tamper_and_cross_binding_swap() -> None:
    destination = _destination()
    other = PostgresMetadataCaptureDestinationV1.from_mapping(
        destination_body("/captured/other-metadata")
    )
    manifest = _manifest(destination)
    receipt = PostgresMetadataCaptureReceiptV1.create(destination, manifest)
    broken = receipt.to_mapping()
    broken["receipt_digest"] = "ab" * 32
    with pytest.raises(InvalidContractValue, match="receipt_digest"):
        _ = PostgresMetadataCaptureReceiptV1.from_mapping(broken)
    swapped = receipt.to_mapping()
    swapped["destination_digest"] = other.destination_digest
    rebound = PostgresMetadataCaptureReceiptV1.from_mapping(
        rebind(RECEIPT_DOMAIN, swapped, "receipt_digest")
    )
    with pytest.raises(InvalidContractValue, match="destination"):
        bind_capture_receipt(destination, manifest, rebound)
    manifest_swap = receipt.to_mapping()
    manifest_swap["output_manifest_digest"] = "cd" * 32
    rebound_manifest = PostgresMetadataCaptureReceiptV1.from_mapping(
        rebind(RECEIPT_DOMAIN, manifest_swap, "receipt_digest")
    )
    with pytest.raises(InvalidContractValue, match="manifest"):
        bind_capture_receipt(destination, manifest, rebound_manifest)


def test_receipt_rejects_byte_count_tamper() -> None:
    destination = _destination()
    manifest = _manifest(destination)
    body = receipt_body(destination.destination_digest, manifest.to_mapping())
    body["byte_count"] = "999"
    rebound = PostgresMetadataCaptureReceiptV1.from_mapping(
        rebind(RECEIPT_DOMAIN, body, "receipt_digest")
    )
    with pytest.raises(InvalidContractValue, match="byte_count"):
        bind_capture_receipt(destination, manifest, rebound)


def test_schemas_and_conformance_use_draft_2020_12() -> None:
    destination = _destination()
    manifest = _manifest(destination)
    receipt = PostgresMetadataCaptureReceiptV1.create(destination, manifest)
    evidence = decode_json_object(CONFORMANCE_EVIDENCE.read_text(encoding="utf-8"))
    assert "https://json-schema.org/draft/2020-12/schema" in OUTPUT_MANIFEST_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert "https://json-schema.org/draft/2020-12/schema" in RECEIPT_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert "https://json-schema.org/draft/2020-12/schema" in CONFORMANCE_SCHEMA.read_text(
        encoding="utf-8"
    )
    assert draft_status(OUTPUT_MANIFEST_SCHEMA, manifest.to_mapping()) == 0
    assert draft_status(RECEIPT_SCHEMA, receipt.to_mapping()) == 0
    assert draft_status(CONFORMANCE_SCHEMA, evidence) == 0
    assert evidence["production_writer_present"] is False
    assert evidence["production_executor_present"] is False
    assert evidence["path_policy"] == "create-only-exclusive"
    assert evidence["artifact_names"] == list(CAPTURE_ARTIFACT_NAMES)
    assert draft_status(OUTPUT_MANIFEST_SCHEMA, manifest.to_mapping() | {"extra": "no"}) != 0
    assert draft_status(RECEIPT_SCHEMA, receipt.to_mapping() | {"extra": "no"}) != 0
    assert draft_status(CONFORMANCE_SCHEMA, evidence | {"extra": "no"}) != 0
