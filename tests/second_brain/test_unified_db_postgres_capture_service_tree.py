"""Claimed capture tree listings must match the on-disk six-file bytes."""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    CAPTURE_PLAN_DIGEST,
    NOW,
    OUTPUT_DIGEST,
    QUERY_MANIFEST_DIGEST,
    authorization_body,
    signed_request,
)
from tests.second_brain.unified_db_postgres_capture_result_support import (
    CAPTURE_ARTIFACT_NAMES,
    RECEIPT_DOMAIN,
    artifact_files,
    destination_body,
    rebind,
)
from tests.second_brain.unified_db_postgres_capture_support import (
    FakePostgresCatalogQuery,
    closed_catalog_query_results,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_checks import (
    bind_produced_capture_digests,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
    verify_metadata_capture_authorization,
)
from wiki_spike.applications.unified_db_postgres_capture_service import (
    PostgresMetadataCaptureService,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_output import (
    PostgresMetadataCaptureOutputManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_result import (
    PostgresMetadataCaptureReceiptV1,
    bind_capture_receipt,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

SERVICE = Path("src/wiki_spike/applications/unified_db_postgres_capture_service.py")
COMPOSITION = Path("src/wiki_spike/composition/unified_db_postgres_capture.py")


def _grant_pair(
    dest: Path,
    *,
    capture_plan_digest: str = CAPTURE_PLAN_DIGEST,
    output_digest: str = OUTPUT_DIGEST,
) -> tuple[VerifiedUnifiedDbMetadataCaptureAuthorityV1, FakePostgresCatalogQuery]:
    dest_body = destination_body(str(dest))
    body = authorization_body(
        destination=dest_body,
        capture_plan_digest=capture_plan_digest,
        output_digest=output_digest,
    )
    expected = ExpectedMetadataCaptureDigestsV1(
        QUERY_MANIFEST_DIGEST,
        capture_plan_digest,
        output_digest,
        str(dest_body["destination_digest"]),
    )
    request, nonces = signed_request(body=body, expected=expected)
    token = verify_metadata_capture_authorization(request, nonces)
    return token, FakePostgresCatalogQuery(closed_catalog_query_results())


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(path.read_text(encoding="utf-8"))


def test_claimed_capture_lists_self_artifact_size_and_tree_byte_count_matching_on_disk(
    tmp_path: Path,
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(dest)
    receipt = PostgresMetadataCaptureService(catalog).capture(token.claim(), NOW)
    files = {path.name: path.read_bytes() for path in dest.iterdir()}
    manifest = PostgresMetadataCaptureOutputManifestV1.from_mapping(
        _load(dest / "output-manifest.json")
    )
    parsed = PostgresMetadataCaptureReceiptV1.from_mapping(_load(dest / "receipt.json"))
    listed = {entry.relative_path: entry for entry in manifest.entries}
    assert listed["receipt.json"].size_bytes == str(len(files["receipt.json"]))
    assert listed["receipt.json"].content_digest != sha256(b"\n").hexdigest()
    assert listed["output-manifest.json"].size_bytes == str(
        len(files["output-manifest.json"])
    )
    assert listed["output-manifest.json"].content_digest != sha256(b"\n").hexdigest()
    assert parsed.byte_count == str(sum(len(files[name]) for name in CAPTURE_ARTIFACT_NAMES))
    assert parsed.receipt_digest == receipt.receipt_digest
    destination = PostgresMetadataCaptureDestinationV1.from_mapping(
        destination_body(str(dest))
    )
    bind_capture_receipt(destination, manifest, parsed)


def _produced_receipt() -> tuple[
    PostgresMetadataCaptureDestinationV1, PostgresMetadataCaptureReceiptV1
]:
    destination = PostgresMetadataCaptureDestinationV1.from_mapping(destination_body())
    files = artifact_files()
    manifest = PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, files
    )
    receipt = PostgresMetadataCaptureReceiptV1.create(destination, manifest)
    return destination, receipt


@pytest.mark.parametrize(
    ("capture_plan_digest", "output_digest"),
    [
        ("0" * 64, OUTPUT_DIGEST),
        (CAPTURE_PLAN_DIGEST, "0" * 64),
    ],
)
def test_bind_produced_capture_digests_refuses_zero_plan_or_output_as_wildcard(
    capture_plan_digest: str, output_digest: str
) -> None:
    destination, receipt = _produced_receipt()
    assert receipt.capture_plan_digest != "0" * 64
    assert receipt.output_digest != "0" * 64
    authorization = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
        authorization_body(
            destination=destination.to_mapping(),
            capture_plan_digest=capture_plan_digest,
            output_digest=output_digest,
        )
    )
    with pytest.raises(InvalidContractValue, match="digest"):
        bind_produced_capture_digests(authorization, receipt)


def test_bind_produced_capture_digests_accepts_matching_produced_hashes() -> None:
    destination, receipt = _produced_receipt()
    matched = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(
        authorization_body(
            destination=destination.to_mapping(),
            capture_plan_digest=receipt.capture_plan_digest,
            output_digest=receipt.output_digest,
        )
    )
    bind_produced_capture_digests(matched, receipt)


def test_bind_capture_receipt_refuses_digest_mismatch_against_tree() -> None:
    destination = PostgresMetadataCaptureDestinationV1.from_mapping(destination_body())
    files = artifact_files()
    manifest = PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, files
    )
    receipt = PostgresMetadataCaptureReceiptV1.create(destination, manifest)
    bind_capture_receipt(destination, manifest, receipt, files)
    tampered = dict(files)
    tampered["catalog.json"] = files["catalog.json"] + b"X"
    with pytest.raises(InvalidContractValue, match="content_digest"):
        bind_capture_receipt(destination, manifest, receipt, tampered)


def test_bind_capture_receipt_refuses_byte_count_mismatch_against_tree() -> None:
    destination = PostgresMetadataCaptureDestinationV1.from_mapping(destination_body())
    files = artifact_files()
    manifest = PostgresMetadataCaptureOutputManifestV1.create(
        destination.destination_digest, files
    )
    body = PostgresMetadataCaptureReceiptV1.create(destination, manifest).to_mapping()
    body["byte_count"] = str(int(str(body["byte_count"])) + 1)
    rebound = PostgresMetadataCaptureReceiptV1.from_mapping(
        rebind(RECEIPT_DOMAIN, body, "receipt_digest")
    )
    with pytest.raises(InvalidContractValue, match="byte_count"):
        bind_capture_receipt(destination, manifest, rebound, files)


@pytest.mark.parametrize(
    ("capture_plan_digest", "output_digest"),
    [
        ("0" * 64, "0" * 64),
        ("0" * 64, OUTPUT_DIGEST),
        (CAPTURE_PLAN_DIGEST, "0" * 64),
    ],
)
def test_claimed_capture_refuses_zero_plan_or_output_digest_as_produced_wildcard(
    tmp_path: Path, capture_plan_digest: str, output_digest: str
) -> None:
    dest = tmp_path / "capture-out"
    token, catalog = _grant_pair(
        dest,
        capture_plan_digest=capture_plan_digest,
        output_digest=output_digest,
    )
    with pytest.raises(InvalidContractValue, match="digest"):
        _ = PostgresMetadataCaptureService(catalog).capture(token.claim(), NOW)
    assert not dest.exists()


def test_service_does_not_hash_self_artifacts_as_newline_placeholder() -> None:
    text = SERVICE.read_text(encoding="utf-8")
    assert '"output-manifest.json": b"\\n"' not in text
    assert '"receipt.json": b"\\n"' not in text


def test_production_composition_still_refuses_unclaimed_without_service_wiring() -> None:
    text = COMPOSITION.read_text(encoding="utf-8")
    assert "PostgresMetadataCaptureService" not in text
    assert "unified_db_postgres_capture_service" not in text
    assert "refuse_postgres_identity_capture" in text
