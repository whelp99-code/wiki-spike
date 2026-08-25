from __future__ import annotations

import json
from dataclasses import replace
from itertools import permutations
from pathlib import Path

import pytest
from tests.second_brain.snapshot_importer_support import (
    digest_of,
    discovery_of,
    snapshot_from_records,
)

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.second_brain_complete_snapshot import (
    COMPLETE_SNAPSHOT_CERTIFICATE_V1,
    CompleteSnapshotCertificateV1,
    SnapshotDisposition,
    SnapshotReconciliationError,
    reconcile_snapshot,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.source_discovery import SourceDiscoveryManifestV1


def _live(native_id: str, revision: str, path: str, content: str, key: str) -> dict[str, JsonValue]:
    return {
        "native_id": native_id,
        "revision": revision,
        "watermark": f"watermark-{revision}",
        "tombstone": False,
        "relative_path": path,
        "content_digest": digest_of(content),
        "keyed_dedupe_ref": f"keyed-content:{digest_of(key)}",
    }


def _evidence(root: Path) -> tuple[CompleteSnapshotCertificateV1, SourceDiscoveryManifestV1]:
    manifest = discovery_of(root)
    return manifest.complete_snapshot_certificate(), manifest


def test_reconciliation_accounts_for_all_five_dispositions_and_removes_only_missing_source_edge(
    tmp_path: Path,
) -> None:
    # Given: a prior snapshot and a certified complete successor containing replay, update, collision, and insert cases.
    root = tmp_path / "source"
    root.mkdir()
    for name, body in (("accepted.md", "new"), ("collision.md", "changed"), ("duplicate.md", "same"), ("updated.md", "after")):
        (root / name).write_text(body, encoding="utf-8")
    previous = snapshot_from_records(
        [
            _live("collision", "1", "collision.md", "before", "c"),
            _live("duplicate", "1", "duplicate.md", "same", "d"),
            _live("missing", "1", "missing.md", "gone", "e"),
            _live("updated", "1", "updated.md", "before", "u"),
        ],
        "watermark-1",
    )
    current = snapshot_from_records(
        [
            _live("accepted", "1", "accepted.md", "new", "a"),
            _live("collision", "1", "collision.md", "changed", "c"),
            _live("duplicate", "1", "duplicate.md", "same", "d"),
            _live("updated", "2", "updated.md", "after", "u"),
        ],
        "watermark-2",
    )

    # When: the complete snapshot is reconciled.
    result = reconcile_snapshot(previous, current, *_evidence(root))

    # Then: conservation is exact and the absent source edge alone is removed.
    assert [(item.native_id, item.disposition) for item in result.items] == [
        ("accepted", SnapshotDisposition.ACCEPTED),
        ("collision", SnapshotDisposition.QUARANTINED),
        ("duplicate", SnapshotDisposition.DUPLICATE),
        ("missing", SnapshotDisposition.TOMBSTONED),
        ("updated", SnapshotDisposition.UPDATED),
    ]
    assert result.expected_count == result.accounted_count == 5
    assert result.disposition_counts == {
        SnapshotDisposition.ACCEPTED: 1,
        SnapshotDisposition.UPDATED: 1,
        SnapshotDisposition.DUPLICATE: 1,
        SnapshotDisposition.TOMBSTONED: 1,
        SnapshotDisposition.QUARANTINED: 1,
    }
    assert [(edge.native_id, edge.keyed_dedupe_ref) for edge in result.provenance_edge_removals] == [
        ("missing", f"keyed-content:{digest_of('e')}")
    ]


def test_uncertified_absence_is_quarantined_without_tombstone_or_edge_removal(tmp_path: Path) -> None:
    # Given: an item absent from a partial, uncertified successor.
    root = tmp_path / "source"
    root.mkdir()
    (root / "present.md").write_text("present", encoding="utf-8")
    previous = snapshot_from_records(
        [_live("missing", "1", "missing.md", "gone", "e"), _live("present", "1", "present.md", "present", "p")],
        "watermark-1",
    )
    current = snapshot_from_records([_live("present", "1", "present.md", "present", "p")], "watermark-2")

    # When: reconciliation has no complete-snapshot certificate.
    result = reconcile_snapshot(previous, current, None, None)

    # Then: absence fails closed and cannot delete provenance.
    missing = next(item for item in result.items if item.native_id == "missing")
    assert missing.disposition is SnapshotDisposition.QUARANTINED
    assert result.provenance_edge_removals == ()


def test_keyed_dedupe_requires_matching_payload_and_revision_collision_is_quarantined(tmp_path: Path) -> None:
    # Given: one new native identity with the same keyed payload and one same-revision payload collision.
    root = tmp_path / "source"
    root.mkdir()
    (root / "alias.md").write_text("same", encoding="utf-8")
    (root / "collision.md").write_text("changed", encoding="utf-8")
    (root / "false-alias.md").write_text("different", encoding="utf-8")
    previous = snapshot_from_records(
        [_live("original", "1", "original.md", "same", "k"), _live("collision", "4", "collision.md", "before", "c")],
        "watermark-1",
    )
    current = snapshot_from_records(
        [
            _live("alias", "1", "alias.md", "same", "k"),
            _live("collision", "4", "collision.md", "changed", "c"),
            _live("false-alias", "1", "false-alias.md", "different", "k"),
        ],
        "watermark-2",
    )

    # When: keyed identities are reconciled.
    result = reconcile_snapshot(previous, current, *_evidence(root))

    # Then: only the key-plus-payload match deduplicates; the revision collision is quarantined.
    outcomes = {item.native_id: item.disposition for item in result.items}
    assert outcomes["alias"] is SnapshotDisposition.DUPLICATE
    assert outcomes["collision"] is SnapshotDisposition.QUARANTINED
    assert outcomes["false-alias"] is SnapshotDisposition.ACCEPTED
    assert outcomes["original"] is SnapshotDisposition.TOMBSTONED


def test_reconciliation_is_permutation_deterministic(tmp_path: Path) -> None:
    # Given: equivalent snapshots in every input ordering.
    root = tmp_path / "source"
    root.mkdir()
    records = [_live("beta", "1", "beta.md", "beta", "b"), _live("alpha", "1", "alpha.md", "alpha", "a")]
    for record in records:
        (root / str(record["relative_path"])).write_text(str(record["native_id"]), encoding="utf-8")
    certificate, manifest = _evidence(root)

    # When: every permutation is reconciled.
    results = {
        reconcile_snapshot(
            snapshot_from_records([], "watermark-0"),
            snapshot_from_records(list(order), "watermark-1"),
            certificate,
            manifest,
        )
        for order in permutations(records)
    }

    # Then: ordering cannot affect the closed result.
    assert len(results) == 1


def test_certificate_rejects_manifest_mismatch(tmp_path: Path) -> None:
    # Given: a certificate for a different complete scan.
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "alpha.md").write_text("alpha", encoding="utf-8")
    (second / "beta.md").write_text("beta", encoding="utf-8")

    # When/Then: a certificate cannot be rebound to another manifest.
    certificate, _manifest = _evidence(first)
    with pytest.raises(ValueError, match="certificate"):
        certificate.assert_manifest(discovery_of(second))


def test_stale_certificate_with_same_paths_cannot_infer_absence(tmp_path: Path) -> None:
    # Given: the same live path was rescanned after its metadata changed.
    root = tmp_path / "source"
    root.mkdir()
    live = root / "present.md"
    live.write_text("first", encoding="utf-8")
    stale_certificate, _stale_manifest = _evidence(root)
    live.write_text("second-longer", encoding="utf-8")
    current_manifest = discovery_of(root)
    previous = snapshot_from_records(
        [_live("missing", "1", "missing.md", "gone", "m"), _live("present", "1", "present.md", "first", "p")],
        "watermark-1",
    )
    current = snapshot_from_records([_live("present", "2", "present.md", "second-longer", "p")], "watermark-2")

    # When/Then: manifest identity is checked before any absence inference.
    with pytest.raises(SnapshotReconciliationError, match="certificate"):
        reconcile_snapshot(previous, current, stale_certificate, current_manifest)
    partial = reconcile_snapshot(previous, current, None, current_manifest)
    assert all(item.disposition is not SnapshotDisposition.TOMBSTONED for item in partial.items)
    assert partial.provenance_edge_removals == ()


def test_certificate_without_manifest_fails_before_absence_inference(tmp_path: Path) -> None:
    # Given: a certificate without its exact current manifest.
    root = tmp_path / "source"
    root.mkdir()
    (root / "present.md").write_text("present", encoding="utf-8")
    certificate, _manifest = _evidence(root)
    previous = snapshot_from_records([_live("missing", "1", "missing.md", "gone", "m")], "watermark-1")
    current = snapshot_from_records([], "watermark-2")

    # When/Then: the certificate alone cannot authorize a tombstone or edge removal.
    with pytest.raises(SnapshotReconciliationError, match="manifest"):
        reconcile_snapshot(previous, current, certificate, None)
    partial = reconcile_snapshot(previous, current, None, None)
    assert partial.items[0].disposition is SnapshotDisposition.QUARANTINED
    assert partial.provenance_edge_removals == ()


def test_swapped_source_root_digest_is_rejected(tmp_path: Path) -> None:
    # Given: a valid certificate body with another source root digest substituted.
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "note.md").write_text("same", encoding="utf-8")
    (second / "note.md").write_text("same", encoding="utf-8")
    certificate, manifest = _evidence(first)
    other, _other_manifest = _evidence(second)
    body = certificate.to_mapping()
    body["source_root_digest"] = other.source_root_digest
    del body["certificate_digest"]
    swapped = replace(
        certificate,
        source_root_digest=other.source_root_digest,
        certificate_digest=canonical_ledger_digest("complete-snapshot-certificate-v1", body),
    )

    # When/Then: root identity cannot be rebound even with a recomputed certificate digest.
    with pytest.raises(SnapshotReconciliationError, match="certificate"):
        swapped.assert_manifest(manifest)


def test_serialized_certificate_contains_no_absolute_source_root(tmp_path: Path) -> None:
    # Given: a certificate for an absolute private source root.
    root = tmp_path / "private-source"
    root.mkdir()
    (root / "note.md").write_text("private", encoding="utf-8")
    certificate, _manifest = _evidence(root)

    # When: the certificate is serialized through its strict contract.
    payload = certificate.to_mapping()
    encoded = json.dumps(payload, sort_keys=True)

    # Then: only the domain-separated root digest crosses the boundary.
    assert payload["certificate_version"] == COMPLETE_SNAPSHOT_CERTIFICATE_V1
    assert "source_root" not in payload
    assert payload["source_root_digest"] != str(root.resolve())
    assert str(root.resolve()) not in encoded
