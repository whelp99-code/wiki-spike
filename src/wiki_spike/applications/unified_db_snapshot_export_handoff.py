"""#83-side fresh-discovery handoff after offline package verify."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from wiki_spike.applications.source_discovery_service import discover_source
from wiki_spike.applications.unified_db_snapshot_export_io import HARD_CAP
from wiki_spike.applications.unified_db_snapshot_export_tree import (
    assert_root_allowlist,
    open_package_root,
    read_root_file,
)
from wiki_spike.applications.unified_db_snapshot_export_verify import (
    verify_export_package,
)
from wiki_spike.memory_core.snapshot_import import (
    SNAPSHOT_IMPORT_REQUEST_V1,
    BoundedSnapshotV1,
    SnapshotImportRequestV1,
)
from wiki_spike.memory_core.source_discovery import (
    SOURCE_DISCOVERY_REQUEST_V1,
    SourceDiscoveryManifestV1,
    SourceDiscoveryRequestV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


@dataclass(frozen=True, slots=True)
class SnapshotImportHandoffV1:
    snapshot: BoundedSnapshotV1
    discovery: SourceDiscoveryManifestV1
    request: SnapshotImportRequestV1


def bridge_snapshot_import_handoff(
    package_root: str,
    *,
    cohort_id: str,
    resolved_scope_digest: str,
) -> SnapshotImportHandoffV1:
    receipt = verify_export_package(package_root)
    root_fd = open_package_root(package_root)
    try:
        assert_root_allowlist(root_fd)
        snapshot_bytes, _budget = read_root_file(
            root_fd, "bounded-snapshot.json", HARD_CAP
        )
        snapshot = BoundedSnapshotV1.from_mapping(
            decode_json_object(snapshot_bytes.decode("utf-8"))
        )
    finally:
        os.close(root_fd)
    payload = str((Path(package_root) / "payload").resolve())
    discovery = discover_source(
        SourceDiscoveryRequestV1.from_mapping(
            {
                "request_version": SOURCE_DISCOVERY_REQUEST_V1,
                "source_name": "unified-db",
                "source_root": payload,
            }
        )
    )
    request = SnapshotImportRequestV1.from_mapping(
        {
            "request_version": SNAPSHOT_IMPORT_REQUEST_V1,
            "cohort_id": cohort_id,
            "source_name": "unified-db",
            "source_root": payload,
            "target_namespace": "second-brain:import:unified-db",
            "resolved_scope_digest": resolved_scope_digest,
            "discovery_manifest_digest": discovery.manifest_digest,
            "snapshot_digest": snapshot.snapshot_digest,
            "reconciliation_mode": "REQUIRED",
            "serving_promotion_requested": False,
        }
    )
    if receipt.snapshot_digest != snapshot.snapshot_digest:
        raise ValueError("handoff snapshot digest mismatch")
    return SnapshotImportHandoffV1(snapshot, discovery, request)
