"""Fixture-only unified-db snapshot export orchestration."""
from __future__ import annotations

from wiki_spike.applications.unified_db_export_authorization_verify import (
    VerifiedUnifiedDbExportAuthorityV1,
)
from wiki_spike.applications.unified_db_snapshot_export_reader import (
    StaticUnifiedDbFixtureReader,
)
from wiki_spike.applications.unified_db_snapshot_export_verify import (
    load_export_fixture,
    verify_export_package,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_snapshot_export import (
    FixtureExportAuthorityV1,
    PackageDurabilityUncertain,
    UnifiedDbExportError,
    UnifiedDbExportRowV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_bind import (
    build_bounded_snapshot,
    package_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export_bounds import (
    HARD_CAP,
    aggregate_export_bytes,
)
from wiki_spike.memory_core.unified_db_snapshot_export_cursors import (
    SnapshotCursorMapV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_evidence import (
    UnifiedDbExportEvidenceV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_manifest import PayloadManifestV1
from wiki_spike.memory_core.unified_db_snapshot_export_ports import (
    LocalSnapshotPackageWriterPort,
    UnifiedDbFixtureReadPort,
)
from wiki_spike.memory_core.unified_db_snapshot_export_profile import (
    UnifiedDbExportPlanV1,
    UnifiedDbExportProfileV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_proof import FixtureReadResultV1
from wiki_spike.memory_core.unified_db_snapshot_export_result import (
    UnifiedDbExportReceiptV1,
)

__all__ = (
    "StaticUnifiedDbFixtureReader",
    "UnifiedDbSnapshotExportService",
    "load_export_fixture",
    "verify_export_package",
)
_FILES = (
    ("bounded-snapshot.json", "snapshot"),
    ("payload-manifest.json", "manifest"),
    ("opening-proof.json", "opening"),
    ("closing-proof.json", "closing"),
    ("evidence.json", "evidence"),
)


class UnifiedDbSnapshotExportService:
    _reader: UnifiedDbFixtureReadPort
    _writer: LocalSnapshotPackageWriterPort

    def __init__(
        self,
        reader: UnifiedDbFixtureReadPort,
        writer: LocalSnapshotPackageWriterPort,
    ) -> None:
        self._reader = reader
        self._writer = writer

    def export_live(self, authority: object, dsn_fd: int | None = None) -> None:
        _ = dsn_fd
        if isinstance(authority, FixtureExportAuthorityV1):
            raise UnifiedDbExportError("fixture-only authority cannot call live export")
        if isinstance(authority, VerifiedUnifiedDbExportAuthorityV1):
            _ = authority.claim()
        raise UnifiedDbExportError(
            "live export refused: executable mapping and signed authority are absent"
        )

    def export_fixture(
        self,
        authority: object,
        profile: UnifiedDbExportProfileV1,
        plan: UnifiedDbExportPlanV1,
        destination: str,
    ) -> UnifiedDbExportReceiptV1:
        if not isinstance(authority, FixtureExportAuthorityV1):
            raise UnifiedDbExportError("fixture-only authority is required")
        if plan.profile_digest != profile.profile_digest:
            raise UnifiedDbExportError("plan is not bound to the export profile")
        if plan.expected_source_ids != profile.source_allowlist:
            raise UnifiedDbExportError("plan sources must equal the source allowlist")
        result = self._reader.read_fixture_rows(authority, plan, int(profile.max_records) + 1)
        if (
            result.fixture_id != plan.fixture_id
            or result.fixture_digest != plan.fixture_digest
            or result.row_set_digest != plan.row_set_digest
        ):
            raise UnifiedDbExportError("fixture substitution refused")
        self._validate_proofs(result, plan)
        self._validate_rows(result.rows, profile, result.cursors)
        snapshot, files = build_bounded_snapshot(result.rows, result.cursors)
        manifest = PayloadManifestV1.create(files)
        digest = package_digest(
            snapshot.snapshot_digest,
            files,
            profile.profile_digest,
            plan.plan_digest,
            manifest.manifest_digest,
            result.cursors.cursor_map_digest,
        )
        live_count = str(sum(1 for record in snapshot.records if not record.tombstone))
        tomb_count = str(sum(1 for record in snapshot.records if record.tombstone))
        byte_count = str(sum(len(content) for _name, content in files))
        evidence = UnifiedDbExportEvidenceV1.create(
            str(len(result.rows)),
            live_count,
            tomb_count,
            byte_count,
            snapshot.snapshot_digest,
            manifest.manifest_digest,
            result.cursors.cursor_map_digest,
            result.opening_proof.proof_digest,
            result.closing_proof.proof_digest,
            digest,
        )
        receipt = UnifiedDbExportReceiptV1.create(
            str(len(result.rows)),
            live_count,
            tomb_count,
            byte_count,
            snapshot.snapshot_digest,
            manifest.manifest_digest,
            result.cursors.cursor_map_digest,
            result.opening_proof.proof_digest,
            result.closing_proof.proof_digest,
            digest,
            profile.profile_digest,
            plan.plan_digest,
            evidence.evidence_digest,
        )
        payloads = {
            "snapshot": snapshot.to_mapping(),
            "manifest": manifest.to_mapping(),
            "opening": result.opening_proof.to_mapping(),
            "closing": result.closing_proof.to_mapping(),
            "evidence": evidence.to_mapping(),
        }
        staging: str | None = None
        try:
            staging = self._writer.start(destination)
            for relative, content in files:
                self._writer.write_file(staging, f"payload/{relative}", content)
            for name, key in _FILES:
                self._writer.write_file(staging, name, canonical_bytes(payloads[key]) + b"\n")
            self._writer.commit(
                staging,
                destination,
                "receipt.json",
                canonical_bytes(receipt.to_mapping()) + b"\n",
                receipt.receipt_digest,
            )
            staging = None
            return receipt
        except PackageDurabilityUncertain:
            staging = None
            raise
        finally:
            if staging is not None:
                self._writer.abort(staging)

    def _validate_proofs(self, result: FixtureReadResultV1, plan: UnifiedDbExportPlanV1) -> None:
        opening, closing = result.opening_proof, result.closing_proof
        if opening.phase != "OPENING" or closing.phase != "CLOSING":
            raise UnifiedDbExportError("read-safety proof phase mismatch")
        if opening.writer_count != "0" or closing.writer_count != "0":
            raise UnifiedDbExportError("zero writers are required")
        if (
            opening.db_commitment != plan.db_commitment
            or closing.db_commitment != plan.db_commitment
            or opening.catalog_commitment != plan.catalog_commitment
            or closing.catalog_commitment != plan.catalog_commitment
            or opening.source_commitment != plan.source_commitment
            or closing.source_commitment != plan.source_commitment
            or opening.data_root_commitment != plan.data_root_commitment
            or closing.data_root_commitment != plan.data_root_commitment
        ):
            raise UnifiedDbExportError("DB/catalog/source/data-root commitments changed")

    def _validate_rows(
        self,
        rows: tuple[UnifiedDbExportRowV1, ...],
        profile: UnifiedDbExportProfileV1,
        cursors: SnapshotCursorMapV1,
    ) -> None:
        if len(rows) > int(profile.max_records):
            raise UnifiedDbExportError("max_records exceeded")
        ordered = tuple(sorted(rows, key=lambda row: (row.source_id, row.native_id)))
        if rows != ordered:
            raise UnifiedDbExportError("rows are not in deterministic order")
        identities = tuple((row.source_id, row.native_id) for row in rows)
        if len(set(identities)) != len(identities):
            raise UnifiedDbExportError("identities must be unique")
        sources = {row.source_id for row in rows}
        if sources != set(profile.source_allowlist) or sources != set(cursors.as_dict()):
            raise UnifiedDbExportError("source allowlist mismatch")
        if aggregate_export_bytes(rows) > min(int(profile.max_aggregate_bytes), HARD_CAP):
            raise UnifiedDbExportError("aggregate bound exceeded")
        for row in rows:
            if row.tombstone:
                if row.body is not None:
                    raise UnifiedDbExportError("tombstones must be explicit and body-free")
                continue
            if row.body is None or len(row.body) > min(int(profile.max_record_bytes), HARD_CAP):
                raise UnifiedDbExportError("per-record bound exceeded")
