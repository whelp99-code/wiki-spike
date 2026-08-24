"""Task 48A: unsigned certified-cohort roster fixture contracts."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.test_native_shadow_measurement import (
    IndependentMonotonicTestAuthority,
    contracts,
    d,
    signed_sample,
)
from tests.second_brain.test_native_shadow_measurement_cli import (
    FixtureRetentionAuthority,
    write_contracts,
)
from wiki_spike.applications.second_brain_shadow_measurement import (
    NativeShadowMeasurementCollector,
    ShadowMeasurementError,
)
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    CERTIFIED_COHORT_ROSTER_FIXTURE_V1,
    CertifiedCohortRosterFixtureV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_bytes,
    canonical_ledger_digest,
)
from wiki_spike.composition.second_brain_shadow_measurement import open_measurement


def _fixture(*, enabled: bool = True) -> dict[str, object]:
    receipt = {
        "import_receipt_digest": d("fixture-import"),
        "receipt_version": "second-brain-certified-cohort-receipt-v1",
        "result": "PASS",
        "workspace_ref": "workspace:native",
    }
    receipt["receipt_sha256"] = canonical_ledger_digest("certified-cohort-receipt-v1", receipt)
    return {
        "fixture_version": CERTIFIED_COHORT_ROSTER_FIXTURE_V1,
        "cohort_receipt": receipt,
        "source_roster": [
            {"source_profile": "Codex", "enabled": enabled},
            {"source_profile": "Claude/Memory Bank", "enabled": True},
            {"source_profile": "Git", "enabled": True},
            {"source_profile": "Markdown", "enabled": True},
        ],
    }


def test_unsigned_fixture_is_body_free_and_rejects_disabled_or_tampered_rosters() -> None:
    fixture = CertifiedCohortRosterFixtureV1.from_mapping(_fixture())
    assert fixture.source_roster == ("Codex", "Claude/Memory Bank", "Git", "Markdown")
    assert fixture.cohort_receipt_sha256 == _fixture()["cohort_receipt"]["receipt_sha256"]
    with pytest.raises(Exception, match="disabled"):
        CertifiedCohortRosterFixtureV1.from_mapping(_fixture(enabled=False))
    tampered = _fixture()
    receipt = tampered["cohort_receipt"]
    assert isinstance(receipt, dict)
    receipt["workspace_ref"] = "workspace:other"
    with pytest.raises(Exception, match="digest"):
        CertifiedCohortRosterFixtureV1.from_mapping(tampered)


def test_collector_uses_the_pinned_roster_for_sample_admission(tmp_path) -> None:
    scope, benchmark, holdout, slo = contracts()
    object.__setattr__(scope, "enabled_source_profiles", ("Codex", "Git"))
    key = Ed25519PrivateKey.generate()
    collector = NativeShadowMeasurementCollector(
        path=tmp_path / "state", authority=IndependentMonotonicTestAuthority(), scope=scope,
        benchmark=benchmark, holdout=holdout, slo=slo, measurement_public_key=key.public_key(),
        measurement_key_id="fixture", source_roster=("Codex", "Git"),
    )
    root = collector.checkpoint_payload(
        cohort_id=str(uuid4()), started_at=datetime(2026, 1, 1, tzinfo=UTC), anchor_root=d("anchor"),
    )
    collector.establish_checkpoint(
        cohort_id=root["cohort_id"], started_at=root["started_at"], anchor_root=root["anchor_root"],
        root_signature=key.sign(canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)).hex(),
    )
    rejected = signed_sample(collector, key, "not-in-roster", "Markdown")
    with pytest.raises(ShadowMeasurementError, match="source or outcome"):
        collector.append(rejected)


def test_composition_binds_scope_and_source_manifest_to_fixture_roster(tmp_path) -> None:
    _, fingerprint = write_contracts(tmp_path)
    roster_path = tmp_path / "certified-cohort-roster.json"
    roster_path.write_text(json.dumps(_fixture()))
    (tmp_path / "bound.json.segments").mkdir()
    collector = open_measurement(
        db=tmp_path / "bound.json", authority=FixtureRetentionAuthority(),
        measurement_public_key=tmp_path / "key.pub", measurement_key_fingerprint=fingerprint,
        resolved_scope=tmp_path / "scope.json", contract=tmp_path / "contract.json",
        source_manifest=tmp_path / "source.json", capability_manifest=tmp_path / "capability.json",
        benchmark_manifest=tmp_path / "benchmark.json", holdout_manifest=tmp_path / "holdout.json",
        certified_cohort_roster=roster_path,
    )
    assert collector._source_roster == ("Codex", "Claude/Memory Bank", "Git", "Markdown")
