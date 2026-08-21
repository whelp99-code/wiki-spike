from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.applications.second_brain_shadow_measurement import (
    DOMAIN,
    AuthoritySnapshot,
    MonotonicAppendAuthority,
    NativeShadowMeasurementCollector,
    ShadowMeasurementError,
)
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BenchmarkManifestV1,
    HoldoutManifestV1,
    RecallSloV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_bytes,
    canonical_ledger_digest,
)

type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]

type Contracts = tuple[ResolvedScopeV1, BenchmarkManifestV1, HoldoutManifestV1, RecallSloV1]
type CollectorFixture = tuple[NativeShadowMeasurementCollector, Ed25519PrivateKey]

_CHAIN_DOMAIN = "second-brain-native-shadow-chain-v1"


def d(value: str) -> str: return sha256(value.encode()).hexdigest()
def ref(kind: str) -> str: return f"{kind}:native"

class IndependentMonotonicTestAuthority:
    """Deterministic authenticated stand-in for an operator-bound authority."""

    def __init__(self, identity: str = "test-retained-authority") -> None:
        self._identity: str = identity
        self._events: list[dict[str, JsonValue]] = []
        self._key: Ed25519PrivateKey = Ed25519PrivateKey.generate()

    @property
    def identity(self) -> str:
        return self._identity

    @property
    def endpoint(self) -> str:
        return "https://authority.test/native-shadow"

    @property
    def policy_id(self) -> str:
        return "retention-immutable-v1"

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def seed_event(self, event: Mapping[str, JsonValue]) -> None:
        self._events.append(dict(deepcopy(event)))

    def _snapshot(self, nonce: str) -> AuthoritySnapshot:
        events = tuple(deepcopy(self._events))
        root = sha256(canonical_ledger_bytes(
            "second-brain-native-shadow-authority-v1",
            {"events": [dict(event) for event in events]},
        )).hexdigest()
        issued = datetime.now(UTC)
        payload: dict[str, JsonValue] = {
            "identity": self.identity, "endpoint": self.endpoint,
            "policy_id": self.policy_id,
            "public_key_fingerprint": sha256(
                self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).hexdigest(),
            "revision": len(events), "root": root, "request_nonce": nonce,
            "issued_at": issued.isoformat().replace("+00:00", "Z"),
            "expires_at": (issued + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "events": [dict(event) for event in events],
        }
        return AuthoritySnapshot(
            identity=self.identity,
            endpoint=self.endpoint,
            policy_id=self.policy_id,
            public_key_fingerprint=sha256(
                self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).hexdigest(),
            revision=len(events),
            root=root,
            request_nonce=nonce,
            issued_at=issued.isoformat().replace("+00:00", "Z"),
            expires_at=(issued + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            events=events,
            signature=self._key.sign(
                canonical_ledger_bytes("second-brain-native-shadow-authority-v1", payload)
            ).hex(),
        )

    def snapshot(self, *, request_nonce: str) -> AuthoritySnapshot:
        return self._snapshot(request_nonce)

    def compare_and_advance(
        self,
        *,
        expected_revision: int,
        event: Mapping[str, JsonValue],
        request_nonce: str,
    ) -> AuthoritySnapshot:
        if expected_revision != len(self._events):
            raise RuntimeError("stale authority version")
        self._events.append(dict(deepcopy(event)))
        return self._snapshot(request_nonce)


def contracts() -> Contracts:
    scope = ResolvedScopeV1.from_mapping({"scope_version":"second-brain-resolved-scope-v1","enabled_source_profiles":["Claude/Memory Bank","Codex","Git","Markdown"],"disabled_source_profiles":{},"enabled_migration_sources":[],"disabled_migration_sources":{},"feature_flags":[],"egress_destinations":[],"enabled_external_model_routes":[],"disabled_external_model_routes":{},"disabled_export_destinations":{},"capability_manifest_digest":d("cap"),"source_manifest_digest":d("source"),"mandatory_release_constraints":["signed-release-baseline"]})
    bench_body={"manifest_version":"second-brain-benchmark-manifest-v1","workspace_ref":ref("workspace"),"corpus_key_ref":ref("key"),"capability_ref":ref("capability"),"item_digests":[d("b")],"label_review_digest":d("labels"),"consent_digest":d("consent")}
    bench=BenchmarkManifestV1.from_mapping(bench_body|{"manifest_digest":canonical_ledger_digest("benchmark-manifest-v1",bench_body)})
    hold_body={"manifest_version":"second-brain-holdout-manifest-v1","workspace_ref":ref("workspace"),"holdout_key_ref":"key:holdout","capability_ref":"capability:holdout","item_digests":[d("h")],"separation_digest":d("separation")}
    hold=HoldoutManifestV1.from_mapping(hold_body|{"manifest_digest":canonical_ledger_digest("holdout-manifest-v1",hold_body)})
    slo_body={"slo_version":"second-brain-recall-slo-v1","parity_min_bps":1,"citation_min_bps":1,"completeness_min_bps":1,"availability_min_bps":1,"max_safety_violations":0,"min_shadow_days":1,"min_parity_cases_per_source":200,"min_cohort_e2e_queries":500,"confidence_method":"one-sided-wilson-95","include_invalid_in_denominator":True,"include_abstained_in_denominator":True,"include_source_unavailable_in_denominator":True}
    slo=RecallSloV1.from_mapping(slo_body|{"slo_digest":canonical_ledger_digest("recall-slo-v1",slo_body)})
    return scope, bench, hold, slo


def collector(
    tmp_path: Path,
    authority: MonotonicAppendAuthority | None = None,
) -> CollectorFixture:
    scope, bench, hold, slo = contracts(); key = Ed25519PrivateKey.generate()
    authority = authority or IndependentMonotonicTestAuthority()
    value=NativeShadowMeasurementCollector(path=tmp_path/"state.json",authority=authority,scope=scope,benchmark=bench,holdout=hold,slo=slo,measurement_public_key=key.public_key(),measurement_key_id="measurement-1")
    start = datetime(2026, 1, 1, tzinfo=UTC)
    root = cast(
        dict[str, JsonValue],
        value.checkpoint_payload(cohort_id=str(uuid4()), started_at=start, anchor_root=d("anchor")),
    )
    cohort_id = root["cohort_id"]
    assert isinstance(cohort_id, str)
    value.establish_checkpoint(cohort_id=cohort_id, started_at=start, anchor_root=d("anchor"), root_signature=key.sign(canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)).hex())
    return value, key


def signed_sample(
    collector: NativeShadowMeasurementCollector,
    key: Ed25519PrivateKey,
    sample_id: str,
    source: str,
    outcome: str = "valid",
    **measures: bool,
) -> dict[str, JsonValue]:
    """Build a sample the collector will accept for its next append."""
    state = collector._state
    assert state is not None
    raw: dict[str, JsonValue] = {
        "sample_version": "second-brain-native-shadow-sample-v1",
        "sample_id": sample_id,
        "source_profile": source,
        "outcome": outcome,
        "citation": measures.get("citation", True),
        "completeness": measures.get("completeness", True),
        "parity": measures.get("parity", True),
        "safety_violation": measures.get("safety_violation", False),
        "cohort_digest": collector.cohort_digest,
        "previous": state["chain_head"],
        "sequence": state["sample_count"],
    }
    raw["signature"] = key.sign(canonical_ledger_bytes(DOMAIN, raw)).hex()
    return raw


def test_signed_samples_require_real_wall_clock_and_raw_denominators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authority = IndependentMonotonicTestAuthority()
    value, key = collector(tmp_path, authority)
    previous: str | None = None
    recorded_at = datetime.now(UTC) - timedelta(seconds=2)
    for index in range(800):
        source = ("Codex", "Claude/Memory Bank", "Git", "Markdown")[index % 4]
        sample: dict[str, JsonValue] = {
            "sample_version": "second-brain-native-shadow-sample-v1",
            "sample_id": str(index),
            "source_profile": source,
            "outcome": "valid",
            "citation": True,
            "completeness": True,
            "parity": True,
            "safety_violation": False,
            "cohort_digest": value.cohort_digest,
            "previous": previous,
            "sequence": index,
        }
        sample["signature"] = key.sign(canonical_ledger_bytes(DOMAIN, sample)).hex()
        entry: dict[str, JsonValue] = {
            "sample": sample,
            "recorded_at": (
                recorded_at + timedelta(milliseconds=index + 1)
            ).isoformat().replace("+00:00", "Z"),
            "previous": previous,
        }
        entry["digest"] = canonical_ledger_digest(_CHAIN_DOMAIN, entry)
        authority.seed_event({"kind": "append", "entry": entry})
        previous = entry["digest"]

    def skip_segment_mirror(
        _collector: NativeShadowMeasurementCollector,
        _revision: int,
        _event: Mapping[str, object],
    ) -> None:
        return None

    monkeypatch.setattr(
        NativeShadowMeasurementCollector,
        "_append_segment",
        skip_segment_mirror,
    )
    # Fast local appends cannot synthesize the real continuous one-day window.
    assert value.report().outcome == "NOT_READY"


def test_checkpoint_is_required_and_is_signed(tmp_path: Path) -> None:
    scope, bench, hold, slo = contracts(); key = Ed25519PrivateKey.generate()
    value=NativeShadowMeasurementCollector(path=tmp_path/"state",authority=IndependentMonotonicTestAuthority(),scope=scope,benchmark=bench,holdout=hold,slo=slo,measurement_public_key=key.public_key(),measurement_key_id="identity")
    with pytest.raises(ShadowMeasurementError, match="authority is empty"):
        _ = value.report()
    with pytest.raises(ShadowMeasurementError, match="signature"):
        value.establish_checkpoint(cohort_id=str(uuid4()), started_at=datetime(2026,1,1,tzinfo=UTC), anchor_root=d("a"), root_signature="00")
