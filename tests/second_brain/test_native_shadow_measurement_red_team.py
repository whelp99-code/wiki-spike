from __future__ import annotations

import inspect
import json
import os
from hashlib import sha256
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from test_native_shadow_measurement import IndependentMonotonicTestAuthority, collector, contracts, d, signed_sample
from wiki_spike.applications import second_brain_shadow_measurement as measurement
from wiki_spike.applications.second_brain_shadow_measurement import AuthoritySnapshot, NativeShadowMeasurementCollector, ShadowMeasurementError
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes


def test_rejects_unified_db_roster_and_unsigned_raw_sample(tmp_path):
    scope, benchmark, holdout, slo = contracts()
    object.__setattr__(scope, "enabled_source_profiles", ("Codex", "Claude/Memory Bank", "Git", "unified-db"))
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ShadowMeasurementError, match="four-source roster"):
        NativeShadowMeasurementCollector(path=tmp_path/"state", authority=IndependentMonotonicTestAuthority(), scope=scope, benchmark=benchmark, holdout=holdout, slo=slo, measurement_public_key=key.public_key(), measurement_key_id="identity")

def test_split_journal_tail_is_quarantined_and_recovered_from_authority(tmp_path):
    value, key = collector(tmp_path, [datetime(2026, 1, 1, tzinfo=timezone.utc)])
    value.append(signed_sample(value, key, "one", "Codex"))
    segment = value._segments_path / "00000000000000000002.frame"
    segment.write_bytes(segment.read_bytes() + b"00000020\n{}")
    reopened = NativeShadowMeasurementCollector(
        path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
        holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
        measurement_key_id="measurement-1",
    )
    assert reopened._state["sample_count"] == 1
    assert list(reopened._segments_path.glob("*.incomplete"))

def test_retained_authority_recovers_a_coordinated_journal_rollback(tmp_path):
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    value, key = collector(tmp_path, now)
    value.append(signed_sample(value, key, "one", "Codex"))
    value.append(signed_sample(value, key, "two", "Git", safety_violation=True))

    # Replacing the mutable journal with an earlier valid prefix cannot erase a
    # failed/safety suffix: the independently retained authority replays it.
    (value._segments_path / "00000000000000000003.frame").unlink()
    reopened = NativeShadowMeasurementCollector(
        path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
        holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
        measurement_key_id="measurement-1",
    )
    assert reopened._state["sample_count"] == 2
    assert "safety violations exceed zero" in reopened.report().reasons

    # A root field cannot be rewritten even if the chain is otherwise untouched.
    checkpoint = value._segments_path / "00000000000000000001.frame"
    event = json.loads(checkpoint.read_bytes()[9:-1])
    event["root"]["anchor_root"] = d("rewritten")
    checkpoint.write_bytes(value._line(event))
    with pytest.raises(ShadowMeasurementError, match="disagrees|authentication"):
        NativeShadowMeasurementCollector(
            path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
            holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
            measurement_key_id="measurement-1",
        )

    second, _ = collector(tmp_path / "second", now)
    replay = signed_sample(value, key, "replayed", "Markdown")
    with pytest.raises(ShadowMeasurementError, match="cohort head"):
        second.append(replay)
def _history(*, count=800, duration_hours=72, outcome="valid", safety=False):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    root = {"started_at": start.isoformat().replace("+00:00", "Z")}
    entries = []
    for index in range(count):
        entries.append({"recorded_at": (start + timedelta(seconds=duration_hours * 3600 * index // max(count - 1, 1))).isoformat().replace("+00:00", "Z"),
                        "sample": {"source_profile": ("Codex", "Claude/Memory Bank", "Git", "Markdown")[index % 4],
                                   "outcome": outcome, "citation": outcome == "valid",
                                   "completeness": outcome == "valid", "parity": outcome == "valid",
                                   "safety_violation": safety}})
    return root, entries, start


@pytest.mark.parametrize(("count", "hours", "sample_outcome", "safety", "outcome"), [
    (800, 72, "valid", False, "EVIDENCE_COMPLETE_NON_SERVING"),
    (800, 71, "valid", False, "NOT_READY"),
    (499, 72, "valid", False, "NOT_READY"),
    (800, 72, "invalid", False, "NOT_READY"),
    (800, 72, "abstained", False, "NOT_READY"),
    (800, 72, "source-unavailable", False, "NOT_READY"),
    (800, 72, "valid", True, "NOT_READY"),
])
def test_pure_metric_evaluator_acceptance_denominators_and_safety_edges(count, hours, sample_outcome, safety, outcome):
    root, entries, start = _history(count=count, duration_hours=hours, outcome=sample_outcome, safety=safety)
    metrics = measurement._evaluate_history_metrics(
        root=root, entries=entries, slo=contracts()[3], evaluated_at=start + timedelta(hours=72)
    )
    assert metrics.sample_count == count
    assert (not metrics.reasons) == (outcome == "EVIDENCE_COMPLETE_NON_SERVING")
    assert not hasattr(metrics, "outcome")
def test_completion_cannot_be_minted_by_a_public_time_or_history_seam():
    assert "evaluate_authenticated_history" not in measurement.__all__
    assert not hasattr(measurement, "evaluate_authenticated_history")
    assert tuple(inspect.signature(NativeShadowMeasurementCollector.report).parameters) == ("self",)



class _FaultSnapshotAuthority(IndependentMonotonicTestAuthority):
    def __init__(self, mutate):
        super().__init__(); self._mutate = mutate

    def snapshot(self, *, request_nonce):
        return self._mutate(super().snapshot(request_nonce=request_nonce))


class _MutablePinAuthority(IndependentMonotonicTestAuthority):
    def __init__(self):
        super().__init__()
        self._endpoint = "https://authority.test/native-shadow"
        self._policy_id = "retention-immutable-v1"

    @property
    def endpoint(self):
        return self._endpoint

    @property
    def policy_id(self):
        return self._policy_id

    def rotate(self, field):
        if field == "identity":
            self._identity = "rotated-authority"
        elif field == "endpoint":
            self._endpoint = "https://rotated.test/native-shadow"
        elif field == "policy_id":
            self._policy_id = "retention-rotated-v1"
        elif field == "public_key":
            self._key = Ed25519PrivateKey.generate()
        else:
            raise AssertionError(field)
    def compare_and_advance(self, *, expected_revision, event, request_nonce):
        receipt = super().compare_and_advance(
            expected_revision=expected_revision, event=event, request_nonce=request_nonce,
        )
        field = getattr(self, "rotate_during_cas", None)
        if field:
            self.rotate(field)
        return receipt


@pytest.mark.parametrize("field", ("identity", "endpoint", "policy_id", "public_key"))
def test_snapshot_rejects_live_authority_pin_rotation(tmp_path, field):
    authority = _MutablePinAuthority()
    value, _ = collector(tmp_path, [datetime(2026, 1, 1, tzinfo=timezone.utc)], authority)
    authority.rotate(field)
    with pytest.raises(ShadowMeasurementError, match="pins changed"):
        value.report()


@pytest.mark.parametrize("field", ("identity", "endpoint", "policy_id", "public_key"))
def test_compare_and_advance_rejects_live_authority_pin_rotation(tmp_path, field):
    authority = _MutablePinAuthority()
    value, key = collector(tmp_path, [datetime(2026, 1, 1, tzinfo=timezone.utc)], authority)
    authority.rotate_during_cas = field
    with pytest.raises(ShadowMeasurementError, match="pins changed"):
        value.append(signed_sample(value, key, "one", "Codex"))


@pytest.mark.parametrize("mutate", [
    lambda receipt: replace(receipt, identity="other"),
    lambda receipt: replace(receipt, endpoint="https://other.test"),
    lambda receipt: replace(receipt, policy_id="other-policy"),
    lambda receipt: replace(receipt, public_key_fingerprint=d("other-key")),
    lambda receipt: replace(receipt, request_nonce="replayed"),
    lambda receipt: replace(receipt, issued_at="2020-01-01T00:00:00Z"),
    lambda receipt: replace(receipt, revision=1),
    lambda receipt: replace(receipt, root=d("wrong-root")),
    lambda receipt: replace(receipt, signature="00"),
])
def test_snapshot_authority_receipt_faults_are_fail_closed(tmp_path, mutate):
    scope, benchmark, holdout, slo = contracts()
    with pytest.raises(ShadowMeasurementError):
        NativeShadowMeasurementCollector(
            path=tmp_path / "state", authority=_FaultSnapshotAuthority(mutate), scope=scope,
            benchmark=benchmark, holdout=holdout, slo=slo,
            measurement_public_key=Ed25519PrivateKey.generate().public_key(), measurement_key_id="identity"
        )


class _FaultCasAuthority(IndependentMonotonicTestAuthority):
    def compare_and_advance(self, *, expected_revision, event, request_nonce):
        receipt = super().compare_and_advance(
            expected_revision=expected_revision, event=event, request_nonce=request_nonce
        )
        return replace(receipt, revision=expected_revision)


def test_compare_and_advance_receipt_requires_atomic_signed_append_before_cache(tmp_path):
    scope, benchmark, holdout, slo = contracts()
    key = Ed25519PrivateKey.generate()
    authority = _FaultCasAuthority()
    value = NativeShadowMeasurementCollector(
        path=tmp_path / "state", authority=authority, scope=scope, benchmark=benchmark,
        holdout=holdout, slo=slo, measurement_public_key=key.public_key(), measurement_key_id="identity"
    )
    root = value.checkpoint_payload(cohort_id="00000000-0000-0000-0000-000000000001",
                                    started_at=datetime(2026, 1, 1, tzinfo=timezone.utc), anchor_root=d("anchor"))
    with pytest.raises(ShadowMeasurementError):
        value.establish_checkpoint(
            cohort_id=root["cohort_id"], started_at=root["started_at"], anchor_root=root["anchor_root"],
            root_signature=key.sign(
                canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)
            ).hex()
        )
    assert not hasattr(value, "_authority_receipt") or value._authority_receipt.revision == 0
def _evaluated(*, count=800, duration_hours=72, slo=None, mutate=None):
    root, entries, start = _history(count=count, duration_hours=duration_hours)
    if mutate:
        mutate(entries)
    return measurement._evaluate_history_metrics(
        root=root, entries=entries, slo=slo or contracts()[3],
        evaluated_at=start + timedelta(hours=72),
    )


@pytest.mark.parametrize(("hours", "reason"), [
    (72, None),
    (71, "continuous measurement is below the required duration"),
])
def test_exact_continuous_72_hour_boundary(hours, reason):
    metrics = _evaluated(duration_hours=hours)
    assert (reason in metrics.reasons) if reason else not metrics.reasons


@pytest.mark.parametrize(("count", "reason"), [
    (500, None),
    (499, "cohort E2E denominator is below its floor"),
])
def test_exact_total_denominator_boundary_with_source_floors_already_passing(count, reason):
    slo = replace(contracts()[3], min_parity_cases_per_source=1)
    metrics = _evaluated(count=count, slo=slo)
    assert (reason in metrics.reasons) if reason else not metrics.reasons


@pytest.mark.parametrize(("source_count", "reason"), [
    (200, None),
    (199, "Codex parity denominator is below its floor"),
])
def test_each_source_exact_parity_floor_with_total_already_passing(source_count, reason):
    root, entries, start = _history()
    for index, entry in enumerate(entries):
        entry["sample"]["source_profile"] = "Codex" if index < source_count else (
            "Claude/Memory Bank" if index % 3 == 0 else "Git" if index % 3 == 1 else "Markdown"
        )
    metrics = measurement._evaluate_history_metrics(
        root=root, entries=entries, slo=contracts()[3],
        evaluated_at=start + timedelta(hours=72),
    )
    assert (reason in metrics.reasons) if reason else not metrics.reasons


@pytest.mark.parametrize("metric", ("parity", "citation", "completeness", "availability"))
def test_wilson_threshold_immediately_at_pass_and_above_fail(metric):
    root, entries, start = _history()
    total = 200 if metric == "parity" else 800
    lower_bps = int(measurement._wilson_lower(total, total) * 10000)
    for threshold, expected_reason in (
        (lower_bps, None),
        (lower_bps + 1, f"{'Codex ' if metric == 'parity' else ''}{metric} lower bound failed"),
    ):
        slo = replace(contracts()[3], **{f"{metric}_min_bps": threshold})
        metrics = measurement._evaluate_history_metrics(
            root=root, entries=entries, slo=slo,
            evaluated_at=start + timedelta(hours=72),
        )
        assert (expected_reason in metrics.reasons) if expected_reason else not metrics.reasons


def test_mixed_outcomes_remain_in_every_enabled_denominator():
    root, entries, start = _history()
    for entry, outcome in zip(entries[-4:], ("invalid", "abstained", "source-unavailable", "valid")):
        entry["sample"].update(outcome=outcome, citation=outcome == "valid",
                               completeness=outcome == "valid", parity=outcome == "valid")
    threshold = int(measurement._wilson_lower(797, 800) * 10000) + 1
    metrics = measurement._evaluate_history_metrics(
        root=root, entries=entries, slo=replace(contracts()[3], citation_min_bps=threshold),
        evaluated_at=start + timedelta(hours=72),
    )
    assert "citation lower bound failed" in metrics.reasons
    assert metrics.sample_count == 800


@pytest.mark.parametrize(("violations", "reason"), [
    (0, None),
    (1, "safety violations exceed zero"),
])
def test_safety_exact_zero_vs_one_boundary(violations, reason):
    metrics = _evaluated(mutate=lambda entries: entries[-1]["sample"].update(
        safety_violation=violations == 1))
    assert (reason in metrics.reasons) if reason else not metrics.reasons


def _resign(authority, receipt, **changes):
    unsigned = receipt.payload() | changes
    return AuthoritySnapshot(**unsigned, signature=authority._key.sign(
        canonical_ledger_bytes("second-brain-native-shadow-authority-v1", unsigned)).hex())


class _ResignedFaultAuthority(IndependentMonotonicTestAuthority):
    def __init__(self, fault):
        super().__init__(); self.fault = fault

    def snapshot(self, *, request_nonce):
        receipt = super().snapshot(request_nonce=request_nonce)
        return self.fault(self, receipt)


@pytest.mark.parametrize(("name", "fault", "reason"), [
    ("identity", lambda a, r: _resign(a, r, identity="semantic-other"), "identity, endpoint, policy, or key mismatch"),
    ("endpoint", lambda a, r: _resign(a, r, endpoint="https://semantic-other.test"), "identity, endpoint, policy, or key mismatch"),
    ("policy", lambda a, r: _resign(a, r, policy_id="semantic-other-policy"), "identity, endpoint, policy, or key mismatch"),
    ("public_key", lambda a, r: _resign(a, r, public_key_fingerprint=d("semantic-other-key")), "identity, endpoint, policy, or key mismatch"),
    ("root", lambda a, r: _resign(a, r, root=d("semantic-root")), "root is invalid"),
    ("revision", lambda a, r: _resign(a, r, revision=r.revision + 1), "revision is invalid"),
    ("freshness", lambda a, r: _resign(a, r, issued_at="2020-01-01T00:00:00Z",
                                        expires_at="2020-01-01T00:01:00Z"), "stale"),
    ("nonce", lambda a, r: _resign(a, r, request_nonce="semantic-replay"), "nonce is invalid or replayed"),
])
def test_resigned_snapshot_field_faults_fail_for_semantics(tmp_path, name, fault, reason):
    scope, benchmark, holdout, slo = contracts()
    with pytest.raises(ShadowMeasurementError, match=reason):
        NativeShadowMeasurementCollector(
            path=tmp_path / name, authority=_ResignedFaultAuthority(fault), scope=scope,
            benchmark=benchmark, holdout=holdout, slo=slo,
            measurement_public_key=Ed25519PrivateKey.generate().public_key(), measurement_key_id="identity",
        )


def test_resigned_event_and_prefix_faults_are_detected_as_authority_rollbacks(tmp_path):
    authority = IndependentMonotonicTestAuthority()
    value, key = collector(tmp_path, [datetime(2026, 1, 1, tzinfo=timezone.utc)], authority)
    value.append(signed_sample(value, key, "one", "Codex"))
    value.append(signed_sample(value, key, "two", "Git"))

    for field in ("event", "prefix"):
        class FaultAuthority(IndependentMonotonicTestAuthority):
            pass
        authority.snapshot = (lambda original, field=field: lambda *, request_nonce: (
            _resign(authority, original(request_nonce=request_nonce),
                    events=[dict(event) | ({"kind": "tampered"} if field == "event" and index == 2
                                           else {"entry": {"tampered": True}} if field == "prefix" and index == 0
                                           else {}) for index, event in enumerate(
                        original(request_nonce=request_nonce).events)])
        ))(authority.snapshot)
        with pytest.raises(ShadowMeasurementError, match="root is invalid|rollback"):
            value.report()
        authority.snapshot = IndependentMonotonicTestAuthority.snapshot.__get__(authority)
def test_cas_boundary_race_preserves_exact_authoritative_prefix(tmp_path):
    class CasBoundaryRaceAuthority(IndependentMonotonicTestAuthority):
        def __init__(self, competing_event):
            super().__init__()
            self._competing_event = competing_event
            self.armed = False
            self.attempted_expected_revisions = []
            self.rejected_revision_mismatches = []

        def compare_and_advance(self, *, expected_revision, event, request_nonce):
            if not self.armed:
                return super().compare_and_advance(
                    expected_revision=expected_revision, event=event, request_nonce=request_nonce
                )
            self.attempted_expected_revisions.append(expected_revision)
            if len(self._events) == expected_revision:
                super().compare_and_advance(
                    expected_revision=expected_revision,
                    event=self._competing_event(event),
                    request_nonce="injected-authority-advance",
                )
            try:
                return super().compare_and_advance(
                    expected_revision=expected_revision, event=event, request_nonce=request_nonce
                )
            except RuntimeError as exc:
                self.rejected_revision_mismatches.append((expected_revision, len(self._events)))
                raise exc

    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]

    def competing_event(stale_event):
        event = json.loads(json.dumps(stale_event))
        sample = event["entry"]["sample"]
        sample["sample_id"] = "authoritative"
        sample["source_profile"] = "Git"
        unsigned = dict(sample)
        del unsigned["signature"]
        sample["signature"] = key.sign(canonical_ledger_bytes(measurement.DOMAIN, unsigned)).hex()
        entry = event["entry"]
        entry["digest"] = sha256(canonical_ledger_bytes(
            "second-brain-native-shadow-chain-v1",
            {field: entry[field] for field in ("sample", "recorded_at", "previous")},
        )).hexdigest()
        return event

    authority = CasBoundaryRaceAuthority(competing_event)
    first, key = collector(tmp_path, now, authority)
    authority.armed = True
    with pytest.raises(RuntimeError, match="stale authority version"):
        first.append(signed_sample(first, key, "stale", "Codex"))

    assert authority.attempted_expected_revisions == [1]
    assert authority.rejected_revision_mismatches == [(1, 2)]
    authority_prefix = authority.snapshot(request_nonce="reopen")
    assert authority_prefix.revision == 2
    assert authority_prefix.events[-1]["entry"]["sample"]["sample_id"] == "authoritative"

    reopened = NativeShadowMeasurementCollector(
        path=first.path, authority=authority, scope=first.scope, benchmark=first.benchmark,
        holdout=first.holdout, slo=first.slo, measurement_public_key=key.public_key(),
        measurement_key_id="measurement-1",
    )
    assert reopened._state["sample_count"] == 1
    assert reopened._state["samples"][0]["sample"]["sample_id"] == "authoritative"
    recovered_prefix = authority.snapshot(request_nonce="verify")
    assert recovered_prefix.events == authority_prefix.events

@pytest.mark.parametrize("stage", ("authority_advance", "segment_write", "file_fsync", "directory_fsync"))
def test_commit_faults_leave_a_restartable_authority_backed_journal(tmp_path, monkeypatch, stage):
    now = [datetime(2026, 1, 1, tzinfo=timezone.utc)]
    value, key = collector(tmp_path, now)
    original_advance = value.authority.compare_and_advance
    original_segment = value._append_segment
    original_fsync = os.fsync
    original_directory = value._fsync_segments_directory

    if stage == "authority_advance":
        monkeypatch.setattr(value.authority, "compare_and_advance",
                            lambda **kwargs: (_ for _ in ()).throw(OSError("authority advance fault")))
    elif stage == "segment_write":
        monkeypatch.setattr(value, "_append_segment",
                            lambda *args: (_ for _ in ()).throw(OSError("segment write fault")))
    elif stage == "file_fsync":
        monkeypatch.setattr(os, "fsync",
                            lambda descriptor: (_ for _ in ()).throw(OSError("file fsync fault")))
    else:
        monkeypatch.setattr(value, "_fsync_segments_directory",
                            lambda: (_ for _ in ()).throw(OSError("directory fsync fault")))

    with pytest.raises(OSError, match=stage.replace("_", " ")):
        value.append(signed_sample(value, key, stage, "Codex"))

    monkeypatch.setattr(value.authority, "compare_and_advance", original_advance)
    monkeypatch.setattr(value, "_append_segment", original_segment)
    monkeypatch.setattr(os, "fsync", original_fsync)
    monkeypatch.setattr(value, "_fsync_segments_directory", original_directory)
    reopened = NativeShadowMeasurementCollector(
        path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
        holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
        measurement_key_id="measurement-1",
    )
    assert reopened._state["sample_count"] == (0 if stage == "authority_advance" else 1)


def test_quarantine_rename_fault_keeps_torn_segment_for_a_retryable_restart(tmp_path, monkeypatch):
    value, key = collector(tmp_path, [datetime(2026, 1, 1, tzinfo=timezone.utc)])
    value.append(signed_sample(value, key, "one", "Codex"))
    segment = value._segments_path / "00000000000000000002.frame"
    segment.write_bytes(segment.read_bytes() + b"00000020\n{}")
    monkeypatch.setattr(os, "replace", lambda *_: (_ for _ in ()).throw(OSError("quarantine rename fault")))
    with pytest.raises(ShadowMeasurementError, match="cannot be quarantined"):
        NativeShadowMeasurementCollector(
            path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
            holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
            measurement_key_id="measurement-1",
        )
    monkeypatch.undo()
    reopened = NativeShadowMeasurementCollector(
        path=value.path, authority=value.authority, scope=value.scope, benchmark=value.benchmark,
        holdout=value.holdout, slo=value.slo, measurement_public_key=key.public_key(),
        measurement_key_id="measurement-1",
    )
    assert reopened._state["sample_count"] == 1
