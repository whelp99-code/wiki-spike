from __future__ import annotations

import json
import runpy
from hashlib import sha256
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.applications.second_brain_shadow_measurement import AuthoritySnapshot
from wiki_spike.applications.second_brain_shadow_measurement import NativeShadowMeasurementCollector
from wiki_spike.infrastructure.second_brain_monotonic_append_authority import (
    RECEIPT_SCHEMA,
    EVIDENCE_SCHEMA,
    DeploymentAuthorityEvidence,
    DeploymentMonotonicAppendAuthority,
    write_live_operation_denial_receipt,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import BenchmarkManifestV1, HoldoutManifestV1, RecallSloV1
from test_native_shadow_measurement_cli import CLI, command, write_contracts


def authority(tmp_path, *, binding="b" * 64, trusted_clock=None):
    trusted_clock = trusted_clock or (lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    key = Ed25519PrivateKey.generate()
    fingerprint = sha256(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
    evidence = DeploymentAuthorityEvidence(
        identity="deploy:shadow", endpoint="retention-authority://shadow-deploy",
        policy_id="shadow-retention-v1", measurement_binding=binding,
        public_key_fingerprint=fingerprint,
    )
    subject = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "authority.json", evidence=evidence, signing_key=key,
        snapshot_factory=AuthoritySnapshot, trusted_clock=trusted_clock,
    )
    subject.verify_deployment_evidence(signed_evidence(subject, key, binding=binding), measurement_binding=binding)
    return subject, key


def signed_evidence(subject, key, *, binding="b" * 64, revision=0, root=None, now=None):
    now = now or subject._trusted_clock()
    root = root or sha256(canonical_ledger_bytes("second-brain-native-shadow-authority-v1", {"events": []})).hexdigest()
    body = {
        "evidence_version": EVIDENCE_SCHEMA, "identity": subject.identity, "endpoint": subject.endpoint,
        "policy_id": subject.policy_id, "public_key_fingerprint": sha256(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest(),
        "measurement_binding": binding, "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "authority_revision": revision,
        "authority_root": root,
    }
    return body | {"signature": key.sign(canonical_ledger_bytes(EVIDENCE_SCHEMA, body)).hex()}


def test_authority_signs_nonce_bound_monotonic_snapshots_and_persists_canonical_state(tmp_path):
    subject, key = authority(tmp_path)
    initial = subject.snapshot(request_nonce="a" * 64)
    assert initial.revision == 0 and initial.events == ()
    advanced = subject.compare_and_advance(
        expected_revision=0, event={"kind": "checkpoint", "root": "x"}, request_nonce="b" * 64,
    )
    assert advanced.revision == 1
    assert {key: value for key, value in advanced.events[0].items() if key != "recorded_at"} == {
        "kind": "checkpoint", "root": "x",
    }
    assert advanced.events[0]["recorded_at"].endswith("Z")
    key.public_key().verify(bytes.fromhex(advanced.signature), canonical_ledger_bytes(
        "second-brain-native-shadow-authority-v1", advanced.payload(),
    ))
    state = json.loads((tmp_path / "authority.json").read_text())
    assert json.dumps(state, sort_keys=True, separators=(",", ":")).encode() == (tmp_path / "authority.json").read_bytes()
    assert state["measurement_binding"] == "b" * 64


def test_denial_receipt_is_closed_canonical_hash_bound_and_contains_no_event_payload(tmp_path):
    subject, _ = authority(tmp_path)
    subject.compare_and_advance(expected_revision=0, event={"raw": "must-not-leak"}, request_nonce="a" * 64)
    receipt = write_live_operation_denial_receipt(path=tmp_path / "receipt.json", authority=subject, operation="append")
    assert set(receipt) == {
        "receipt_version", "identity", "endpoint", "policy_id", "public_key_fingerprint",
        "measurement_binding", "authority_revision", "authority_root", "operation",
        "live_operation_authorized", "receipt_digest",
    }
    assert receipt["receipt_version"] == RECEIPT_SCHEMA
    assert receipt["live_operation_authorized"] is False
    assert "raw" not in json.dumps(receipt)
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    assert receipt["receipt_digest"] == sha256(canonical_ledger_bytes(RECEIPT_SCHEMA, body)).hexdigest()
    assert json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() == (tmp_path / "receipt.json").read_bytes()


def test_evidence_is_closed_signed_fresh_and_bound_to_the_exact_authority(tmp_path):
    subject, key = authority(tmp_path)
    subject.verify_deployment_evidence(signed_evidence(subject, key), measurement_binding="b" * 64)


def test_injected_authority_happy_path_requires_signed_run_bound_evidence(tmp_path):
    measurement_key, fingerprint = write_contracts(tmp_path)
    script = runpy.run_path(str(CLI))
    argv = command(tmp_path, fingerprint, "init")[2:]
    args = script["_arguments"](argv)
    binding = script["_measurement_binding"](args)
    subject, key = authority(tmp_path, binding=binding)
    files = {name: json.loads((tmp_path / name).read_text()) for name in ("scope.json", "benchmark.json", "holdout.json", "contract.json")}
    collector = NativeShadowMeasurementCollector(
        path=tmp_path / "cohort.json", authority=subject, scope=ResolvedScopeV1.from_mapping(files["scope.json"]),
        benchmark=BenchmarkManifestV1.from_mapping(files["benchmark.json"]), holdout=HoldoutManifestV1.from_mapping(files["holdout.json"]),
        slo=RecallSloV1.from_mapping(files["contract.json"]), measurement_public_key=measurement_key.public_key(), measurement_key_id=fingerprint,
    )
    root = collector.checkpoint_payload(cohort_id=json.loads((tmp_path / "checkpoint.json").read_text())["cohort_id"], started_at=datetime.now(timezone.utc), anchor_root="a" * 64)
    (tmp_path / "checkpoint.json").write_text(json.dumps({key: root[key] for key in ("cohort_id", "started_at", "anchor_root")} | {"root_signature": measurement_key.sign(canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)).hex()}))
    (tmp_path / "evidence.json").write_text(json.dumps(signed_evidence(subject, key, binding=binding)))
    assert script["run_with_authority"](subject, [*argv, "--authority-evidence", str(tmp_path / "evidence.json")]) == 0
    assert (tmp_path / "authority.json").exists()
    before = (tmp_path / "authority.json").read_bytes()
    assert script["run_with_authority"](subject, argv) == 2  # missing evidence
    forged = json.loads((tmp_path / "evidence.json").read_text()); forged["endpoint"] = "retention-authority://forged"
    (tmp_path / "forged.json").write_text(json.dumps(forged))
    assert script["run_with_authority"](subject, [*argv, "--authority-evidence", str(tmp_path / "forged.json")]) == 2
    stale = signed_evidence(subject, key, binding=binding, now=datetime.now(timezone.utc) - timedelta(minutes=10))
    (tmp_path / "stale.json").write_text(json.dumps(stale))
    assert script["run_with_authority"](subject, [*argv, "--authority-evidence", str(tmp_path / "stale.json")]) == 2
    assert (tmp_path / "authority.json").read_bytes() == before
    segments_before = {item.name: item.read_bytes() for item in (tmp_path / "cohort.json.segments").iterdir()}
    (tmp_path / "authority.json").write_text("{")
    status_argv = ["status", *argv[1:argv.index("--checkpoint")]]
    assert script["run_with_authority"](subject, [*status_argv, "--authority-evidence", str(tmp_path / "evidence.json")]) == 2
    assert {item.name: item.read_bytes() for item in (tmp_path / "cohort.json.segments").iterdir()} == segments_before
