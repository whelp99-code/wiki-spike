"""Task 48B matrix: producer vectors, retained authority, injected CLI, public rc 2."""
from __future__ import annotations

import json
import runpy
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from tests.second_brain.test_native_shadow_measurement_cli import CLI, command, run, write_contracts

from wiki_spike.applications.second_brain_shadow_measurement import AuthoritySnapshot, NativeShadowMeasurementCollector
from wiki_spike.infrastructure.second_brain_authority_factory import InstalledArtifactIdentity
from wiki_spike.infrastructure.second_brain_monotonic_append_authority import (
    BUNDLE_VERSION,
    CONFIG_VERSION,
    EVIDENCE_SCHEMA,
    RECEIPT_SCHEMA,
    ROOT_VERSION,
    DeploymentAuthorityEvidence,
    DeploymentMonotonicAppendAuthority,
    ShadowProduceRequestV1,
    produce_shadow_artifacts,
    verify_shadow_artifacts,
    write_live_operation_denial_receipt,
)
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import BenchmarkManifestV1, HoldoutManifestV1, RecallSloV1
from wiki_spike.memory_core.second_brain_gate_envelope import digest_fields, signing_message
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

DIGEST_FIELDS = (
    "shadow_executor_bundle_sha256",
    "shadow_measurement_root_sha256",
    "shadow_run_config_payload_sha256",
)
CONFIG_PAYLOAD = (
    "version", "db_ref", "db_identity_sha256", "authority_endpoint_ref",
    "authority_endpoint_identity_sha256", "measurement_public_key_ref",
    "measurement_public_key_sha256", "measurement_key_fingerprint",
    "resolved_scope_ref", "resolved_scope_sha256", "contract_ref", "contract_sha256",
    "source_manifest_ref", "source_manifest_sha256", "capability_manifest_ref",
    "capability_manifest_sha256", "benchmark_manifest_ref", "benchmark_manifest_sha256",
    "holdout_manifest_ref", "holdout_manifest_sha256", "shadow_executor_bundle_ref",
    "shadow_executor_bundle_sha256",
)


def _hex(tag: str) -> str:
    return sha256(tag.encode()).hexdigest()


def _fingerprint(key: Ed25519PrivateKey) -> str:
    return sha256(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


class MemoryInputs:
    """In-memory immutable input registry for fixture verification."""

    def __init__(self, items: Mapping[str, bytes]) -> None:
        self._items = dict(items)

    def resolve(self, ref: str) -> bytes:
        return self._items[ref]

    def resolve_digest(self, digest: str) -> bytes:
        for raw in self._items.values():
            if sha256(raw).hexdigest() == digest:
                return raw
        raise KeyError(digest)


def produce_request(*, cohort: str = "cohort", issued_at: str = "2026-01-01T00:00:00Z") -> ShadowProduceRequestV1:
    return ShadowProduceRequestV1(
        roster_artifact_sha256=_hex("wheel"),
        authority_cli_artifact_sha256=_hex("cli"),
        lockfile_sha256=_hex("lock"),
        cohort_receipt_sha256=_hex(cohort),
        initial_checkpoint_sha256=_hex("checkpoint"),
        issued_at=issued_at,
        db_ref="db:native",
        db_identity_sha256=_hex("db-genesis"),
        authority_endpoint_ref="endpoint:native",
        authority_endpoint_identity_sha256=_hex("endpoint"),
        measurement_public_key_ref="key:measure",
        measurement_public_key_sha256=_hex("pubkey-bytes"),
        measurement_key_fingerprint=_hex("fingerprint"),
        resolved_scope_ref="scope:native",
        resolved_scope_sha256=_hex("scope"),
        contract_ref="contract:native",
        contract_sha256=_hex("contract"),
        source_manifest_ref="source:native",
        source_manifest_sha256=_hex("source"),
        capability_manifest_ref="capability:native",
        capability_manifest_sha256=_hex("capability"),
        benchmark_manifest_ref="benchmark:native",
        benchmark_manifest_sha256=_hex("benchmark"),
        holdout_manifest_ref="holdout:native",
        holdout_manifest_sha256=_hex("holdout"),
        bundle_ref="bundle:shadow",
        root_ref="root:shadow",
        signer_ref="signer:m5-fixture",
        key_id="m5-fixture-1",
    )


def signed_world(request: ShadowProduceRequestV1 | None = None):
    key = Ed25519PrivateKey.generate()
    req = request or produce_request()
    bundle, root, config = produce_shadow_artifacts(req, key)
    items = {
        req.db_ref: b"db-genesis",
        req.authority_endpoint_ref: b"endpoint",
        req.measurement_public_key_ref: b"pubkey-bytes",
        req.resolved_scope_ref: b"scope",
        req.contract_ref: b"contract",
        req.source_manifest_ref: b"source",
        req.capability_manifest_ref: b"capability",
        req.benchmark_manifest_ref: b"benchmark",
        req.holdout_manifest_ref: b"holdout",
        req.bundle_ref: json.dumps(bundle.to_mapping(), sort_keys=True, separators=(",", ":")).encode(),
        req.root_ref: json.dumps(root.to_mapping(), sort_keys=True, separators=(",", ":")).encode(),
        f"cohort:{req.cohort_receipt_sha256}": b"cohort",
    }
    artifacts = InstalledArtifactIdentity(
        req.roster_artifact_sha256, req.authority_cli_artifact_sha256, req.lockfile_sha256,
    )
    return key, req, bundle, root, config, MemoryInputs(items), artifacts


def authority(tmp_path: Path, *, binding: str = "b" * 64, trusted_clock=None, digests=None):
    trusted_clock = trusted_clock or (lambda now=datetime.now(UTC): now)
    key = Ed25519PrivateKey.generate()
    produced = digests or {field: _hex(field) for field in DIGEST_FIELDS}
    evidence = DeploymentAuthorityEvidence(
        identity="deploy:shadow",
        endpoint="retention-authority://shadow-deploy",
        policy_id="shadow-retention-v1",
        measurement_binding=binding,
        public_key_fingerprint=_fingerprint(key),
        **produced,
    )
    subject = DeploymentMonotonicAppendAuthority(
        state_path=tmp_path / "authority.json",
        evidence=evidence,
        signing_key=key,
        snapshot_factory=AuthoritySnapshot,
        trusted_clock=trusted_clock,
    )
    subject.verify_deployment_evidence(
        signed_evidence(subject, key, binding=binding),
        measurement_binding=binding,
    )
    return subject, key, produced


def signed_evidence(subject, key, *, binding: str = "b" * 64, revision: int = 0, root: str | None = None, now=None):
    now = now or subject._trusted_clock()
    root = root or sha256(canonical_ledger_bytes("second-brain-native-shadow-authority-v1", {"events": []})).hexdigest()
    body = {
        "evidence_version": EVIDENCE_SCHEMA,
        "identity": subject.identity,
        "endpoint": subject.endpoint,
        "policy_id": subject.policy_id,
        "public_key_fingerprint": _fingerprint(key),
        "measurement_binding": binding,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "authority_revision": revision,
        "authority_root": root,
        "shadow_executor_bundle_sha256": subject.shadow_executor_bundle_sha256,
        "shadow_measurement_root_sha256": subject.shadow_measurement_root_sha256,
        "shadow_run_config_payload_sha256": subject.shadow_run_config_payload_sha256,
    }
    return body | {"signature": key.sign(canonical_ledger_bytes(EVIDENCE_SCHEMA, body)).hex()}


def test_producer_emits_signed_bundle_root_and_run_config_vectors() -> None:
    key, req, bundle, root, config, inputs, artifacts = signed_world()
    assert bundle.version == BUNDLE_VERSION
    assert root.version == ROOT_VERSION
    assert config.version == CONFIG_VERSION
    mapping = bundle.to_mapping()
    assert mapping["bundle_sha256"] == digest_fields({
        "version": BUNDLE_VERSION,
        "roster_artifact_sha256": req.roster_artifact_sha256,
        "authority_cli_artifact_sha256": req.authority_cli_artifact_sha256,
        "lockfile_sha256": req.lockfile_sha256,
        "cohort_receipt_sha256": req.cohort_receipt_sha256,
    })
    key.public_key().verify(
        bytes.fromhex(bundle.signature),
        signing_message(BUNDLE_VERSION, {k: mapping[k] for k in mapping if k not in {"signer_ref", "key_id", "signature"}}),
    )
    payload = {field: config.to_mapping()[field] for field in CONFIG_PAYLOAD}
    assert config.run_config_payload_sha256 == digest_fields(payload)
    assert "shadow_measurement_root" not in json.dumps(payload)
    assert root.shadow_run_config_payload_sha256 == config.run_config_payload_sha256
    assert root.shadow_executor_bundle_sha256 == bundle.bundle_sha256
    key.public_key().verify(
        bytes.fromhex(root.signature),
        signing_message(ROOT_VERSION, {k: v for k, v in root.to_mapping().items() if k != "signature"}),
    )
    key.public_key().verify(
        bytes.fromhex(config.signature),
        signing_message(CONFIG_VERSION, {k: v for k, v in config.to_mapping().items() if k != "signature"}),
    )
    verify_shadow_artifacts(
        bundle=bundle, root=root, config=config, inputs=inputs, artifacts=artifacts, public_key=key.public_key(),
    )


def test_authority_signs_monotonic_snapshots_and_receipts_include_artifact_digests(tmp_path: Path) -> None:
    subject, key, produced = authority(tmp_path)
    initial = subject.snapshot(request_nonce="a" * 64)
    assert initial.revision == 0 and initial.events == ()
    advanced = subject.compare_and_advance(
        expected_revision=0, event={"kind": "checkpoint", "root": "x"}, request_nonce="b" * 64,
    )
    assert advanced.revision == 1
    key.public_key().verify(
        bytes.fromhex(advanced.signature),
        canonical_ledger_bytes("second-brain-native-shadow-authority-v1", advanced.payload()),
    )
    receipt = write_live_operation_denial_receipt(
        path=tmp_path / "receipt.json", authority=subject, operation="append",
    )
    for field, digest in produced.items():
        assert receipt[field] == digest
        assert getattr(subject, field) == digest
    assert receipt["live_operation_authorized"] is False
    assert "checkpoint" not in json.dumps(receipt)
    body = {key: value for key, value in receipt.items() if key != "receipt_digest"}
    assert receipt["receipt_digest"] == sha256(canonical_ledger_bytes(RECEIPT_SCHEMA, body)).hexdigest()
    assert receipt["receipt_version"] == RECEIPT_SCHEMA


def test_injected_authority_requires_signed_evidence_and_public_cli_stays_rc2(tmp_path: Path, capsys) -> None:
    measurement_key, fingerprint = write_contracts(tmp_path)
    script = runpy.run_path(str(CLI))
    argv = command(tmp_path, fingerprint, "init")[2:]
    binding = script["_measurement_binding"](script["_arguments"](argv))
    subject, key, produced = authority(tmp_path, binding=binding)
    files = {name: json.loads((tmp_path / name).read_text()) for name in ("scope.json", "benchmark.json", "holdout.json", "contract.json")}
    collector = NativeShadowMeasurementCollector(
        path=tmp_path / "rebind.json", authority=subject,
        scope=ResolvedScopeV1.from_mapping(files["scope.json"]),
        benchmark=BenchmarkManifestV1.from_mapping(files["benchmark.json"]),
        holdout=HoldoutManifestV1.from_mapping(files["holdout.json"]),
        slo=RecallSloV1.from_mapping(files["contract.json"]),
        measurement_public_key=measurement_key.public_key(), measurement_key_id=fingerprint,
    )
    root = collector.checkpoint_payload(
        cohort_id=json.loads((tmp_path / "checkpoint.json").read_text())["cohort_id"],
        started_at=datetime.now(UTC), anchor_root="a" * 64,
    )
    (tmp_path / "checkpoint.json").write_text(json.dumps({
        field: root[field] for field in ("cohort_id", "started_at", "anchor_root")
    } | {"root_signature": measurement_key.sign(canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)).hex()}))
    (tmp_path / "evidence.json").write_text(json.dumps(signed_evidence(subject, key, binding=binding)))
    assert script["run_with_authority"](subject, [*argv, "--authority-evidence", str(tmp_path / "evidence.json")]) == 0
    report = json.loads(capsys.readouterr().out)
    for field, digest in produced.items():
        assert report[field] == digest
    public = run(command(tmp_path, fingerprint, "init"))
    assert public.returncode == 2
    assert "deployment-provided MonotonicAppendAuthority" in public.stderr
    assert script["run_with_authority"](subject, argv) == 2
