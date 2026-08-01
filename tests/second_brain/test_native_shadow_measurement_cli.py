from __future__ import annotations

import json
import os
import subprocess
import sys
from hashlib import sha256
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_bytes,
    canonical_ledger_digest,
)
from wiki_spike.canonical import canonical_bytes
from wiki_spike.applications.second_brain_shadow_measurement import (
    AuthoritySnapshot,
    NativeShadowMeasurementCollector,
)
from wiki_spike.composition.second_brain_shadow_measurement import (
    ShadowMeasurementCompositionError,
    open_measurement,
)
from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BenchmarkManifestV1,
    HoldoutManifestV1,
    RecallSloV1,
)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "scripts" / "second_brain_shadow_measurement.py"


def digest(value: str) -> str:
    return sha256(value.encode()).hexdigest()
AUTHORITY_ENDPOINT = "retention-authority://fixture"
AUTHORITY_UNAVAILABLE = (
    "authority error: unsupported authority endpoint scheme; "
    "expected retention-authority://local/<path>\n"
)


from test_native_shadow_measurement import IndependentMonotonicTestAuthority


class FixtureRetentionAuthority(IndependentMonotonicTestAuthority):
    """Authenticated in-memory authority used only for fixture checkpoints."""

    def __init__(self) -> None:
        super().__init__(AUTHORITY_ENDPOINT)




def write_contracts(tmp_path: Path):
    source_body = {
        "manifest_version": "native-source-manifest-v1",
        "workspace_ref": "workspace:native",
        "profiles": ["Codex", "Claude/Memory Bank", "Git", "Markdown"],
    }
    capability_body = {
        "manifest_version": "native-capability-manifest-v1",
        "workspace_ref": "workspace:native",
        "benchmark_key_ref": "key:native",
        "holdout_key_ref": "key:holdout",
        "benchmark_capability_ref": "capability:native",
        "holdout_capability_ref": "capability:holdout",
        "capabilities": ["local-authenticated-measurement"],
        "denied_capabilities": ["serving", "activation", "promotion", "routes", "export", "network"],
    }
    source_manifest_digest = sha256(canonical_bytes(source_body)).hexdigest()
    capability_manifest_digest = sha256(canonical_bytes(capability_body)).hexdigest()
    scope = {"scope_version":"second-brain-resolved-scope-v1","enabled_source_profiles":["Claude/Memory Bank","Codex","Git","Markdown"],"disabled_source_profiles":{},"enabled_migration_sources":[],"disabled_migration_sources":{},"feature_flags":[],"egress_destinations":[],"enabled_external_model_routes":[],"disabled_external_model_routes":{},"disabled_export_destinations":{},"capability_manifest_digest":capability_manifest_digest,"source_manifest_digest":source_manifest_digest,"mandatory_release_constraints":["signed-release-baseline"]}
    benchmark_body = {"manifest_version":"second-brain-benchmark-manifest-v1","workspace_ref":"workspace:native","corpus_key_ref":"key:native","capability_ref":"capability:native","item_digests":[digest("benchmark")],"label_review_digest":digest("labels"),"consent_digest":digest("consent")}
    holdout_body = {"manifest_version":"second-brain-holdout-manifest-v1","workspace_ref":"workspace:native","holdout_key_ref":"key:holdout","capability_ref":"capability:holdout","item_digests":[digest("holdout")],"separation_digest":digest("separation")}
    slo_body = {"slo_version":"second-brain-recall-slo-v1","parity_min_bps":0,"citation_min_bps":0,"completeness_min_bps":0,"availability_min_bps":0,"max_safety_violations":0,"min_shadow_days":3,"min_parity_cases_per_source":200,"min_cohort_e2e_queries":500,"confidence_method":"one-sided-wilson-95","include_invalid_in_denominator":True,"include_abstained_in_denominator":True,"include_source_unavailable_in_denominator":True}
    files = {"scope.json": scope, "source.json": source_body | {"source_manifest_digest": source_manifest_digest}, "capability.json": capability_body | {"capability_manifest_digest": capability_manifest_digest}, "benchmark.json": benchmark_body | {"manifest_digest": canonical_ledger_digest("benchmark-manifest-v1", benchmark_body)}, "holdout.json": holdout_body | {"manifest_digest": canonical_ledger_digest("holdout-manifest-v1", holdout_body)}, "contract.json": slo_body | {"slo_digest": canonical_ledger_digest("recall-slo-v1", slo_body)}}
    for name, body in files.items():
        (tmp_path / name).write_text(json.dumps(body))
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    (tmp_path / "key.pub").write_text(raw.hex())
    collector = NativeShadowMeasurementCollector(
        path=tmp_path / "cohort.json",
        authority=FixtureRetentionAuthority(),
        scope=ResolvedScopeV1.from_mapping(scope),
        benchmark=BenchmarkManifestV1.from_mapping(files["benchmark.json"]),
        holdout=HoldoutManifestV1.from_mapping(files["holdout.json"]),
        slo=RecallSloV1.from_mapping(files["contract.json"]),
        measurement_public_key=key.public_key(),
        measurement_key_id=sha256(raw).hexdigest(),
    )
    root = collector.checkpoint_payload(
        cohort_id=str(uuid4()),
        started_at=datetime.now(timezone.utc),
        anchor_root=digest("anchor"),
    )
    (tmp_path / "checkpoint.json").write_text(json.dumps({
        "cohort_id": root["cohort_id"],
        "started_at": root["started_at"],
        "anchor_root": root["anchor_root"],
        "root_signature": key.sign(
            canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)
        ).hex(),
    }))
    return key, sha256(raw).hexdigest()


def command(tmp_path: Path, fingerprint: str, operation: str, *extra: str) -> list[str]:
    checkpoint = ["--checkpoint", str(tmp_path / "checkpoint.json")] if operation == "init" else []
    return [sys.executable, str(CLI), operation, "--db", str(tmp_path / "cohort.json"), "--authority-endpoint", AUTHORITY_ENDPOINT, "--measurement-public-key", str(tmp_path / "key.pub"), "--measurement-key-fingerprint", fingerprint, "--resolved-scope", str(tmp_path / "scope.json"), "--contract", str(tmp_path / "contract.json"), "--source-manifest", str(tmp_path / "source.json"), "--capability-manifest", str(tmp_path / "capability.json"), "--benchmark-manifest", str(tmp_path / "benchmark.json"), "--holdout-manifest", str(tmp_path / "holdout.json"), *checkpoint, *extra]


def run(args: list[str]) -> subprocess.CompletedProcess[str]:
    env = os.environ | {"PYTHONPATH": str(ROOT / "src")}
    return subprocess.run(args, text=True, capture_output=True, env=env, check=False)


def test_closed_cli_requires_deployment_authority_adapter(tmp_path):
    _, fingerprint = write_contracts(tmp_path)
    init = run(command(tmp_path, fingerprint, "init"))
    assert init.returncode == 2
    assert init.stderr == AUTHORITY_UNAVAILABLE
    assert run(command(tmp_path, fingerprint, "status")).returncode == 2
    assert run(command(tmp_path, fingerprint, "verify")).returncode == 2


def test_closed_cli_rejects_roster_drift_unsigned_input_clock_and_legacy_flags(tmp_path):
    _, fingerprint = write_contracts(tmp_path)
    no_checkpoint = command(tmp_path, fingerprint, "init")
    no_checkpoint.remove("--checkpoint")
    no_checkpoint.remove(str(tmp_path / "checkpoint.json"))
    assert run(no_checkpoint).returncode == 2
    assert run(command(tmp_path, fingerprint, "init", "--clock", "forged")).returncode == 2
    assert run(command(tmp_path, fingerprint, "init", "--activate")).returncode == 2
    assert run(command(tmp_path, fingerprint, "init", "--legacy")).returncode == 2
    assert run(command(tmp_path, fingerprint, "init")).returncode == 2
    unsigned = {"sample_version": "second-brain-native-shadow-sample-v1", "sample_id": "bad",
                "source_profile": "Codex", "outcome": "valid", "citation": True,
                "completeness": True, "parity": True, "safety_violation": False}
    (tmp_path / "unsigned.json").write_text(json.dumps(unsigned))
    assert run(command(tmp_path, fingerprint, "append", "--sample", str(tmp_path / "unsigned.json"))).returncode == 2
    assert run(command(tmp_path, "0" * 64, "status")).returncode == 2
    scope = json.loads((tmp_path / "scope.json").read_text()); scope["enabled_source_profiles"][-1] = "unified-db"
    (tmp_path / "scope.json").write_text(json.dumps(scope))
    assert run(command(tmp_path, fingerprint, "init")).returncode == 2

def test_cli_rejects_digest_consistent_manifest_semantic_conflicts(tmp_path):
    for name, filename, mutation, digest_field, scope_field in (
        (
            "source-roster",
            "source.json",
            lambda body: body["profiles"].__setitem__(0, "unified-db"),
            "source_manifest_digest",
            "source_manifest_digest",
        ),
        (
            "source-workspace",
            "source.json",
            lambda body: body.__setitem__("workspace_ref", "workspace:foreign"),
            "source_manifest_digest",
            "source_manifest_digest",
        ),
        (
            "capability-serving",
            "capability.json",
            lambda body: body["capabilities"].append("serving"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
        (
            "capability-key",
            "capability.json",
            lambda body: body.__setitem__("benchmark_key_ref", "key:foreign"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
        (
            "capability-workspace",
            "capability.json",
            lambda body: body.__setitem__("workspace_ref", "workspace:foreign"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
        (
            "capability-holdout-key",
            "capability.json",
            lambda body: body.__setitem__("holdout_key_ref", "key:foreign"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
        (
            "capability-benchmark-ref",
            "capability.json",
            lambda body: body.__setitem__("benchmark_capability_ref", "capability:foreign"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
        (
            "capability-holdout-ref",
            "capability.json",
            lambda body: body.__setitem__("holdout_capability_ref", "capability:foreign"),
            "capability_manifest_digest",
            "capability_manifest_digest",
        ),
    ):
        case = tmp_path / name
        case.mkdir()
        _, fingerprint = write_contracts(case)
        manifest = json.loads((case / filename).read_text())
        mutation(manifest)
        body = {key: value for key, value in manifest.items() if key != digest_field}
        manifest[digest_field] = sha256(canonical_bytes(body)).hexdigest()
        (case / filename).write_text(json.dumps(manifest))
        scope = json.loads((case / "scope.json").read_text())
        scope[scope_field] = manifest[digest_field]
        (case / "scope.json").write_text(json.dumps(scope))
        with pytest.raises(ShadowMeasurementCompositionError):
            open_measurement(
                db=case / "semantic-cohort.json",
                authority=FixtureRetentionAuthority(),
                measurement_public_key=case / "key.pub",
                measurement_key_fingerprint=fingerprint,
                resolved_scope=case / "scope.json",
                contract=case / "contract.json",
                source_manifest=case / "source.json",
                capability_manifest=case / "capability.json",
                benchmark_manifest=case / "benchmark.json",
                holdout_manifest=case / "holdout.json",
                checkpoint=case / "checkpoint.json",
                create=True,
            )
        result = run(command(case, fingerprint, "init"))
        assert result.returncode == 2
        assert result.stderr == AUTHORITY_UNAVAILABLE

def test_cli_rejects_manifest_body_drift_and_post_init_drift(tmp_path):
    _, fingerprint = write_contracts(tmp_path)
    source = json.loads((tmp_path / "source.json").read_text())
    source["profiles"].append("forged")
    (tmp_path / "source.json").write_text(json.dumps(source))
    assert run(command(tmp_path, fingerprint, "init")).returncode == 2

    _, fingerprint = write_contracts(tmp_path)
    assert run(command(tmp_path, fingerprint, "init")).returncode == 2
    capability = json.loads((tmp_path / "capability.json").read_text())
    capability["capabilities"].append("forged")
    (tmp_path / "capability.json").write_text(json.dumps(capability))
    assert run(command(tmp_path, fingerprint, "status")).returncode == 2


def test_cli_rejects_cross_manifest_workspace_key_and_capability_incoherence(tmp_path):
    for field, value in (
        ("workspace_ref", "workspace:foreign"),
        ("holdout_key_ref", "key:native"),
        ("capability_ref", "capability:native"),
    ):
        case = tmp_path / field
        case.mkdir()
        _, fingerprint = write_contracts(case)
        holdout = json.loads((case / "holdout.json").read_text())
        holdout[field] = value
        body = {key: value for key, value in holdout.items() if key != "manifest_digest"}
        holdout["manifest_digest"] = canonical_ledger_digest("holdout-manifest-v1", body)
        (case / "holdout.json").write_text(json.dumps(holdout))
        assert run(command(case, fingerprint, "init")).returncode == 2
def test_cli_rejects_missing_or_corrupt_state_without_creating_it(tmp_path):
    _, fingerprint = write_contracts(tmp_path)
    missing = run(command(tmp_path, fingerprint, "status"))
    assert missing.returncode == 2
    assert not (tmp_path / "cohort.json").exists()
    assert not (tmp_path / "cohort.json.lock").exists()

    (tmp_path / "cohort.json").write_text("{")
    corrupt = run(command(tmp_path, fingerprint, "verify"))
    assert corrupt.returncode == 2
    assert corrupt.stderr == AUTHORITY_UNAVAILABLE
def test_boundary_checker_scans_explicit_native_file_root(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname = \"boundary-test\"\nversion = \"0\"\n")
    (tmp_path / "native.py").write_text("import socket\n")
    config = {
        "layers": {"native_measurement": ["native.py"]},
        "rules": [{
            "from_layers": ["native_measurement"],
            "forbidden_modules": ["socket"],
            "reason": "network is forbidden",
        }],
        "scan_roots": ["native.py"],
        "schema_version": "phase3-boundaries-v1",
    }
    config_path = tmp_path / "boundaries.json"
    config_path.write_bytes(canonical_bytes(config))
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "check_architecture_boundaries.py"),
         "--repo-root", str(tmp_path), "--config", str(config_path), "--json"],
        text=True, capture_output=True, check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stdout)["violations"][0]["imported_module"] == "socket"

def test_cli_end_to_end_init_status_verify(tmp_path):
    """Provision real authority, init cohort, append sample, verify status."""
    from wiki_spike.composition.retained_authority import provision_authority, LocalRetainedAuthority
    # Provision authority FIRST so checkpoint binds to it
    auth_dir = provision_authority(tmp_path / "authority")
    authority = LocalRetainedAuthority(auth_dir)
    endpoint = authority.endpoint

    # Write contracts using the real authority for checkpoint creation
    source_body = {"manifest_version": "native-source-manifest-v1", "workspace_ref": "workspace:native", "profiles": ["Codex", "Claude/Memory Bank", "Git", "Markdown"]}
    capability_body = {"manifest_version": "native-capability-manifest-v1", "workspace_ref": "workspace:native", "benchmark_key_ref": "key:native", "holdout_key_ref": "key:holdout", "benchmark_capability_ref": "capability:native", "holdout_capability_ref": "capability:holdout", "capabilities": ["local-authenticated-measurement"], "denied_capabilities": ["serving", "activation", "promotion", "routes", "export", "network"]}
    source_manifest_digest = sha256(canonical_bytes(source_body)).hexdigest()
    capability_manifest_digest = sha256(canonical_bytes(capability_body)).hexdigest()
    scope = {"scope_version":"second-brain-resolved-scope-v1","enabled_source_profiles":["Claude/Memory Bank","Codex","Git","Markdown"],"disabled_source_profiles":{},"enabled_migration_sources":[],"disabled_migration_sources":{},"feature_flags":[],"egress_destinations":[],"enabled_external_model_routes":[],"disabled_external_model_routes":{},"disabled_export_destinations":{},"capability_manifest_digest":capability_manifest_digest,"source_manifest_digest":source_manifest_digest,"mandatory_release_constraints":["signed-release-baseline"]}
    benchmark_body = {"manifest_version":"second-brain-benchmark-manifest-v1","workspace_ref":"workspace:native","corpus_key_ref":"key:native","capability_ref":"capability:native","item_digests":[digest("benchmark")],"label_review_digest":digest("labels"),"consent_digest":digest("consent")}
    holdout_body = {"manifest_version":"second-brain-holdout-manifest-v1","workspace_ref":"workspace:native","holdout_key_ref":"key:holdout","capability_ref":"capability:holdout","item_digests":[digest("holdout")],"separation_digest":digest("separation")}
    slo_body = {"slo_version":"second-brain-recall-slo-v1","parity_min_bps":0,"citation_min_bps":0,"completeness_min_bps":0,"availability_min_bps":0,"max_safety_violations":0,"min_shadow_days":3,"min_parity_cases_per_source":200,"min_cohort_e2e_queries":500,"confidence_method":"one-sided-wilson-95","include_invalid_in_denominator":True,"include_abstained_in_denominator":True,"include_source_unavailable_in_denominator":True}
    files = {"scope.json": scope, "source.json": source_body | {"source_manifest_digest": source_manifest_digest}, "capability.json": capability_body | {"capability_manifest_digest": capability_manifest_digest}, "benchmark.json": benchmark_body | {"manifest_digest": canonical_ledger_digest("benchmark-manifest-v1", benchmark_body)}, "holdout.json": holdout_body | {"manifest_digest": canonical_ledger_digest("holdout-manifest-v1", holdout_body)}, "contract.json": slo_body | {"slo_digest": canonical_ledger_digest("recall-slo-v1", slo_body)}}
    for name, body in files.items():
        (tmp_path / name).write_text(json.dumps(body))
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes_raw()
    (tmp_path / "key.pub").write_text(raw.hex())
    fingerprint = sha256(raw).hexdigest()

    # Create checkpoint bound to the real authority
    collector = NativeShadowMeasurementCollector(
        path=tmp_path / "cohort.json", authority=authority,
        scope=ResolvedScopeV1.from_mapping(scope),
        benchmark=BenchmarkManifestV1.from_mapping(files["benchmark.json"]),
        holdout=HoldoutManifestV1.from_mapping(files["holdout.json"]),
        slo=RecallSloV1.from_mapping(files["contract.json"]),
        measurement_public_key=key.public_key(), measurement_key_id=fingerprint,
    )
    root = collector.checkpoint_payload(cohort_id=str(uuid4()), started_at=datetime.now(timezone.utc), anchor_root=digest("anchor"))
    (tmp_path / "checkpoint.json").write_text(json.dumps({
        "cohort_id": root["cohort_id"], "started_at": root["started_at"],
        "anchor_root": root["anchor_root"],
        "root_signature": key.sign(canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)).hex(),
    }))

    def real_command(operation, *extra):
        checkpoint = ["--checkpoint", str(tmp_path / "checkpoint.json")] if operation == "init" else []
        return [sys.executable, str(CLI), operation, "--db", str(tmp_path / "cohort.json"),
                "--authority-endpoint", endpoint, "--measurement-public-key", str(tmp_path / "key.pub"),
                "--measurement-key-fingerprint", fingerprint, "--resolved-scope", str(tmp_path / "scope.json"),
                "--contract", str(tmp_path / "contract.json"), "--source-manifest", str(tmp_path / "source.json"),
                "--capability-manifest", str(tmp_path / "capability.json"),
                "--benchmark-manifest", str(tmp_path / "benchmark.json"),
                "--holdout-manifest", str(tmp_path / "holdout.json"), *checkpoint, *extra]

    # Init succeeds
    init = run(real_command("init"))
    assert init.returncode == 0, init.stderr
    init_body = json.loads(init.stdout)
    assert init_body["status"] == "initialized"
    cohort_digest = init_body["cohort_digest"]
    assert len(cohort_digest) == 64

    # Status reports NOT_READY with zero samples
    status = run(real_command("status"))
    assert status.returncode == 0, status.stderr
    status_body = json.loads(status.stdout)
    assert status_body["outcome"] == "NOT_READY"
    assert status_body["sample_count"] == 0
    assert status_body["cohort_digest"] == cohort_digest

    # Verify also works
    verify = run(real_command("verify"))
    assert verify.returncode == 0, verify.stderr

    # Append a properly signed sample
    sample_payload = {
        "sample_version": "second-brain-native-shadow-sample-v1",
        "sample_id": "e2e-test:001", "source_profile": "Codex",
        "outcome": "valid", "citation": True, "completeness": True,
        "parity": True, "safety_violation": False,
        "cohort_digest": cohort_digest, "previous": None, "sequence": 0,
    }
    sample_payload["signature"] = key.sign(canonical_ledger_bytes("second-brain-native-shadow-sample-v1", sample_payload)).hex()
    (tmp_path / "sample.json").write_text(json.dumps(sample_payload))
    append = run(real_command("append", "--sample", str(tmp_path / "sample.json")))
    assert append.returncode == 0, append.stderr
    assert json.loads(append.stdout)["status"] == "appended"

    # Status now shows 1 sample
    status2 = run(real_command("status"))
    assert status2.returncode == 0, status2.stderr
    status2_body = json.loads(status2.stdout)
    assert status2_body["sample_count"] == 1
    assert status2_body["outcome"] == "NOT_READY"