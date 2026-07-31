#!/usr/bin/env python3
"""Provision and initialize a real native shadow-measurement cohort.

This script:
1. Provisions a LocalRetainedAuthority (Ed25519 signing key + append-only journal)
2. Generates the measurement Ed25519 key pair
3. Generates all operational manifests with correct digest bindings
4. Creates and signs the cohort checkpoint
5. Initializes the cohort via the composition layer

Usage:
    python3 scripts/provision_shadow_measurement.py --output-dir <dir>

The output directory will contain:
    authority/          - provisioned authority directory
    measurement.key     - measurement Ed25519 private key (raw hex, 0600)
    measurement.pub     - measurement Ed25519 public key (raw hex)
    scope.json          - resolved scope
    contract.json       - recall SLO contract
    source.json         - source manifest
    capability.json     - capability manifest
    benchmark.json      - benchmark manifest
    holdout.json        - holdout manifest
    checkpoint.json     - signed cohort checkpoint
    cohort.json         - initialized cohort DB (after init)
    cohort.json.segments/ - journal segments (after init)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from wiki_spike.canonical import canonical_bytes
from wiki_spike.composition.retained_authority import provision_authority
from wiki_spike.composition.second_brain_shadow_measurement import open_measurement
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_bytes,
    canonical_ledger_digest,
)


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def provision(output_dir: Path) -> None:
    if output_dir.exists() and any(output_dir.iterdir()):
        print(f"error: output directory is not empty: {output_dir}", file=sys.stderr)
        raise SystemExit(1)
    output_dir.mkdir(parents=True, exist_ok=True)

    # 1. Provision authority
    auth_dir = output_dir / "authority"
    provision_authority(auth_dir, identity="wiki-spike-operational-authority")
    print(f"authority provisioned: {auth_dir}")

    # 2. Generate measurement key pair
    measurement_key = Ed25519PrivateKey.generate()
    private_raw = measurement_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public_raw = measurement_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    (output_dir / "measurement.key").write_text(private_raw.hex() + "\n")
    os.chmod(output_dir / "measurement.key", 0o600)
    (output_dir / "measurement.pub").write_text(public_raw.hex() + "\n")
    fingerprint = sha256(public_raw).hexdigest()
    print(f"measurement key fingerprint: {fingerprint}")

    # 3. Generate manifests
    workspace_ref = "workspace:native"
    source_body = {
        "manifest_version": "native-source-manifest-v1",
        "workspace_ref": workspace_ref,
        "profiles": ["Codex", "Claude/Memory Bank", "Git", "Markdown"],
    }
    capability_body = {
        "manifest_version": "native-capability-manifest-v1",
        "workspace_ref": workspace_ref,
        "benchmark_key_ref": "key:native",
        "holdout_key_ref": "key:holdout",
        "benchmark_capability_ref": "capability:native",
        "holdout_capability_ref": "capability:holdout",
        "capabilities": ["local-authenticated-measurement"],
        "denied_capabilities": ["serving", "activation", "promotion", "routes", "export", "network"],
    }
    source_manifest_digest = sha256(canonical_bytes(source_body)).hexdigest()
    capability_manifest_digest = sha256(canonical_bytes(capability_body)).hexdigest()

    benchmark_body = {
        "manifest_version": "second-brain-benchmark-manifest-v1",
        "workspace_ref": workspace_ref,
        "corpus_key_ref": "key:native",
        "capability_ref": "capability:native",
        "item_digests": [sha256(b"operational-benchmark-corpus-v1").hexdigest()],
        "label_review_digest": sha256(b"operational-label-review-v1").hexdigest(),
        "consent_digest": sha256(b"operational-consent-v1").hexdigest(),
    }
    benchmark_digest = canonical_ledger_digest("benchmark-manifest-v1", benchmark_body)

    holdout_body = {
        "manifest_version": "second-brain-holdout-manifest-v1",
        "workspace_ref": workspace_ref,
        "holdout_key_ref": "key:holdout",
        "capability_ref": "capability:holdout",
        "item_digests": [sha256(b"operational-holdout-corpus-v1").hexdigest()],
        "separation_digest": sha256(b"operational-separation-v1").hexdigest(),
    }
    holdout_digest = canonical_ledger_digest("holdout-manifest-v1", holdout_body)

    slo_body = {
        "slo_version": "second-brain-recall-slo-v1",
        "parity_min_bps": 7000,
        "citation_min_bps": 7000,
        "completeness_min_bps": 7000,
        "availability_min_bps": 9500,
        "max_safety_violations": 0,
        "min_shadow_days": 3,
        "min_parity_cases_per_source": 200,
        "min_cohort_e2e_queries": 500,
        "confidence_method": "one-sided-wilson-95",
        "include_invalid_in_denominator": True,
        "include_abstained_in_denominator": True,
        "include_source_unavailable_in_denominator": True,
    }
    slo_digest = canonical_ledger_digest("recall-slo-v1", slo_body)

    scope = {
        "scope_version": "second-brain-resolved-scope-v1",
        "enabled_source_profiles": ["Claude/Memory Bank", "Codex", "Git", "Markdown"],
        "disabled_source_profiles": {},
        "enabled_migration_sources": [],
        "disabled_migration_sources": {},
        "feature_flags": [],
        "egress_destinations": [],
        "enabled_external_model_routes": [],
        "disabled_external_model_routes": {},
        "disabled_export_destinations": {},
        "capability_manifest_digest": capability_manifest_digest,
        "source_manifest_digest": source_manifest_digest,
        "mandatory_release_constraints": ["signed-release-baseline"],
    }

    # Write manifests
    manifests = {
        "scope.json": scope,
        "source.json": source_body | {"source_manifest_digest": source_manifest_digest},
        "capability.json": capability_body | {"capability_manifest_digest": capability_manifest_digest},
        "benchmark.json": benchmark_body | {"manifest_digest": benchmark_digest},
        "holdout.json": holdout_body | {"manifest_digest": holdout_digest},
        "contract.json": slo_body | {"slo_digest": slo_digest},
    }
    for name, body in manifests.items():
        (output_dir / name).write_text(json.dumps(body, indent=2) + "\n")
    print(f"manifests written: {', '.join(sorted(manifests))}")

    # 4. Create cohort checkpoint
    from wiki_spike.applications.second_brain_shadow_measurement import NativeShadowMeasurementCollector
    from wiki_spike.composition.retained_authority import LocalRetainedAuthority
    from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
    from wiki_spike.memory_core.second_brain_evaluation_contracts import (
        BenchmarkManifestV1, HoldoutManifestV1, RecallSloV1,
    )

    authority = LocalRetainedAuthority(auth_dir)
    collector = NativeShadowMeasurementCollector(
        path=output_dir / "cohort.json",
        authority=authority,
        scope=ResolvedScopeV1.from_mapping(scope),
        benchmark=BenchmarkManifestV1.from_mapping(manifests["benchmark.json"]),
        holdout=HoldoutManifestV1.from_mapping(manifests["holdout.json"]),
        slo=RecallSloV1.from_mapping(manifests["contract.json"]),
        measurement_public_key=measurement_key.public_key(),
        measurement_key_id=fingerprint,
    )
    cohort_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    anchor_root = sha256(canonical_bytes({"cohort_id": cohort_id, "provisioned_at": _stamp(started_at)})).hexdigest()

    root = collector.checkpoint_payload(
        cohort_id=cohort_id,
        started_at=started_at,
        anchor_root=anchor_root,
    )
    root_signature = measurement_key.sign(
        canonical_ledger_bytes("second-brain-native-shadow-cohort-v1", root)
    ).hex()
    checkpoint = {
        "cohort_id": cohort_id,
        "started_at": root["started_at"],
        "anchor_root": anchor_root,
        "root_signature": root_signature,
    }
    (output_dir / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2) + "\n")
    print(f"cohort checkpoint: {cohort_id}")
    print(f"started_at: {root['started_at']}")

    # 5. Initialize cohort via composition layer
    collector = open_measurement(
        db=output_dir / "cohort.json",
        authority=authority,
        measurement_public_key=output_dir / "measurement.pub",
        measurement_key_fingerprint=fingerprint,
        resolved_scope=output_dir / "scope.json",
        contract=output_dir / "contract.json",
        source_manifest=output_dir / "source.json",
        capability_manifest=output_dir / "capability.json",
        benchmark_manifest=output_dir / "benchmark.json",
        holdout_manifest=output_dir / "holdout.json",
        checkpoint=output_dir / "checkpoint.json",
        create=True,
    )
    print(f"cohort initialized: {collector.cohort_digest}")
    print(f"authority endpoint: {authority.endpoint}")
    print()
    print("CLI usage:")
    print(f"  PYTHONPATH=src python3 scripts/second_brain_shadow_measurement.py status \\")
    print(f"    --db {output_dir / 'cohort.json'} \\")
    print(f"    --authority-endpoint '{authority.endpoint}' \\")
    print(f"    --measurement-public-key {output_dir / 'measurement.pub'} \\")
    print(f"    --measurement-key-fingerprint {fingerprint} \\")
    print(f"    --resolved-scope {output_dir / 'scope.json'} \\")
    print(f"    --contract {output_dir / 'contract.json'} \\")
    print(f"    --source-manifest {output_dir / 'source.json'} \\")
    print(f"    --capability-manifest {output_dir / 'capability.json'} \\")
    print(f"    --benchmark-manifest {output_dir / 'benchmark.json'} \\")
    print(f"    --holdout-manifest {output_dir / 'holdout.json'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision operational shadow measurement cohort")
    parser.add_argument("--output-dir", required=True, help="Directory for operational state")
    args = parser.parse_args()
    provision(Path(args.output_dir))


if __name__ == "__main__":
    main()
