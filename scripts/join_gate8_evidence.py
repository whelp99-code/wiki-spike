#!/usr/bin/env python3
"""Gate 8 dispatch-only evidence join for the Encrypted Single-Memory Lifecycle.

Strictly imports the three explicitly selected immutable bundles, binds Gate 1
to its own commit, binds conformance and canary to one implementation commit,
and preserves all three import receipts verbatim. This script emits only the
verdict-free pre-review manifest and evidence join; it never manufactures a
delivery verdict or review attestation.
"""
from __future__ import annotations

import argparse
import time
from decimal import Decimal
import re
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))
if str(_REPO_ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "scripts"))

from wiki_spike.infrastructure.conformance import (  # noqa: E402
    CANARY,
    CONFORMANCE,
    GATE1,
    ConformanceError,
    build_evidence_join,
    build_pre_review_manifest,
)
from import_encrypted_lifecycle_bundle import (  # noqa: E402
    ENVELOPE_ENTRY_PATH,
    BundleImportError,
    import_bundle,
    load_archive,
    strict_document,
)

LANE_ORDER = (GATE1, CONFORMANCE, CANARY)

LANE_SPECS = {
    GATE1: {"artifact_kind": "GATE1_DECISION", "payload_path": "payload/gate1-decision.json", "payload_schema": "wiki-gate1-decision-v1", "platform": "self-hosted/macos-15/arm64/wiki-gate1-workstation", "payload_fields": {}},
    CONFORMANCE: {"artifact_kind": "CONFORMANCE_PRE_CANARY", "payload_path": "payload/conformance-pre-canary.json", "payload_schema": "wiki-gate8-conformance-report-v1", "platform": "self-hosted/macos-15/arm64/wiki-conformance-workstation", "payload_fields": {"conformant": True}},
    CANARY: {"artifact_kind": "CANARY_24H", "payload_path": "payload/rollout-evidence.json", "payload_schema": "wiki-gate8-canary-report-v1", "platform": "self-hosted/macos-15/arm64/wiki-canary-workstation", "payload_fields": {"evidence_lane": "CANARY_24H", "healthy": True, "configured_duration_seconds": "86400", "interval_seconds": "900", "failure_count": "0"}},
}


def _import_lane(lane: str, lane_dir: Path, expected: dict) -> tuple[dict, dict, dict]:
    """Strictly import exactly one explicitly selected archive."""
    archives = list(lane_dir.glob("*.tar"))
    if len(archives) != 1:
        raise BundleImportError("ARCHIVE_CARDINALITY_INVALID", f"{lane} must contain exactly one bundle tar")
    files = load_archive(archives[0])
    envelope = strict_document(files[ENVELOPE_ENTRY_PATH], "envelope")
    strict_expected = {
        "repository": expected["repository"], "artifact_kind": expected["artifact_kind"],
        "platform": expected["platform"], "producer_commit": expected["producer_commit"],
        "contract_digest": expected["contract_digest"], "toolchain_lock_digest": expected["toolchain_lock_digest"],
        "workflow_file_digest": expected["workflow_file_digest"], "workflow_run_id": expected["workflow_run_id"],
        "workflow_run_attempt": expected["workflow_run_attempt"], "artifact_name": expected["artifact_name"],
        "bundle_sha256": expected["bundle_sha256"], "payload_paths": expected["payload_paths"],
        "payload_sha256": envelope["payload_sha256"], "source_run_url": expected["source_run_url"],
    }
    receipt = import_bundle(archives[0], expected=strict_expected)
    payload = strict_document(files[expected["payload_path"]], expected["payload_path"])
    return receipt, envelope, payload


def _validate_payload(lane: str, payload: dict, implementation_commit: str, expected: dict) -> None:
    if lane == GATE1:
        required = {
            "schema", "owners", "adr_refs", "profile_selection", "metric_freeze",
            "contract_digests", "residual_claims", "decided_at",
        }
        if set(payload) != required or payload.get("schema") != LANE_SPECS[lane]["payload_schema"]:
            raise BundleImportError("GATE1_PAYLOAD_SCHEMA_INVALID", "gate1 decision must use the closed schema")
        if payload["profile_selection"] not in ("A", "B") or not payload["owners"] or not payload["adr_refs"] or not payload["contract_digests"]:
            raise BundleImportError("GATE1_PAYLOAD_NOT_PASS", "gate1 decision does not record a complete accepted profile")
        return
    if lane == CONFORMANCE:
        required = {"schema", "conformant", "checks", "implementation_commit"}
        if set(payload) != required or payload.get("schema") != LANE_SPECS[lane]["payload_schema"]:
            raise BundleImportError("CONFORMANCE_PAYLOAD_SCHEMA_INVALID", "conformance report must use the closed schema")
        checks = payload["checks"]
        if payload["conformant"] is not True or payload["implementation_commit"] != implementation_commit or not isinstance(checks, dict) or not checks:
            raise BundleImportError("CONFORMANCE_PAYLOAD_NOT_PASS", "conformance report is not a PASS for the implementation commit")
        if any(not isinstance(check, dict) or set(check) != {"passed", "detail"} or check["passed"] is not True for check in checks.values()):
            raise BundleImportError("CONFORMANCE_PAYLOAD_NOT_PASS", "every conformance check must pass")
        return
    required = {
        "schema", "evidence_lane", "healthy", "probe_count", "failure_count",
        "configured_duration_seconds", "interval_seconds", "original_workflow_run_id",
        "observed_duration_seconds", "produced_at", "started_at", "started_at_epoch",
        "finished_at", "finished_at_epoch", "probes", "provenance",
    }
    if set(payload) != required or payload.get("schema") != LANE_SPECS[CANARY]["payload_schema"]:
        raise BundleImportError("CANARY_PAYLOAD_SCHEMA_INVALID", "canary report must use the closed schema")
    for field, value in LANE_SPECS[CANARY]["payload_fields"].items():
        if payload.get(field) != value:
            raise BundleImportError("CANARY_PAYLOAD_MISMATCH", f"canary field {field} must equal {value!r}")
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{3}", payload["observed_duration_seconds"]):
        raise BundleImportError("CANARY_DURATION_NONCANONICAL", "observed duration must be a canonical millisecond decimal")
    if Decimal(payload["observed_duration_seconds"]) < Decimal("86400.000"):
        raise BundleImportError("CANARY_DURATION_SHORT", "canary observed duration is shorter than 86400 seconds")
    for field in ("started_at_epoch", "finished_at_epoch"):
        if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{3}", payload[field]):
            raise BundleImportError("CANARY_TIMESTAMP_NONCANONICAL", f"{field} must be a canonical millisecond epoch")
    if any(not isinstance(payload[field], str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", payload[field]) for field in ("produced_at", "started_at", "finished_at")):
        raise BundleImportError("CANARY_TIMESTAMP_NONCANONICAL", "canary report timestamps must be canonical UTC")
    expected_started = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(Decimal(payload["started_at_epoch"]))))
    expected_finished = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(Decimal(payload["finished_at_epoch"]))))
    if payload["started_at"] != expected_started or payload["finished_at"] != expected_finished or payload["produced_at"] != expected_finished:
        raise BundleImportError("CANARY_TIMESTAMP_MISMATCH", "canary UTC timestamps do not match their canonical epochs")
    started, finished = Decimal(payload["started_at_epoch"]), Decimal(payload["finished_at_epoch"])
    if finished < started or Decimal(payload["observed_duration_seconds"]) != finished - started:
        raise BundleImportError("CANARY_DURATION_MISMATCH", "canary duration does not equal its closed timestamps")
    expected_probe_count = 86400 // 900 + 1
    if payload.get("probe_count") != str(expected_probe_count):
        raise BundleImportError("CANARY_PROBE_COVERAGE_MISMATCH", "canary must contain exactly 97 scheduled probes")
    probes = payload.get("probes")
    if not isinstance(probes, list) or len(probes) != expected_probe_count:
        raise BundleImportError("CANARY_PROBE_COVERAGE_MISMATCH", "canary probes do not cover the exact 24-hour schedule")
    previous_completed = started
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict) or set(probe) != {"probe_index", "passed", "error", "elapsed_seconds", "scheduled_at_epoch", "completed_at_epoch"} or probe.get("probe_index") != str(index) or probe.get("passed") is not True:
            raise BundleImportError("CANARY_UNHEALTHY_PROBE", f"canary probe {index} is missing, reordered, or unhealthy")
        for field in ("scheduled_at_epoch", "completed_at_epoch"):
            if not isinstance(probe[field], str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)\.[0-9]{3}", probe[field]):
                raise BundleImportError("CANARY_TIMESTAMP_NONCANONICAL", f"canary probe {index} {field} is noncanonical")
        scheduled, completed = Decimal(probe["scheduled_at_epoch"]), Decimal(probe["completed_at_epoch"])
        if scheduled != started + Decimal(index * 900) or completed < previous_completed or completed < scheduled or completed > scheduled + 900:
            raise BundleImportError("CANARY_SCHEDULE_MISMATCH", f"canary probe {index} does not meet the fixed schedule")
        previous_completed = completed
    provenance = payload["provenance"]
    expected_provenance = {
        "repository": expected["repository"],
        "original_workflow_run_id": expected["workflow_run_id"],
        "current_workflow_run_id": expected["workflow_run_id"],
        "current_workflow_run_attempt": expected["workflow_run_attempt"],
        "implementation_commit": expected["producer_commit"],
        "platform": expected["platform"],
        "workflow_file_digest": expected["workflow_file_digest"],
        "contract_digest": expected["contract_digest"],
        "toolchain_lock_digest": expected["toolchain_lock_digest"],
        "source_run_url": expected["source_run_url"],
    }
    if provenance != expected_provenance or payload["original_workflow_run_id"] != expected_provenance["original_workflow_run_id"]:
        raise BundleImportError("CANARY_PROVENANCE_MISMATCH", "canary provenance does not equal the imported immutable tuple")


def _expected_lane(lane: str, args: argparse.Namespace) -> dict:
    spec = LANE_SPECS[lane]
    producer_commit = args.gate1_commit if lane == GATE1 else args.implementation_commit
    return {
        "repository": getattr(args, f"{lane}_repository"),
        "artifact_kind": spec["artifact_kind"],
        "producer_commit": producer_commit,
        "contract_digest": args.contract_digest,
        "toolchain_lock_digest": args.toolchain_lock_digest,
        "workflow_file_digest": getattr(args, f"{lane}_workflow_digest"),
        "workflow_run_id": getattr(args, f"{lane}_run_id"),
        "workflow_run_attempt": getattr(args, f"{lane}_run_attempt"),
        "platform": spec["platform"],
        "artifact_name": getattr(args, f"{lane}_artifact_name"),
        "bundle_sha256": getattr(args, f"{lane}_bundle_sha256"),
        "payload_path": spec["payload_path"],
        "payload_paths": list({"GATE1_DECISION": ("payload/gate1-decision.json", "payload/macos/sqlcipher-feasibility.json", "payload/ubuntu/import-receipt.json", "payload/vector-validation.json"), "CONFORMANCE_PRE_CANARY": ("payload/conformance-pre-canary.json",), "CANARY_24H": ("payload/rollout-evidence.json",)}[spec["artifact_kind"]]),
        "payload_schema": spec["payload_schema"],
        "payload_fields": spec["payload_fields"],
        "source_run_url": getattr(args, f"{lane}_source_run_url"),
    }


def _validate_explicit_tuple(lane: str, receipt: dict, envelope: dict, args: argparse.Namespace) -> None:
    expected_name = getattr(args, f"{lane}_artifact_name")
    expected_sha256 = getattr(args, f"{lane}_bundle_sha256")
    if envelope.get("artifact_name") != expected_name:
        raise BundleImportError(
            "ARTIFACT_NAME_MISMATCH",
            f"{lane} artifact_name {envelope.get('artifact_name')!r} does not match explicit tuple",
        )
    if receipt.get("bundle_sha256") != expected_sha256:
        raise BundleImportError(
            "BUNDLE_SHA256_MISMATCH",
            f"{lane} bundle_sha256 does not match explicit tuple",
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate1", required=True, help="directory of the imported gate1 bundle")
    parser.add_argument("--conformance", required=True, help="directory of the imported conformance bundle")
    parser.add_argument("--canary", required=True, help="directory of the imported canary bundle")
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--gate1-commit", required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--contract-digest", required=True)
    parser.add_argument("--toolchain-lock-digest", required=True)
    for lane in LANE_ORDER:
        parser.add_argument(f"--{lane}-run-id", required=True)
        parser.add_argument(f"--{lane}-run-attempt", required=True)
        parser.add_argument(f"--{lane}-repository", required=True)
        parser.add_argument(f"--{lane}-source-run-url", required=True)
        parser.add_argument(f"--{lane}-artifact-name", required=True)
        parser.add_argument(f"--{lane}-bundle-sha256", required=True)
        parser.add_argument(f"--{lane}-workflow-digest", required=True)
    args = parser.parse_args(argv)

    lane_dirs = {
        GATE1: Path(args.gate1),
        CONFORMANCE: Path(args.conformance),
        CANARY: Path(args.canary),
    }

    import_receipts: dict[str, dict] = {}
    bundle_refs: dict[str, dict] = {}
    try:
        for lane in LANE_ORDER:
            receipt, envelope, payload = _import_lane(lane, lane_dirs[lane], _expected_lane(lane, args))
            _validate_explicit_tuple(lane, receipt, envelope, args)
            _validate_payload(lane, payload, args.implementation_commit, _expected_lane(lane, args))
            import_receipts[lane] = receipt
            bundle_refs[lane] = receipt
    except BundleImportError as exc:
        print(f"REJECTED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1
    implementation_commit = args.implementation_commit

    try:
        manifest = build_pre_review_manifest(
            workspace_id=args.workspace_id,
            implementation_commit=implementation_commit,
            bundles=bundle_refs,
        )
        join = build_evidence_join(
            workspace_id=args.workspace_id,
            implementation_commit=implementation_commit,
            import_receipts=import_receipts,
            manifest_digest=manifest.manifest_digest,
        )
    except ConformanceError as exc:
        print(f"REJECTED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1

    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)

    manifest_doc = {
        "schema": manifest.schema,
        "workspace_id": manifest.workspace_id,
        "implementation_commit": manifest.implementation_commit,
        "bundles": [{"lane": b.lane, "receipt": b.receipt} for b in manifest.bundles],
        "manifest_digest": manifest.manifest_digest,
    }
    join_doc = {
        "schema": join.schema,
        "workspace_id": join.workspace_id,
        "implementation_commit": join.implementation_commit,
        "import_receipts": [{"lane": lane, "receipt": receipt} for lane, receipt in join.import_receipts],
        "manifest_digest": join.manifest_digest,
        "join_digest": join.join_digest,
    }
    (out / "pre-review-manifest.json").write_text(
        json.dumps(manifest_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "evidence-join.json").write_text(
        json.dumps(join_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"implementation_commit={implementation_commit}")
    print(f"manifest_digest={manifest.manifest_digest}")
    print(f"join_digest={join.join_digest}")
    print(f"wrote {out/'pre-review-manifest.json'} and {out/'evidence-join.json'}")
    print("verdict-free: attestations/receipt are produced by the review process over manifest_digest")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
