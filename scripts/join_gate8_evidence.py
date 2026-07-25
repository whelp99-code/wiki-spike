#!/usr/bin/env python3
"""Gate 8 evidence join for the Encrypted Single-Memory Lifecycle.

Joins the three independently produced + imported immutable bundles
(gate1, conformance, canary) into the Gate 8 review evidence:

  1. Strictly imports each lane's bundle (re-implemented strict importer;
     never trusts the builder).
  2. Requires a single producer_commit across all three lanes (same-commit
     binding).
  3. Builds the VERDICT-FREE pre-review manifest (no pass/fail) over the three
     imported bundles.
  4. Builds the evidence join preserving the three independent import receipts
     verbatim.

Outputs ``pre-review-manifest.json`` and ``evidence-join.json``. The two
independent ARCHITECT/CRITIC attestations and the separate review receipt are
produced by the review process over the emitted manifest digest (see
``wiki_spike.infrastructure.conformance``); this script never fabricates a
verdict or an attestation.
"""
from __future__ import annotations

import argparse
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
    load_bundle_files,
    strict_parse_manifest,
)

LANE_ORDER = (GATE1, CONFORMANCE, CANARY)


def _import_lane(lane: str, lane_dir: Path) -> tuple[dict, dict]:
    """Strictly import one lane's bundle and return (import_receipt, envelope)."""
    receipt = import_bundle(lane_dir)
    files = load_bundle_files(lane_dir)
    envelope = strict_parse_manifest(files[ENVELOPE_ENTRY_PATH])
    return receipt, envelope


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate1", required=True, help="directory of the imported gate1 bundle")
    parser.add_argument("--conformance", required=True, help="directory of the imported conformance bundle")
    parser.add_argument("--canary", required=True, help="directory of the imported canary bundle")
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args(argv)

    lane_dirs = {
        GATE1: Path(args.gate1),
        CONFORMANCE: Path(args.conformance),
        CANARY: Path(args.canary),
    }

    import_receipts: dict[str, dict] = {}
    bundle_refs: dict[str, dict] = {}
    commits: set[str] = set()

    try:
        for lane in LANE_ORDER:
            receipt, envelope = _import_lane(lane, lane_dirs[lane])
            import_receipts[lane] = receipt
            commits.add(envelope.get("producer_commit", ""))
            bundle_refs[lane] = {
                "artifact_name": envelope["artifact_name"],
                "artifact_kind": envelope["artifact_kind"],
                "bundle_sha256": receipt["bundle_sha256"],
                "platform": envelope.get("platform", ""),
            }
    except BundleImportError as exc:
        print(f"REJECTED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1

    if len(commits) != 1:
        print(f"REJECTED [producer_commit_mismatch] lanes bound to differing commits: {sorted(commits)}", file=sys.stderr)
        return 1
    implementation_commit = commits.pop()

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
        "bundles": [
            {
                "lane": b.lane,
                "artifact_name": b.artifact_name,
                "artifact_kind": b.artifact_kind,
                "bundle_sha256": b.bundle_sha256,
                "platform": b.platform,
            }
            for b in manifest.bundles
        ],
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
