#!/usr/bin/env python3
"""Build the evaluation-governance bundle whose digest DB-05 must bind.

DB-05 requires its signed record to bind digests for the encryption/capability
isolation design, owner consent and label review, the benchmark and holdout
manifests proving separation, the frozen SLOs and denominator rules, and the
benchmark isolation fixtures. `EvaluationGovernanceV1` is exactly that bundle,
and its `governance_digest` is the value DB-05's `evidence_digest` takes.

Each digest this tool computes is derived from real input: corpus item digests
come from hashing files, and every binding digest is recomputed by the same
contract code that will later validate the record. It fabricates nothing. Where
an attestation must come from a human process -- consent, label review,
separation, isolation -- the tool takes the digest as input and refuses to
invent one.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from second_brain_evidence_common import (  # noqa: E402
    EvidenceToolError,
    dispatch_version,
    emit,
    item_digests,
    load_object,
    run,
)
from wiki_spike.memory_core.second_brain_evaluation_contracts import (  # noqa: E402
    BENCHMARK_MANIFEST_V1,
    EVALUATION_GOVERNANCE_V1,
    HOLDOUT_MANIFEST_V1,
    RECALL_SLO_V1,
    BenchmarkManifestV1,
    EvaluationGovernanceV1,
    HoldoutManifestV1,
    RecallSloV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (  # noqa: E402
    canonical_ledger_digest,
)


def cmd_items(args: argparse.Namespace) -> int:
    digests = item_digests(Path(args.corpus_dir))
    print(json.dumps({"count": len(digests), "item_digests": digests}, indent=2))
    return 0


def cmd_slo(args: argparse.Namespace) -> int:
    body = {
        "slo_version": RECALL_SLO_V1,
        "parity_min_bps": args.parity_min_bps,
        "citation_min_bps": args.citation_min_bps,
        "completeness_min_bps": args.completeness_min_bps,
        "availability_min_bps": args.availability_min_bps,
        "max_safety_violations": 0,
        "min_shadow_days": args.min_shadow_days,
        "min_parity_cases_per_source": args.min_parity_cases_per_source,
        "min_cohort_e2e_queries": args.min_cohort_e2e_queries,
        "confidence_method": "one-sided-wilson-95",
        "include_invalid_in_denominator": True,
        "include_abstained_in_denominator": True,
        "include_source_unavailable_in_denominator": True,
    }
    body["slo_digest"] = canonical_ledger_digest("recall-slo-v1", body)
    RecallSloV1.from_mapping(body)
    return emit(
        {k: v for k, v in body.items() if k != "slo_digest"}, "slo_digest", "recall-slo-v1", args.out
    )


def cmd_benchmark(args: argparse.Namespace) -> int:
    body = {
        "manifest_version": BENCHMARK_MANIFEST_V1,
        "workspace_ref": args.workspace_ref,
        "corpus_key_ref": args.corpus_key_ref,
        "capability_ref": args.capability_ref,
        "item_digests": item_digests(Path(args.corpus_dir)),
        "label_review_digest": args.label_review_digest,
        "consent_digest": args.consent_digest,
    }
    probe = dict(body)
    probe["manifest_digest"] = canonical_ledger_digest("benchmark-manifest-v1", body)
    BenchmarkManifestV1.from_mapping(probe)
    return emit(body, "manifest_digest", "benchmark-manifest-v1", args.out)


def cmd_holdout(args: argparse.Namespace) -> int:
    body = {
        "manifest_version": HOLDOUT_MANIFEST_V1,
        "workspace_ref": args.workspace_ref,
        "holdout_key_ref": args.holdout_key_ref,
        "capability_ref": args.capability_ref,
        "item_digests": item_digests(Path(args.corpus_dir)),
        "separation_digest": args.separation_digest,
    }
    probe = dict(body)
    probe["manifest_digest"] = canonical_ledger_digest("holdout-manifest-v1", body)
    HoldoutManifestV1.from_mapping(probe)
    return emit(body, "manifest_digest", "holdout-manifest-v1", args.out)


def cmd_governance(args: argparse.Namespace) -> int:
    benchmark = BenchmarkManifestV1.from_mapping(load_object(Path(args.benchmark)))
    holdout = HoldoutManifestV1.from_mapping(load_object(Path(args.holdout)))
    slo = RecallSloV1.from_mapping(load_object(Path(args.slo)))
    shared = set(benchmark.item_digests) & set(holdout.item_digests)
    if shared:
        raise EvidenceToolError(
            f"{len(shared)} item(s) appear in both the benchmark and the holdout; "
            "separation is the property this manifest pair exists to prove"
        )
    if benchmark.corpus_key_ref == holdout.holdout_key_ref:
        raise EvidenceToolError(
            "benchmark and holdout must use separate keys, not one key under two names"
        )
    body = {
        "governance_version": EVALUATION_GOVERNANCE_V1,
        "workspace_ref": args.workspace_ref,
        "benchmark_manifest_digest": benchmark.manifest_digest,
        "holdout_manifest_digest": holdout.manifest_digest,
        "slo_digest": slo.slo_digest,
        "consent_digest": benchmark.consent_digest,
        "encryption_isolation_digest": args.encryption_isolation_digest,
        "serving_corpus_digest": args.serving_corpus_digest,
    }
    probe = dict(body)
    probe["governance_digest"] = canonical_ledger_digest("evaluation-governance-v1", body)
    EvaluationGovernanceV1.from_mapping(probe)
    result = emit(body, "governance_digest", "evaluation-governance-v1", args.out)
    print(
        "This governance_digest is the value DB-05's evidence_digest takes.",
        file=sys.stderr,
    )
    return result


# Each artifact carries its own binding digest under its own field name.
# EvaluationGovernanceV1 also holds a slo_digest, so probing attributes in turn
# reports the wrong value for it; dispatch on the version instead.
_ARTIFACTS = {
    RECALL_SLO_V1: (RecallSloV1, "slo_digest"),
    BENCHMARK_MANIFEST_V1: (BenchmarkManifestV1, "manifest_digest"),
    HOLDOUT_MANIFEST_V1: (HoldoutManifestV1, "manifest_digest"),
    EVALUATION_GOVERNANCE_V1: (EvaluationGovernanceV1, "governance_digest"),
}
_VERSION_FIELDS = ("manifest_version", "slo_version", "governance_version")


def cmd_verify(args: argparse.Namespace) -> int:
    path = Path(args.file)
    data = load_object(path)
    version, loader, digest_field = dispatch_version(path, data, _VERSION_FIELDS, _ARTIFACTS)
    loaded = loader.from_mapping(data)
    print(
        json.dumps(
            {
                "file": str(path),
                "version": version,
                "digest_field": digest_field,
                "digest": getattr(loaded, digest_field),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    items = sub.add_parser("items", help="hash a corpus directory into item digests")
    items.add_argument("--corpus-dir", required=True)
    items.set_defaults(func=cmd_items)

    slo = sub.add_parser("slo", help="freeze the numerical SLOs")
    slo.add_argument("--parity-min-bps", type=int, required=True)
    slo.add_argument("--citation-min-bps", type=int, required=True)
    slo.add_argument("--completeness-min-bps", type=int, required=True)
    slo.add_argument("--availability-min-bps", type=int, required=True)
    slo.add_argument("--min-shadow-days", type=int, default=3)
    slo.add_argument("--min-parity-cases-per-source", type=int, default=200)
    slo.add_argument("--min-cohort-e2e-queries", type=int, default=500)
    slo.add_argument("--out")
    slo.set_defaults(func=cmd_slo)

    benchmark = sub.add_parser("benchmark-manifest", help="build the benchmark manifest")
    benchmark.add_argument("--corpus-dir", required=True)
    benchmark.add_argument("--workspace-ref", required=True)
    benchmark.add_argument("--corpus-key-ref", required=True)
    benchmark.add_argument("--capability-ref", required=True)
    benchmark.add_argument("--label-review-digest", required=True)
    benchmark.add_argument("--consent-digest", required=True)
    benchmark.add_argument("--out")
    benchmark.set_defaults(func=cmd_benchmark)

    holdout = sub.add_parser("holdout-manifest", help="build the holdout manifest")
    holdout.add_argument("--corpus-dir", required=True)
    holdout.add_argument("--workspace-ref", required=True)
    holdout.add_argument("--holdout-key-ref", required=True)
    holdout.add_argument("--capability-ref", required=True)
    holdout.add_argument("--separation-digest", required=True)
    holdout.add_argument("--out")
    holdout.set_defaults(func=cmd_holdout)

    governance = sub.add_parser(
        "governance", help="bind everything into the digest DB-05 must reference"
    )
    governance.add_argument("--benchmark", required=True)
    governance.add_argument("--holdout", required=True)
    governance.add_argument("--slo", required=True)
    governance.add_argument("--workspace-ref", required=True)
    governance.add_argument("--encryption-isolation-digest", required=True)
    governance.add_argument("--serving-corpus-digest", required=True)
    governance.add_argument("--out")
    governance.set_defaults(func=cmd_governance)

    verify = sub.add_parser("verify", help="revalidate any artifact this tool produced")
    verify.add_argument("--file", required=True)
    verify.set_defaults(func=cmd_verify)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args.func, args)


if __name__ == "__main__":
    raise SystemExit(main())
