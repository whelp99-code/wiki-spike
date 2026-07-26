#!/usr/bin/env python3
"""Write the Gate 1 encrypted-lifecycle decision record.

Fail-closed by construction: this script REFUSES to write
`artifacts/encrypted-lifecycle/gate1-decision.json` unless every required
input exists, is readable, and is internally consistent, and no MUST check
failed. It never fabricates a reviewer verdict -- owners/roles must be
supplied explicitly on the command line; there is no default owner.

Profile selection (pre-initialization, no runtime fallback, per stage-08/09
storage decision and R10 supersession):
  - "A" (SQLCipher) if at least one supplied feasibility result has
    status "ok" and must_verdict "PASS".
  - "B" (field-AEAD) if every supplied feasibility result is
    "platform_unavailable" (SQLCipher was never testable, so profile A
    cannot be claimed, and the pre-initialization choice falls to the
    always-available field-AEAD profile).
  - internally "UNRESOLVED" if zero feasibility results were supplied, or
    if any supplied result has must_verdict "FAIL" (a MUST failure blocks
    Gate 1 outright). The gate1-decision-v1 schema's `profile_selection`
    enum only admits "A"/"B" -- an UNRESOLVED outcome is never written as
    a schema value; the writer refuses to emit any file instead.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

GATE1_SCHEMA = "wiki-gate1-decision-v1"


class DecisionRefused(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    def normalize(v: Any, path: str) -> Any:
        if v is None or isinstance(v, bool):
            return v
        if isinstance(v, str):
            return unicodedata.normalize("NFC", v)
        if isinstance(v, (int, float)):
            raise DecisionRefused("RAW_NUMERIC_TOKEN", f"raw numeric token at {path}")
        if isinstance(v, list):
            return [normalize(item, f"{path}[{i}]") for i, item in enumerate(v)]
        if isinstance(v, Mapping):
            out: dict[str, Any] = {}
            for k, item in v.items():
                nk = unicodedata.normalize("NFC", str(k))
                out[nk] = normalize(item, f"{path}.{nk}")
            return {k: out[k] for k in sorted(out)}
        raise DecisionRefused("UNSUPPORTED_VALUE", f"unsupported value at {path}")

    normalized = normalize(value, "$")
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _require_file(path: Path, code: str, label: str) -> None:
    if not path.is_file():
        raise DecisionRefused(code, f"required input missing or not a file: {label} ({path})")


def load_feasibility_results(paths: list[Path]) -> list[dict[str, Any]]:
    results = []
    for p in paths:
        _require_file(p, "FEASIBILITY_INPUT_MISSING", str(p))
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DecisionRefused("FEASIBILITY_INPUT_INVALID_JSON", f"{p}: {exc}") from exc
        if not isinstance(data, dict) or "status" not in data or "must_verdict" not in data:
            raise DecisionRefused("FEASIBILITY_INPUT_MALFORMED", f"{p} is missing required status/must_verdict fields")
        results.append(data)
    return results


def load_vector_validation(path: Path) -> dict[str, Any]:
    _require_file(path, "VECTOR_VALIDATION_INPUT_MISSING", str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DecisionRefused("VECTOR_VALIDATION_INPUT_INVALID_JSON", f"{path}: {exc}") from exc
    if not isinstance(data, dict):
        raise DecisionRefused("VECTOR_VALIDATION_INPUT_MALFORMED", f"{path} top level is not a JSON object")
    verdict = data.get("verdict") or data.get("status") or data.get("result")
    if verdict is None:
        raise DecisionRefused("VECTOR_VALIDATION_INPUT_NO_VERDICT", f"{path} has no verdict/status/result field")
    if str(verdict).upper() not in ("PASS", "OK", "PASSED"):
        raise DecisionRefused("VECTOR_VALIDATION_FAILED", f"{path} reports verdict={verdict!r}, not a passing result")
    if data.get("cryptography_available") is not True:
        raise DecisionRefused("VECTOR_VALIDATION_CRYPTO_UNAVAILABLE", f"{path}: cryptography_available is not true; signature checks were skipped (fail-closed)")
    if data.get("jsonschema_available") is not True:
        raise DecisionRefused("VECTOR_VALIDATION_JSONSCHEMA_UNAVAILABLE", f"{path}: jsonschema_available is not true; schema strictness was skipped (fail-closed)")
    return data


def resolve_profile(feasibility_results: list[dict[str, Any]]) -> str:
    if not feasibility_results:
        raise DecisionRefused("PROFILE_UNRESOLVED_NO_FEASIBILITY", "zero feasibility results supplied; both-platform absence leaves profile selection unresolved")
    for r in feasibility_results:
        if r.get("must_verdict") == "FAIL":
            raise DecisionRefused("MUST_CHECK_FAILED", f"a supplied feasibility result reports must_verdict=FAIL (platform={r.get('platform')})")
    if any(r.get("status") == "ok" and r.get("must_verdict") == "PASS" for r in feasibility_results):
        return "A"
    if all(r.get("status") == "platform_unavailable" for r in feasibility_results):
        return "B"
    raise DecisionRefused("PROFILE_UNRESOLVED_AMBIGUOUS", "feasibility results are neither a clean SQLCipher PASS nor a uniform platform_unavailable set")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--feasibility", action="append", default=[], help="path to a sqlcipher-feasibility JSON (repeatable)")
    parser.add_argument("--expected-producer-commit", default=None, help="required commit recorded by every imported feasibility result")
    parser.add_argument("--vector-validation", required=True, help="path to the independent vector validator receipt")
    parser.add_argument("--adr", action="append", required=True, help="ADR markdown path (repeatable, e.g. docs/adr/ADR-0026-*.md)")
    parser.add_argument("--schemas-dir", required=True, help="directory of encrypted-lifecycle JSON schemas")
    parser.add_argument("--fixtures-dir", default=None, help="directory of frozen vector fixtures (optional)")
    parser.add_argument("--owner", action="append", default=[], required=True, help="actor_id:ROLE, repeatable (ROLE in ARCHITECT/CRITIC/EXECUTOR_OWNER/PRODUCT_OWNER)")
    parser.add_argument(
        "--residual-claim",
        action="append",
        default=[],
        help="a documented residual-claim/limitation string (repeatable)",
    )
    parser.add_argument("--extraction-precision-min", default="80", help="decimal-string integer, e.g. 80 for 80%%")
    parser.add_argument("--extraction-recall-min", default="80", help="decimal-string integer, e.g. 80 for 80%%")
    parser.add_argument("--recall-p95-ms-advisory", default="200")
    parser.add_argument("--candidate-p95-ms-advisory", default="500")
    parser.add_argument("--output", default="artifacts/encrypted-lifecycle/gate1-decision.json")
    args = parser.parse_args(argv)

    try:
        if args.expected_producer_commit is not None and not re.fullmatch(r"[0-9a-f]{40}", args.expected_producer_commit):
            raise DecisionRefused("EXPECTED_COMMIT_INVALID", "expected producer commit must be 40 lowercase hex characters")
        feasibility_paths = [Path(p) for p in args.feasibility]
        feasibility_results = load_feasibility_results(feasibility_paths)
        if args.expected_producer_commit is not None and any(result.get("recorded_commit") != args.expected_producer_commit for result in feasibility_results):
            raise DecisionRefused("FEASIBILITY_COMMIT_MISMATCH", "feasibility recorded_commit must equal the detached producer commit")
        vector_validation_path = Path(args.vector_validation)
        vector_validation = load_vector_validation(vector_validation_path)

        adr_paths = [Path(p) for p in args.adr]
        for adr in adr_paths:
            _require_file(adr, "ADR_INPUT_MISSING", str(adr))

        schemas_dir = Path(args.schemas_dir)
        if not schemas_dir.is_dir():
            raise DecisionRefused("SCHEMAS_DIR_MISSING", str(schemas_dir))
        schema_files = sorted(schemas_dir.glob("*.schema.json"))
        if not schema_files:
            raise DecisionRefused("SCHEMAS_DIR_EMPTY", str(schemas_dir))

        fixture_files: list[Path] = []
        if args.fixtures_dir:
            fixtures_dir = Path(args.fixtures_dir)
            if fixtures_dir.is_dir():
                fixture_files = sorted(f for f in fixtures_dir.rglob("*") if f.is_file())

        owners = []
        for spec in args.owner:
            if ":" not in spec:
                raise DecisionRefused("OWNER_SPEC_MALFORMED", f"expected actor_id:ROLE, got {spec!r}")
            actor_id, role = spec.split(":", 1)
            if role not in ("ARCHITECT", "CRITIC", "EXECUTOR_OWNER", "PRODUCT_OWNER"):
                raise DecisionRefused("OWNER_ROLE_INVALID", f"unknown role {role!r} in {spec!r}")
            owners.append({"actor_id": actor_id, "role": role})
        if not owners:
            raise DecisionRefused("OWNERS_EMPTY", "at least one --owner is required; reviewer verdicts are never fabricated")

        contract_digests: dict[str, str] = {}
        for f in schema_files + adr_paths + [vector_validation_path] + fixture_files:
            key = str(f)
            contract_digests[key] = sha256_file(f)

        profile = resolve_profile(feasibility_results)

        adr_refs = sorted({p.stem.split("-", 2)[0] + "-" + p.stem.split("-", 2)[1] for p in adr_paths})

        decision = {
            "schema": GATE1_SCHEMA,
            "owners": owners,
            "adr_refs": adr_refs,
            "profile_selection": profile,
            "metric_freeze": {
                "extraction_precision_min": args.extraction_precision_min,
                "extraction_recall_min": args.extraction_recall_min,
                "recall_p95_ms_advisory": args.recall_p95_ms_advisory,
                "candidate_p95_ms_advisory": args.candidate_p95_ms_advisory,
            },
            "contract_digests": contract_digests,
            "residual_claims": args.residual_claim,
            "decided_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        canonical_bytes(decision)  # validates decision itself has no raw numbers / unsupported values
    except DecisionRefused as exc:
        print(f"REFUSED [{exc.code}] {exc.message}", file=sys.stderr)
        return 1

    output_path = Path(args.output)
    if output_path.exists():
        print(f"REFUSED [OUTPUT_EXISTS] refusing to overwrite {output_path}", file=sys.stderr)
        return 1
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(canonical_bytes(decision))
    print(f"wrote {output_path} profile_selection={decision['profile_selection']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
