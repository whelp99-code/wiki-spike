"""Tests for scripts/second_brain_evaluation_governance.py.

DB-05 cannot be signed without an `evidence_digest`, and that digest is the
`governance_digest` of an `EvaluationGovernanceV1`. No benchmark or holdout
manifest existed in the repository, so the record was unsignable no matter who
consented. This tool builds that bundle.

These tests pin the two things that matter: the digest it reports is the one a
signer must paste into DB-05, and the separation the manifest pair exists to
prove is actually enforced.
"""
from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    EVALUATION_GOVERNANCE_V1,
    EvaluationGovernanceV1,
)

SCRIPT = (
    Path(__file__).resolve().parents[2] / "scripts" / "second_brain_evaluation_governance.py"
)


def load_tool():
    spec = importlib.util.spec_from_file_location("second_brain_evaluation_governance", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()
WORKSPACE = "workspace:second-brain-final"


def digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def corpus(root: Path, name: str, bodies: list[str]) -> Path:
    directory = root / name
    directory.mkdir()
    for index, text in enumerate(bodies):
        (directory / f"{index}.md").write_text(text, encoding="utf-8")
    return directory


def build_slo(tmp_path: Path, **overrides) -> Path:
    out = tmp_path / "slo.json"
    args = {
        "--parity-min-bps": "9000",
        "--citation-min-bps": "9000",
        "--completeness-min-bps": "9000",
        "--availability-min-bps": "9900",
    }
    args.update(overrides)
    flat = [item for pair in args.items() for item in pair]
    assert TOOL.main(["slo", *flat, "--out", str(out)]) == 0
    return out


def build_benchmark(tmp_path: Path, directory: Path, key: str = "key:benchmark-2026") -> Path:
    out = tmp_path / f"benchmark-{directory.name}.json"
    assert (
        TOOL.main(
            [
                "benchmark-manifest",
                "--corpus-dir", str(directory),
                "--workspace-ref", WORKSPACE,
                "--corpus-key-ref", key,
                "--capability-ref", "capability:benchmark-read",
                "--label-review-digest", digest("label-review"),
                "--consent-digest", digest("consent"),
                "--out", str(out),
            ]
        )
        == 0
    )
    return out


def build_holdout(tmp_path: Path, directory: Path, key: str = "key:holdout-2026") -> Path:
    out = tmp_path / f"holdout-{directory.name}.json"
    assert (
        TOOL.main(
            [
                "holdout-manifest",
                "--corpus-dir", str(directory),
                "--workspace-ref", WORKSPACE,
                "--holdout-key-ref", key,
                "--capability-ref", "capability:holdout-read",
                "--separation-digest", digest("separation"),
                "--out", str(out),
            ]
        )
        == 0
    )
    return out


def governance_args(tmp_path: Path, benchmark: Path, holdout: Path, slo: Path, **overrides):
    args = {
        "--benchmark": str(benchmark),
        "--holdout": str(holdout),
        "--slo": str(slo),
        "--workspace-ref": WORKSPACE,
        "--encryption-isolation-digest": digest("isolation"),
        "--serving-corpus-digest": digest("serving"),
    }
    args.update(overrides)
    return ["governance", *[item for pair in args.items() for item in pair]]


@pytest.fixture
def bundle(tmp_path):
    bench = corpus(tmp_path, "bench", ["b1", "b2", "b3"])
    hold = corpus(tmp_path, "hold", ["h1", "h2"])
    return (
        build_benchmark(tmp_path, bench),
        build_holdout(tmp_path, hold),
        build_slo(tmp_path),
    )


def test_governance_digest_is_the_value_db05_must_bind(tmp_path, bundle, capsys):
    benchmark, holdout, slo = bundle
    out = tmp_path / "governance.json"
    assert TOOL.main(governance_args(tmp_path, benchmark, holdout, slo, **{"--out": str(out)})) == 0
    reported = json.loads(capsys.readouterr().out)["governance_digest"]
    record = json.loads(out.read_text(encoding="utf-8"))
    # The contract must accept it, and the reported digest must be the bound one.
    loaded = EvaluationGovernanceV1.from_mapping(record)
    assert loaded.governance_digest == reported == record["governance_digest"]


def test_verify_reports_the_governance_digest_not_the_embedded_slo_digest(
    tmp_path, bundle, capsys
):
    """EvaluationGovernanceV1 also carries slo_digest; verify must not report it."""
    benchmark, holdout, slo = bundle
    out = tmp_path / "governance.json"
    assert TOOL.main(governance_args(tmp_path, benchmark, holdout, slo, **{"--out": str(out)})) == 0
    capsys.readouterr()
    assert TOOL.main(["verify", "--file", str(out)]) == 0
    reported = json.loads(capsys.readouterr().out)
    record = json.loads(out.read_text(encoding="utf-8"))
    assert reported["digest_field"] == "governance_digest"
    assert reported["digest"] == record["governance_digest"]
    assert reported["digest"] != record["slo_digest"]


def test_an_item_shared_with_the_holdout_is_refused(tmp_path):
    shared = "same body in both corpora"
    bench = corpus(tmp_path, "bench", [shared, "b2"])
    leaky = corpus(tmp_path, "leaky", [shared, "h2"])
    args = governance_args(
        tmp_path,
        build_benchmark(tmp_path, bench),
        build_holdout(tmp_path, leaky),
        build_slo(tmp_path),
    )
    assert TOOL.main(args) == 2


def test_one_key_under_two_names_is_refused(tmp_path):
    bench = corpus(tmp_path, "bench", ["b1"])
    hold = corpus(tmp_path, "hold", ["h1"])
    args = governance_args(
        tmp_path,
        build_benchmark(tmp_path, bench, key="key:shared-2026"),
        build_holdout(tmp_path, hold, key="key:shared-2026"),
        build_slo(tmp_path),
    )
    assert TOOL.main(args) == 2


@pytest.mark.parametrize("reused", ["benchmark", "holdout"])
def test_reusing_a_corpus_digest_as_the_serving_corpus_is_refused(tmp_path, bundle, reused):
    benchmark, holdout, slo = bundle
    source = benchmark if reused == "benchmark" else holdout
    manifest_digest = json.loads(source.read_text(encoding="utf-8"))["manifest_digest"]
    args = governance_args(
        tmp_path,
        benchmark,
        holdout,
        slo,
        **{"--serving-corpus-digest": manifest_digest},
    )
    assert TOOL.main(args) == 2


def test_slo_below_the_enforced_floor_is_refused(tmp_path):
    with pytest.raises(AssertionError):
        build_slo(tmp_path, **{"--min-shadow-days": "2"})


def test_an_empty_or_duplicate_corpus_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert TOOL.main(["items", "--corpus-dir", str(empty)]) == 2
    duplicated = corpus(tmp_path, "dup", ["same", "same"])
    assert TOOL.main(["items", "--corpus-dir", str(duplicated)]) == 2


def test_items_reports_only_digests(tmp_path, capsys):
    bench = corpus(tmp_path, "bench", ["secret body one", "secret body two"])
    assert TOOL.main(["items", "--corpus-dir", str(bench)]) == 0
    printed = capsys.readouterr().out
    assert "secret body" not in printed
    assert json.loads(printed)["count"] == 2


def test_verify_refuses_a_file_carrying_more_than_one_version_field(tmp_path, bundle):
    benchmark, _, slo = bundle
    spliced = json.loads(benchmark.read_text(encoding="utf-8"))
    spliced["governance_version"] = EVALUATION_GOVERNANCE_V1
    path = tmp_path / "spliced.json"
    path.write_text(json.dumps(spliced), encoding="utf-8")
    assert TOOL.main(["verify", "--file", str(path)]) == 2


def test_tool_source_holds_no_private_key_material():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("PrivateKey", "private_bytes", "-----BEGIN"):
        assert forbidden not in source, f"{forbidden} must never appear in the tool"
