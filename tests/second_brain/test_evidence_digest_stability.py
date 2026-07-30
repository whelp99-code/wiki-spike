"""Golden digests. These values are what a signer pastes into a decision record.

Everything else in this suite checks that a bad artifact is refused. This checks
the opposite and more consequential thing: that a *good* artifact produces the
same digest today as it did yesterday.

A signed DB-03 or DB-05 record binds one digest forever. If the canonical
encoding, a field name, a field order, or a default ever shifts, the same inputs
start producing a different digest -- every already-signed record silently stops
matching the evidence it was signed against, and no other test in this
repository would notice, because each artifact would still self-verify against
its own new digest.

The literals below were produced by running the tools. If a change makes one of
them move, that is not a test to update casually: it invalidates existing
signatures, and the decision records bound to them have to be re-signed.

Extracting the DB-05 shared plumbing into `second_brain_evidence_common.py`
rewrote 114 lines of a merged, signing-critical tool. These values were verified
byte-identical against the pre-refactor version at origin/main before being
pinned here.
"""
from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DB03 = ROOT / "scripts" / "second_brain_migration_source_evidence.py"
DB05 = ROOT / "scripts" / "second_brain_evaluation_governance.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DB03_TOOL = load(DB03, "golden_db03")
DB05_TOOL = load(DB05, "golden_db05")


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def corpus(root: Path, name: str, bodies: dict[str, str]) -> Path:
    directory = root / name
    directory.mkdir()
    for filename, body in bodies.items():
        (directory / filename).write_text(body, encoding="utf-8")
    return directory


DB03_GOLDEN = {
    "snapshot": "b92b5efe05817713787e6d71f16ffe17e67c15edd36f44dc3c134531ed82515d",
    "profile": "ad44f172be75cf9aef16888cbd41f59709d96dbc33132bb681f5b46301823fb5",
    "diff": "ebdc06683eae1beed6a83c6c709cb8a4f53d0ef9a6e02ac6c4453c4978057189",
    "treatment": "fa42a0eecb2bc57e990ed1d8d7f250561af3aee521137bb54b85b9f295f4419b",
    "evidence": "bdb3da817dc559453af1c04506b3916222af785de7d14307a15dc32fdee130db",
}

DB05_GOLDEN = {
    "slo": "a511af623ac20f648b5f7e29e7a231f2e94e5a13a31e03ed8ad33a7cbe2ff784",
    "benchmark": "f6ba94dc81c6def544b04cf6e43913c2b27c912dc013c39a1b9c1d340980614d",
    "holdout": "8502c164941e7cbbb30f0041201d91dad0db7cb4a9bc6d19bb1283c51b750d59",
    "governance": "180c933a6d0b2cc157da182e6d8597f201814eab24672645f389cf8166f5d318",
}


@pytest.fixture
def db03_artifacts(tmp_path):
    out = tmp_path / "db03-out"
    out.mkdir()
    cand = corpus(tmp_path, "cand", {"0.txt": "c-one", "1.txt": "c-two", "2.txt": "shared"})
    canon = corpus(tmp_path, "canon", {"0.txt": "shared", "1.txt": "k-only"})
    run = lambda *a: DB03_TOOL.main([str(x) for x in a])

    assert run("snapshot", "--source-name", "unified-db", "--snapshot-ref", "snapshot:golden",
               "--writers-quiesced-at", "2026-07-30T00:00:00Z",
               "--snapshot-taken-at", "2026-07-30T00:05:00Z",
               "--source-root-digest-before", d("ROOT"), "--source-root-digest-after", d("ROOT"),
               "--snapshot-package-digest", d("PKG"), "--owner-key-ref", "key:golden-owner",
               "--owner-attestation-digest", d("OWNER"), "--out", out / "snapshot.json") == 0
    assert run("export-profile", "--snapshot", out / "snapshot.json",
               "--export-method", "read-only-transaction",
               "--write-capability-probe-digest", d("PROBE"),
               "--schema-version", "golden-2026-07", "--schema-digest", d("SCHEMA"),
               "--native-identity-field", "source_id", "--native-identity-field", "native_id",
               "--identity-mapping-digest", d("IDMAP"),
               "--revision-semantics", "content-hash-revision",
               "--revision-mapping-digest", d("REVMAP"), "--watermark-cursor-field", "cursor",
               "--overlap-behavior", "replay-overlap", "--restart-evidence-digest", d("RESTART"),
               "--page-size-limit", "500", "--retention-days", "90",
               "--source-fixture-digest", d("FIXTURE"), "--out", out / "profile.json") == 0
    assert run("digests", "--dir", cand, "--out", out / "cand.json") == 0
    assert run("digests", "--dir", canon, "--out", out / "canon.json") == 0
    assert run("uniqueness-diff", "--snapshot", out / "snapshot.json",
               "--candidates", out / "cand.json", "--canonical", out / "canon.json",
               "--out", out / "diff.json") == 0
    assert run("history-treatment", "--snapshot", out / "snapshot.json",
               "--tombstone-representation", "absent",
               "--history-availability", "partial-with-proof",
               "--retained-sample", d("RET"), "--unavailable-sample", d("UNAV"),
               "--out", out / "treatment.json") == 0
    assert run("evidence", "--snapshot", out / "snapshot.json",
               "--export-profile", out / "profile.json",
               "--uniqueness-diff", out / "diff.json",
               "--history-treatment", out / "treatment.json",
               "--workspace-ref", "workspace:golden",
               "--security-review-digest", d("SEC"), "--out", out / "evidence.json") == 0
    return out


@pytest.mark.parametrize(
    "artifact,field",
    [
        ("snapshot", "snapshot_binding_digest"), ("profile", "profile_digest"),
        ("diff", "diff_digest"), ("treatment", "treatment_digest"),
        ("evidence", "evidence_digest"),
    ],
)
def test_db03_digests_are_stable(db03_artifacts, artifact, field):
    stored = json.loads((db03_artifacts / f"{artifact}.json").read_text(encoding="utf-8"))
    assert stored[field] == DB03_GOLDEN[artifact], (
        f"{artifact}.{field} moved. Fixed inputs must always yield this digest; a change "
        "here invalidates every DB-03 record already signed against the old value."
    )


@pytest.fixture
def db05_artifacts(tmp_path):
    out = tmp_path / "db05-out"
    out.mkdir()
    bench = corpus(tmp_path, "bench", {f"{i}.md": f"bench-{i}" for i in (1, 2, 3)})
    hold = corpus(tmp_path, "hold", {f"{i}.md": f"hold-{i}" for i in (1, 2)})
    run = lambda *a: DB05_TOOL.main([str(x) for x in a])

    assert run("slo", "--parity-min-bps", "9000", "--citation-min-bps", "9000",
               "--completeness-min-bps", "9000", "--availability-min-bps", "9900",
               "--out", out / "slo.json") == 0
    assert run("benchmark-manifest", "--corpus-dir", bench, "--workspace-ref", "workspace:p",
               "--corpus-key-ref", "key:b", "--capability-ref", "capability:b",
               "--label-review-digest", d("L"), "--consent-digest", d("C"),
               "--out", out / "benchmark.json") == 0
    assert run("holdout-manifest", "--corpus-dir", hold, "--workspace-ref", "workspace:p",
               "--holdout-key-ref", "key:h", "--capability-ref", "capability:h",
               "--separation-digest", d("S"), "--out", out / "holdout.json") == 0
    assert run("governance", "--benchmark", out / "benchmark.json",
               "--holdout", out / "holdout.json", "--slo", out / "slo.json",
               "--workspace-ref", "workspace:p", "--encryption-isolation-digest", d("I"),
               "--serving-corpus-digest", d("V"), "--out", out / "governance.json") == 0
    return out


@pytest.mark.parametrize(
    "artifact,field",
    [
        ("slo", "slo_digest"), ("benchmark", "manifest_digest"),
        ("holdout", "manifest_digest"), ("governance", "governance_digest"),
    ],
)
def test_db05_digests_survived_the_shared_plumbing_refactor(db05_artifacts, artifact, field):
    """Verified byte-identical against origin/main's tool before being pinned."""
    stored = json.loads((db05_artifacts / f"{artifact}.json").read_text(encoding="utf-8"))
    assert stored[field] == DB05_GOLDEN[artifact], (
        f"{artifact}.{field} moved. Extracting the shared plumbing must not change what a "
        "DB-05 signer binds; a change here invalidates records already signed against it."
    )


def test_the_two_tools_never_produce_a_colliding_digest(db03_artifacts, db05_artifacts):
    assert set(DB03_GOLDEN.values()).isdisjoint(DB05_GOLDEN.values())
