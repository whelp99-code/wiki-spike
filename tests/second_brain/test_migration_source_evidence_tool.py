"""Tests for scripts/second_brain_migration_source_evidence.py.

DB-03 cannot be signed without an `evidence_digest`, and for a migration source
that digest is the `evidence_digest` of a `MigrationSourceEvidenceV1`. No such
bundle existed, which is why the unified-db inventory stopped at
STOP_PENDING_IMMUTABLE_SNAPSHOT_AND_DIFF.

These tests pin what the tool is for: the digest it reports is the one a signer
pastes into a DB-03 body and the record then assembles and verifies, the diff it
computes is a real set difference, and no exported record content ever reaches an
artifact.
"""
from __future__ import annotations

import importlib.util
import json
from base64 import b64encode
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNATURE_VERSION,
    DecisionRecordV1,
)
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (
    MigrationSourceEvidenceV1,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "second_brain_migration_source_evidence.py"
DECISION_SCRIPT = ROOT / "scripts" / "second_brain_decision.py"
WORKSPACE = "workspace:second-brain-final"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load(SCRIPT, "second_brain_migration_source_evidence")
DECISION_TOOL = load(DECISION_SCRIPT, "second_brain_decision")


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def corpus(root: Path, name: str, bodies: list[str]) -> Path:
    directory = root / name
    directory.mkdir()
    for index, text in enumerate(bodies):
        (directory / f"{index}.txt").write_text(text, encoding="utf-8")
    return directory


def run(*args: str) -> int:
    return TOOL.main([str(arg) for arg in args])


def build_snapshot(tmp_path: Path, source: str = "unified-db", **overrides) -> Path:
    out = tmp_path / f"snapshot-{source.replace('/', '-')}.json"
    args = {
        "--source-name": source,
        "--snapshot-ref": f"snapshot:{source.replace('/', '-')}-2026-07-30",
        "--writers-quiesced-at": "2026-07-30T00:00:00Z",
        "--snapshot-taken-at": "2026-07-30T00:05:00Z",
        "--source-root-digest-before": d("root"),
        "--source-root-digest-after": d("root"),
        "--snapshot-package-digest": d("package"),
        "--owner-key-ref": "key:migration-owner-2026",
        "--owner-attestation-digest": d("owner-attestation"),
    }
    args.update(overrides)
    args["--out"] = str(out)
    assert run("snapshot", *[item for pair in args.items() for item in pair]) == 0
    return out


def build_profile(tmp_path: Path, snapshot: Path, **overrides) -> Path:
    out = tmp_path / f"profile-{snapshot.stem}.json"
    args = {
        "--snapshot": str(snapshot),
        "--export-method": "read-only-transaction",
        "--write-capability-probe-digest": d("write-capability-probe"),
        "--schema-version": "unified-db-2026-07",
        "--schema-digest": d("schema"),
        "--identity-mapping-digest": d("identity-mapping"),
        "--revision-semantics": "content-hash-revision",
        "--revision-mapping-digest": d("revision-mapping"),
        "--watermark-cursor-field": "source_cursor",
        "--overlap-behavior": "replay-overlap",
        "--restart-evidence-digest": d("restart"),
        "--page-size-limit": "500",
        "--retention-days": "90",
        "--source-fixture-digest": d("fixture"),
    }
    args.update(overrides)
    args["--out"] = str(out)
    flat = [item for pair in args.items() for item in pair]
    for field in ("source_id", "native_id", "content_hash"):
        flat += ["--native-identity-field", field]
    assert run("export-profile", *flat) == 0
    return out


def build_diff(tmp_path: Path, snapshot: Path, candidates: Path, canonical: Path) -> Path:
    out = tmp_path / f"diff-{snapshot.stem}.json"
    assert (
        run(
            "uniqueness-diff",
            "--snapshot", snapshot,
            "--candidates", candidates,
            "--canonical", canonical,
            "--out", out,
        )
        == 0
    )
    return out


def build_treatment(tmp_path: Path, snapshot: Path, **overrides) -> Path:
    out = tmp_path / f"treatment-{snapshot.stem}.json"
    args = {
        "--tombstone-representation": "absent",
        "--history-availability": "partial-with-proof",
    }
    args.update(overrides)
    flat = [item for pair in args.items() for item in pair]
    flat += ["--retained-sample", d("retained-1")]
    flat += ["--unavailable-sample", d("unavailable-1")]
    assert run("history-treatment", "--snapshot", snapshot, *flat, "--out", out) == 0
    return out


# Distinctive enough that a substring search cannot collide with hex digest text.
CANDIDATE_BODIES = ("cand-one", "cand-two", "cand-three", "in-both-corpora")
CANONICAL_BODIES = ("in-both-corpora", "canon-only")


@pytest.fixture
def pipeline(tmp_path):
    """The whole DB-03 chain: snapshot, profile, diff, treatment, bundle."""
    candidates = corpus(tmp_path, "candidates", list(CANDIDATE_BODIES))
    canonical = corpus(tmp_path, "canonical", list(CANONICAL_BODIES))
    candidate_digests = tmp_path / "candidates.json"
    canonical_digests = tmp_path / "canonical.json"
    assert run("digests", "--dir", candidates, "--out", candidate_digests) == 0
    assert run("digests", "--dir", canonical, "--out", canonical_digests) == 0
    snapshot = build_snapshot(tmp_path)
    return {
        "snapshot": snapshot,
        "profile": build_profile(tmp_path, snapshot),
        "diff": build_diff(tmp_path, snapshot, candidate_digests, canonical_digests),
        "treatment": build_treatment(tmp_path, snapshot),
        "candidate_digests": candidate_digests,
        "canonical_digests": canonical_digests,
    }


def build_evidence(tmp_path: Path, pipeline: dict, **overrides) -> Path:
    out = tmp_path / "evidence.json"
    args = {
        "--snapshot": str(pipeline["snapshot"]),
        "--export-profile": str(pipeline["profile"]),
        "--uniqueness-diff": str(pipeline["diff"]),
        "--history-treatment": str(pipeline["treatment"]),
        "--workspace-ref": WORKSPACE,
        "--security-review-digest": d("security-review"),
    }
    args.update(overrides)
    args["--out"] = str(out)
    assert run("evidence", *[item for pair in args.items() for item in pair]) == 0
    return out


def test_the_evidence_digest_is_the_value_db03_must_bind(tmp_path, pipeline, capsys):
    out = build_evidence(tmp_path, pipeline)
    reported = json.loads(capsys.readouterr().out)["evidence_digest"]
    record = json.loads(out.read_text(encoding="utf-8"))
    loaded = MigrationSourceEvidenceV1.from_mapping(record)
    assert loaded.evidence_digest == reported == record["evidence_digest"]


def test_the_uniqueness_diff_is_a_real_set_difference(tmp_path, pipeline):
    """Expected digests are computed from the corpus bodies, not from the tool's own filter."""
    diff = json.loads(pipeline["diff"].read_text(encoding="utf-8"))
    # Only "in-both-corpora" appears on both sides, so exactly the three
    # cand-* bodies are unique, in the sorted-filename order `digests` emits.
    assert diff["unique_item_digests"] == [
        sha256(body.encode("utf-8")).hexdigest()
        for body in ("cand-one", "cand-two", "cand-three")
    ]
    assert sha256(b"in-both-corpora").hexdigest() not in diff["unique_item_digests"]
    assert diff["candidate_item_count"] == "4"
    assert diff["duplicate_item_count"] == "1"
    assert diff["unique_item_count"] == "3"


def test_a_source_that_adds_nothing_is_reported_as_such(tmp_path, capsys):
    shared = corpus(tmp_path, "shared", ["a", "b"])
    digests = tmp_path / "shared.json"
    assert run("digests", "--dir", shared, "--out", digests) == 0
    snapshot = build_snapshot(tmp_path)
    out = tmp_path / "empty-diff.json"
    assert (
        run(
            "uniqueness-diff",
            "--snapshot", snapshot,
            "--candidates", digests,
            "--canonical", digests,
            "--out", out,
        )
        == 0
    )
    captured = capsys.readouterr()
    assert "adds nothing" in captured.err
    assert json.loads(out.read_text(encoding="utf-8"))["unique_item_count"] == "0"


@pytest.mark.parametrize(
    "artifact,field",
    [
        ("snapshot", "snapshot_binding_digest"),
        ("profile", "profile_digest"),
        ("diff", "diff_digest"),
        ("treatment", "treatment_digest"),
    ],
)
def test_verify_reports_each_artifacts_own_binding_digest(
    tmp_path, pipeline, capsys, artifact, field
):
    path = pipeline[artifact]
    assert run("verify", "--file", path) == 0
    reported = json.loads(capsys.readouterr().out)
    stored = json.loads(path.read_text(encoding="utf-8"))
    assert reported["digest_field"] == field
    assert reported["digest"] == stored[field]


def test_verify_never_reports_a_borrowed_digest(tmp_path, pipeline, capsys):
    """The bundle carries four other artifacts' digests; verify must skip them."""
    out = build_evidence(tmp_path, pipeline)
    capsys.readouterr()
    assert run("verify", "--file", out) == 0
    reported = json.loads(capsys.readouterr().out)
    stored = json.loads(out.read_text(encoding="utf-8"))
    assert reported["digest_field"] == "evidence_digest"
    assert reported["digest"] == stored["evidence_digest"]
    borrowed = {
        stored[key]
        for key in (
            "snapshot_binding_digest",
            "export_profile_digest",
            "uniqueness_diff_digest",
            "history_treatment_digest",
        )
    }
    assert reported["digest"] not in borrowed


def test_digests_reports_only_digests(tmp_path, capsys):
    directory = corpus(tmp_path, "secrets", ["private body one", "private body two"])
    assert run("digests", "--dir", directory) == 0
    printed = capsys.readouterr().out
    assert "private body" not in printed
    assert json.loads(printed)["count"] == 2


def test_no_exported_content_reaches_any_artifact(tmp_path, pipeline):
    """Neither a record body nor the file name that held it may appear anywhere."""
    for path in pipeline.values():
        text = path.read_text(encoding="utf-8")
        for body in CANDIDATE_BODIES + CANONICAL_BODIES:
            assert body not in text
        for name in ("0.txt", "1.txt", "candidates/", "canonical/"):
            assert name not in text


def test_an_empty_or_byte_identical_export_is_refused(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    assert run("digests", "--dir", empty) == 2
    duplicated = corpus(tmp_path, "dup", ["same", "same"])
    assert run("digests", "--dir", duplicated) == 2


def test_a_symlink_in_the_export_tree_is_refused_not_followed(tmp_path):
    directory = corpus(tmp_path, "linked", ["real"])
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (directory / "link.txt").symlink_to(outside)
    assert run("digests", "--dir", directory) == 2


def test_a_digest_list_with_duplicates_is_refused(tmp_path, pipeline):
    doubled = tmp_path / "doubled.json"
    doubled.write_text(json.dumps([d("x"), d("x")]), encoding="utf-8")
    assert (
        run(
            "uniqueness-diff",
            "--snapshot", pipeline["snapshot"],
            "--candidates", doubled,
            "--canonical", pipeline["canonical_digests"],
        )
        == 2
    )


def test_verify_refuses_a_file_carrying_more_than_one_version_field(tmp_path, pipeline):
    spliced = json.loads(pipeline["snapshot"].read_text(encoding="utf-8"))
    spliced["diff_version"] = "second-brain-migration-uniqueness-diff-v1"
    path = tmp_path / "spliced.json"
    path.write_text(json.dumps(spliced), encoding="utf-8")
    assert run("verify", "--file", path) == 2


def test_duplicate_json_keys_are_refused(tmp_path, pipeline):
    path = tmp_path / "duplicated.json"
    path.write_text('{"snapshot_version": "a", "snapshot_version": "b"}', encoding="utf-8")
    assert run("verify", "--file", path) == 2


def raw_public_bytes(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def envelope(tmp_path: Path, role: str, key: Ed25519PrivateKey, signed: bytes) -> Path:
    path = tmp_path / f"{role}.env.json"
    path.write_text(
        json.dumps(
            {
                "signature_version": DECISION_SIGNATURE_VERSION,
                "role": role,
                "key_id": f"{role}-key",
                "public_key_b64": b64encode(raw_public_bytes(key)).decode("ascii"),
                "signature_b64": b64encode(key.sign(signed)).decode("ascii"),
            }
        ),
        encoding="utf-8",
    )
    return path


def test_the_digest_flows_into_a_db03_record_that_assembles_and_verifies(tmp_path, pipeline):
    """The whole point: this bundle is what makes a DB-03 record signable."""
    evidence_path = build_evidence(tmp_path, pipeline)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    body = {
        "decision_version": "second-brain-decision-record-v1",
        "decision_id": "DB-03",
        "outcome": "GO",
        "scope_kind": "migration_source",
        "scope_name": evidence["source_name"],
        "record_revision": "1",
        "decided_at": "2026-07-30T01:00:00Z",
        "supersedes": None,
        "post_interview_reconciliation": {
            "original_question": "Is unified-db an acceptable read-only migration source?",
            "reconciliation": "Read-only migration input only; never a serving authority.",
        },
        "reason": "Immutable snapshot, zero-write proof, uniqueness diff and history treatment.",
        "evidence_refs": [str(evidence_path.name)],
        "evidence_digest": evidence["evidence_digest"],
        "expires_at": "2027-01-01T00:00:00Z",
    }
    body_path = tmp_path / "body.json"
    body_path.write_text(json.dumps(body), encoding="utf-8")
    payload = DECISION_TOOL.signing_bytes(json.loads(body_path.read_text(encoding="utf-8")))
    owner, approver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    record_path = tmp_path / "DB-03.json"
    assert (
        DECISION_TOOL.main(
            [
                "assemble",
                "--body", str(body_path),
                "--signature", str(envelope(tmp_path, "owner", owner, payload)),
                "--signature", str(envelope(tmp_path, "approver", approver, payload)),
                "--out", str(record_path),
            ]
        )
        == 0
    )
    record = DecisionRecordV1.from_mapping(json.loads(record_path.read_text(encoding="utf-8")))
    assert record.decision_id == "DB-03"
    assert record.scope_name == evidence["source_name"]
    assert record.evidence_digest == evidence["evidence_digest"]
    assert DECISION_TOOL.main(["verify", "--record", str(record_path)]) == 0


def test_tool_source_holds_no_private_key_material():
    source = SCRIPT.read_text(encoding="utf-8")
    for forbidden in ("Ed25519PrivateKey", "private_bytes", "-----BEGIN"):
        assert forbidden not in source, f"{forbidden} must never appear in the tool"


def test_tool_never_emits_an_outcome():
    """Building evidence is not deciding. GO/NO_GO belongs to the signed record."""
    source = SCRIPT.read_text(encoding="utf-8")
    assert '"outcome"' not in source
    assert "NO_GO" not in source.replace("it is a NO_GO candidate, not a GO one.", "")


def test_the_canonical_corpus_digest_is_independent_of_input_order(tmp_path, pipeline):
    """Sorting is the point: the same corpus must bind the same digest either way.

    Mutation testing showed `sorted(digests)` could become `list(digests)` with
    the suite still green, because every test happened to supply one order.
    """
    canonical = json.loads(pipeline["canonical_digests"].read_text(encoding="utf-8"))
    forward = tmp_path / "canonical-forward.json"
    reverse = tmp_path / "canonical-reverse.json"
    forward.write_text(json.dumps({"item_digests": canonical["item_digests"]}), encoding="utf-8")
    reverse.write_text(
        json.dumps({"item_digests": list(reversed(canonical["item_digests"]))}), encoding="utf-8"
    )
    assert canonical["item_digests"] != list(reversed(canonical["item_digests"]))

    out_a, out_b = tmp_path / "diff-a.json", tmp_path / "diff-b.json"
    for canon, out in ((forward, out_a), (reverse, out_b)):
        assert (
            run("uniqueness-diff", "--snapshot", pipeline["snapshot"],
                "--candidates", pipeline["candidate_digests"], "--canonical", canon,
                "--out", out)
            == 0
        )
    a = json.loads(out_a.read_text(encoding="utf-8"))
    b = json.loads(out_b.read_text(encoding="utf-8"))
    assert a["canonical_corpus_digest"] == b["canonical_corpus_digest"]
    assert a["diff_digest"] == b["diff_digest"]
