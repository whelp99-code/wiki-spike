"""Red-team suite for the DB-03 migration-source evidence bundle.

Every case here is an attempt to obtain a signable `evidence_digest` for a
source that has not earned one: laundering a snapshot taken off a live instance,
inferring tombstones a source cannot express, inflating a uniqueness diff,
collapsing owner and Security into one attestation, splicing components across
sources or snapshots, and smuggling record bodies through metadata fields.

The one boundary this suite states rather than tests: a hand-forged component
file whose *internal* claims are self-consistent will parse. Content truth comes
from the operator's snapshot, not from arithmetic. What the contracts guarantee
is that such a component cannot be silently combined with real ones -- every
splice is caught -- and that the tool itself never fabricates the values.
"""
from __future__ import annotations

import importlib.util
import json
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest
from wiki_spike.memory_core.second_brain_migration_evidence_contracts import (
    MigrationExportProfileV1,
    MigrationHistoryTreatmentV1,
    MigrationSnapshotV1,
    MigrationSourceEvidenceV1,
    MigrationUniquenessDiffV1,
    assert_migration_evidence_bundle_coherent,
)

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "second_brain_migration_source_evidence.py"


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "second_brain_migration_source_evidence_redteam", SCRIPT
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()
WORKSPACE = "workspace:second-brain-final"


def d(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def run(*args) -> int:
    return TOOL.main([str(arg) for arg in args])


def rebind(path: Path, domain: str, field: str, **overrides) -> Path:
    """Tamper with an artifact and recompute its binding digest.

    A tamperer who owns the file can always do this, so every invariant that
    matters must be enforced independently of the digest.
    """
    body = json.loads(path.read_text(encoding="utf-8"))
    body.pop(field)
    body.update(overrides)
    body[field] = canonical_ledger_digest(domain, body)
    path.write_text(json.dumps(body, sort_keys=True), encoding="utf-8")
    return path


def corpus(root: Path, name: str, bodies: list[str]) -> Path:
    directory = root / name
    directory.mkdir()
    for index, text in enumerate(bodies):
        (directory / f"{index}.txt").write_text(text, encoding="utf-8")
    return directory


def snapshot(tmp_path: Path, source: str = "unified-db", **overrides) -> Path:
    out = tmp_path / f"snapshot-{source.replace('/', '-')}-{len(list(tmp_path.iterdir()))}.json"
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


def profile(tmp_path: Path, snapshot_path: Path, **overrides) -> Path:
    out = tmp_path / f"profile-{snapshot_path.stem}.json"
    args = {
        "--snapshot": str(snapshot_path),
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


def diff(tmp_path: Path, snapshot_path: Path, candidates: Path, canonical: Path) -> Path:
    out = tmp_path / f"diff-{snapshot_path.stem}.json"
    assert (
        run(
            "uniqueness-diff", "--snapshot", snapshot_path,
            "--candidates", candidates, "--canonical", canonical, "--out", out,
        )
        == 0
    )
    return out


def treatment(tmp_path: Path, snapshot_path: Path, **overrides) -> Path:
    out = tmp_path / f"treatment-{snapshot_path.stem}.json"
    args = {
        "--tombstone-representation": "absent",
        "--history-availability": "partial-with-proof",
    }
    args.update(overrides)
    flat = [item for pair in args.items() for item in pair]
    flat += ["--retained-sample", d("retained-1"), "--unavailable-sample", d("unavailable-1")]
    assert run("history-treatment", "--snapshot", snapshot_path, *flat, "--out", out) == 0
    return out


@pytest.fixture
def chain(tmp_path):
    candidates = corpus(tmp_path, "candidates", ["c1", "c2", "shared"])
    canonical = corpus(tmp_path, "canonical", ["shared", "k2"])
    candidate_digests = tmp_path / "candidates.json"
    canonical_digests = tmp_path / "canonical.json"
    assert run("digests", "--dir", candidates, "--out", candidate_digests) == 0
    assert run("digests", "--dir", canonical, "--out", canonical_digests) == 0
    snap = snapshot(tmp_path)
    return {
        "snapshot": snap,
        "profile": profile(tmp_path, snap),
        "diff": diff(tmp_path, snap, candidate_digests, canonical_digests),
        "treatment": treatment(tmp_path, snap),
        "candidate_digests": candidate_digests,
        "canonical_digests": canonical_digests,
    }


def evidence_args(chain: dict, out: Path, **overrides) -> list:
    args = {
        "--snapshot": str(chain["snapshot"]),
        "--export-profile": str(chain["profile"]),
        "--uniqueness-diff": str(chain["diff"]),
        "--history-treatment": str(chain["treatment"]),
        "--workspace-ref": WORKSPACE,
        "--security-review-digest": d("security-review"),
    }
    args.update(overrides)
    args["--out"] = str(out)
    return ["evidence", *[item for pair in args.items() for item in pair]]


# --- snapshot integrity -------------------------------------------------------


def test_a_live_instance_snapshot_cannot_be_laundered_by_rebinding(tmp_path, chain):
    """Recomputing the digest does not make a live-instance snapshot valid."""
    rebind(
        chain["snapshot"], "migration-snapshot-v1", "snapshot_binding_digest",
        active_run_observed=True,
    )
    assert run("verify", "--file", chain["snapshot"]) == 2
    assert run(*evidence_args(chain, tmp_path / "out.json")) == 2


def test_a_source_that_changed_under_the_export_cannot_be_rebound(tmp_path, chain):
    rebind(
        chain["snapshot"], "migration-snapshot-v1", "snapshot_binding_digest",
        source_root_digest_after=d("root-after-a-write"),
    )
    assert run("verify", "--file", chain["snapshot"]) == 2


def snapshot_args(tmp_path: Path, **overrides) -> list:
    """Raw snapshot argv, so a refusal can be asserted as an exit code."""
    args = {
        "--source-name": "unified-db",
        "--snapshot-ref": "snapshot:unified-db-2026-07-30",
        "--writers-quiesced-at": "2026-07-30T00:00:00Z",
        "--snapshot-taken-at": "2026-07-30T00:05:00Z",
        "--source-root-digest-before": d("root"),
        "--source-root-digest-after": d("root"),
        "--snapshot-package-digest": d("package"),
        "--owner-key-ref": "key:migration-owner-2026",
        "--owner-attestation-digest": d("owner-attestation"),
        "--out": str(tmp_path / "probe-snapshot.json"),
    }
    args.update(overrides)
    return ["snapshot", *[item for pair in args.items() for item in pair]]


def test_a_snapshot_predating_the_quiesce_is_refused(tmp_path):
    assert run(*snapshot_args(tmp_path, **{"--snapshot-taken-at": "2026-07-29T12:00:00Z"})) == 2
    assert not (tmp_path / "probe-snapshot.json").exists()


def test_a_legal_but_non_canonical_instant_spelling_is_accepted(tmp_path, capsys):
    """The operator's clock may print trailing zeros; that is not tampering."""
    assert run(*snapshot_args(tmp_path, **{"--snapshot-taken-at": "2026-07-30T00:05:00.000Z"})) == 0
    written = json.loads((tmp_path / "probe-snapshot.json").read_text(encoding="utf-8"))
    assert written["snapshot_taken_at"] == "2026-07-30T00:05:00Z"


def test_the_cli_refuses_a_source_outside_db03s_scope_inventory(tmp_path, capsys):
    """The unified-db inventory lists eight sub-sources; DB-03 scopes only three."""
    with pytest.raises(SystemExit):
        run(
            "snapshot", "--source-name", "hermes", "--snapshot-ref", "snapshot:hermes",
            "--writers-quiesced-at", "2026-07-30T00:00:00Z",
            "--snapshot-taken-at", "2026-07-30T00:05:00Z",
            "--source-root-digest-before", d("root"), "--source-root-digest-after", d("root"),
            "--snapshot-package-digest", d("package"), "--owner-key-ref", "key:o",
            "--owner-attestation-digest", d("owner"),
        )


@pytest.mark.parametrize(
    "override",
    [
        {"--snapshot-ref": "unified-db-2026-07-30"},
        {"--owner-key-ref": "migration-owner-2026"},
    ],
)
def test_unprefixed_refs_are_refused(tmp_path, override):
    assert run(*snapshot_args(tmp_path, **override)) == 2


# --- export profile -----------------------------------------------------------


def test_the_profile_takes_its_source_from_the_snapshot_not_the_operator(chain):
    """There is no --source-name on export-profile; it cannot disagree."""
    stored = json.loads(chain["profile"].read_text(encoding="utf-8"))
    snap = json.loads(chain["snapshot"].read_text(encoding="utf-8"))
    assert stored["source_name"] == snap["source_name"]
    assert "--source-name" not in SCRIPT.read_text(encoding="utf-8").split(
        "export-profile", 1
    )[1].split("uniqueness-diff", 1)[0]


@pytest.mark.parametrize(
    "field",
    ["schema_version", "watermark_cursor_field"],
)
def test_a_record_body_cannot_be_smuggled_through_a_metadata_field(chain, field):
    body = json.loads(chain["profile"].read_text(encoding="utf-8"))
    body.pop("profile_digest")
    body[field] = "x" * 129
    body["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", body)
    with pytest.raises(InvalidContractValue, match="identifier characters"):
        MigrationExportProfileV1.from_mapping(body)


def test_a_record_body_cannot_be_smuggled_through_the_identity_field_list(chain):
    body = json.loads(chain["profile"].read_text(encoding="utf-8"))
    body.pop("profile_digest")
    body["native_identity_fields"] = ["source_id", "y" * 200]
    body["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", body)
    with pytest.raises(InvalidContractValue, match="identifier characters"):
        MigrationExportProfileV1.from_mapping(body)


@pytest.mark.parametrize("value", ["0500", "1e3", " 500", "500 "])
def test_a_non_canonical_decimal_creates_no_second_encoding(chain, value):
    body = json.loads(chain["profile"].read_text(encoding="utf-8"))
    body.pop("profile_digest")
    body["page_size_limit"] = value
    body["profile_digest"] = canonical_ledger_digest("migration-export-profile-v1", body)
    with pytest.raises(InvalidContractValue, match="canonical decimal"):
        MigrationExportProfileV1.from_mapping(body)


# --- uniqueness diff ----------------------------------------------------------


def test_the_tool_never_reports_a_shared_item_as_unique(chain):
    stored = json.loads(chain["diff"].read_text(encoding="utf-8"))
    canonical = set(
        json.loads(chain["canonical_digests"].read_text(encoding="utf-8"))["item_digests"]
    )
    assert canonical.isdisjoint(stored["unique_item_digests"])
    assert stored["duplicate_item_count"] == "1"


def test_an_inflated_unique_count_is_refused(chain):
    body = json.loads(chain["diff"].read_text(encoding="utf-8"))
    body.pop("diff_digest")
    body["unique_item_count"] = "99"
    body["candidate_item_count"] = "100"
    body["diff_digest"] = canonical_ledger_digest("migration-uniqueness-diff-v1", body)
    with pytest.raises(InvalidContractValue, match="unique_item_count"):
        MigrationUniquenessDiffV1.from_mapping(body)


def test_hiding_duplicates_by_understating_the_candidate_count_is_refused(chain):
    body = json.loads(chain["diff"].read_text(encoding="utf-8"))
    body.pop("diff_digest")
    body["candidate_item_count"] = body["unique_item_count"]
    body["diff_digest"] = canonical_ledger_digest("migration-uniqueness-diff-v1", body)
    with pytest.raises(InvalidContractValue, match="partition"):
        MigrationUniquenessDiffV1.from_mapping(body)


def test_a_comparison_method_other_than_the_pinned_one_is_refused(chain):
    body = json.loads(chain["diff"].read_text(encoding="utf-8"))
    body.pop("diff_digest")
    body["comparison_method"] = "operator-judgement"
    body["diff_digest"] = canonical_ledger_digest("migration-uniqueness-diff-v1", body)
    with pytest.raises(InvalidContractValue, match="comparison_method"):
        MigrationUniquenessDiffV1.from_mapping(body)


# --- deletion and history -----------------------------------------------------


def test_tombstones_cannot_be_inferred_for_a_source_that_has_none(tmp_path, chain):
    out = tmp_path / "inferred-treatment.json"
    assert (
        run(
            "history-treatment", "--snapshot", chain["snapshot"],
            "--tombstone-representation", "absent",
            "--history-availability", "partial-with-proof",
            "--tombstone-sample", d("guessed-tombstone"),
            "--retained-sample", d("retained-1"),
            "--unavailable-sample", d("unavailable-1"),
            "--out", out,
        )
        == 2
    )
    assert not out.exists()


def test_unavailable_history_cannot_be_dressed_up_with_retained_samples(tmp_path, chain):
    body = json.loads(chain["treatment"].read_text(encoding="utf-8"))
    body.pop("treatment_digest")
    body["history_availability"] = "unavailable"
    body["treatment_digest"] = canonical_ledger_digest("migration-history-treatment-v1", body)
    with pytest.raises(InvalidContractValue, match="cannot also present retained"):
        MigrationHistoryTreatmentV1.from_mapping(body)


def test_a_record_cannot_be_counted_as_both_retained_and_unavailable(chain):
    body = json.loads(chain["treatment"].read_text(encoding="utf-8"))
    body.pop("treatment_digest")
    body["unavailable_history_sample_digests"] = list(body["retained_history_sample_digests"])
    body["treatment_digest"] = canonical_ledger_digest("migration-history-treatment-v1", body)
    with pytest.raises(InvalidContractValue, match="overlap"):
        MigrationHistoryTreatmentV1.from_mapping(body)


def test_absence_is_not_deletion_cannot_be_disabled(chain):
    body = json.loads(chain["treatment"].read_text(encoding="utf-8"))
    body.pop("treatment_digest")
    body["absence_is_not_deletion"] = False
    body["treatment_digest"] = canonical_ledger_digest("migration-history-treatment-v1", body)
    with pytest.raises(InvalidContractValue, match="absence_is_not_deletion"):
        MigrationHistoryTreatmentV1.from_mapping(body)


# --- bundle assembly ----------------------------------------------------------


def test_a_component_edited_after_the_bundle_was_built_no_longer_binds(tmp_path, chain):
    out = tmp_path / "evidence.json"
    assert run(*evidence_args(chain, out)) == 0
    before = json.loads(out.read_text(encoding="utf-8"))["evidence_digest"]
    rebind(
        chain["treatment"], "migration-history-treatment-v1", "treatment_digest",
        history_availability="complete",
        unavailable_history_sample_digests=[],
    )
    second = tmp_path / "evidence-2.json"
    assert run(*evidence_args(chain, second)) == 0
    assert json.loads(second.read_text(encoding="utf-8"))["evidence_digest"] != before


def test_another_sources_component_cannot_be_spliced_in(tmp_path, chain):
    foreign = snapshot(tmp_path, source="me-wiki")
    foreign_profile = profile(tmp_path, foreign)
    assert (
        run(*evidence_args(chain, tmp_path / "out.json", **{"--export-profile": str(foreign_profile)}))
        == 2
    )


def test_a_component_from_a_different_snapshot_of_the_same_source_is_refused(tmp_path, chain):
    later = snapshot(
        tmp_path, **{"--snapshot-ref": "snapshot:unified-db-2026-08-01"}
    )
    stale = treatment(tmp_path, later)
    assert (
        run(*evidence_args(chain, tmp_path / "out.json", **{"--history-treatment": str(stale)}))
        == 2
    )


def test_the_wrong_artifact_type_in_a_component_slot_is_refused(tmp_path, chain):
    assert (
        run(*evidence_args(chain, tmp_path / "out.json", **{"--snapshot": str(chain["profile"])}))
        == 2
    )


def test_one_person_holding_both_roles_is_refused(tmp_path, chain):
    owner = json.loads(chain["snapshot"].read_text(encoding="utf-8"))["owner_attestation_digest"]
    assert (
        run(*evidence_args(chain, tmp_path / "out.json", **{"--security-review-digest": owner}))
        == 2
    )


def test_a_component_digest_cannot_be_reused_for_a_second_slot(tmp_path, chain):
    out = tmp_path / "evidence.json"
    assert run(*evidence_args(chain, out)) == 0
    body = json.loads(out.read_text(encoding="utf-8"))
    body.pop("evidence_digest")
    body["uniqueness_diff_digest"] = body["export_profile_digest"]
    body["evidence_digest"] = canonical_ledger_digest("migration-source-evidence-v1", body)
    with pytest.raises(InvalidContractValue, match="six distinct artifacts"):
        MigrationSourceEvidenceV1.from_mapping(body)


def test_a_self_consistent_forgery_still_cannot_join_the_real_chain(tmp_path, chain):
    """The stated boundary: forged internals parse, but splices never pass coherence."""
    forged_snapshot_path = snapshot(
        tmp_path, **{"--owner-attestation-digest": d("forged-owner")}
    )
    forged = MigrationSnapshotV1.from_mapping(
        json.loads(forged_snapshot_path.read_text(encoding="utf-8"))
    )
    out = tmp_path / "evidence.json"
    assert run(*evidence_args(chain, out)) == 0
    evidence = MigrationSourceEvidenceV1.from_mapping(
        json.loads(out.read_text(encoding="utf-8"))
    )
    real = MigrationSnapshotV1.from_mapping(
        json.loads(chain["snapshot"].read_text(encoding="utf-8"))
    )
    real_profile = MigrationExportProfileV1.from_mapping(
        json.loads(chain["profile"].read_text(encoding="utf-8"))
    )
    real_diff = MigrationUniquenessDiffV1.from_mapping(
        json.loads(chain["diff"].read_text(encoding="utf-8"))
    )
    real_treatment = MigrationHistoryTreatmentV1.from_mapping(
        json.loads(chain["treatment"].read_text(encoding="utf-8"))
    )
    assert_migration_evidence_bundle_coherent(
        evidence, real, real_profile, real_diff, real_treatment
    )
    with pytest.raises(InvalidContractValue):
        assert_migration_evidence_bundle_coherent(
            evidence, forged, real_profile, real_diff, real_treatment
        )


# --- input handling -----------------------------------------------------------


@pytest.mark.parametrize("payload", ["[]", '{"item_digests": []}', '{"item_digests": ["short"]}'])
def test_a_malformed_digest_list_is_refused(tmp_path, chain, payload):
    path = tmp_path / "bad.json"
    path.write_text(payload, encoding="utf-8")
    assert (
        run(
            "uniqueness-diff", "--snapshot", chain["snapshot"],
            "--candidates", path, "--canonical", chain["canonical_digests"],
        )
        == 2
    )


def test_a_json_array_where_an_artifact_is_expected_is_refused(tmp_path):
    path = tmp_path / "array.json"
    path.write_text("[1, 2, 3]", encoding="utf-8")
    assert run("verify", "--file", path) == 2


def test_a_missing_file_fails_closed_without_a_traceback(tmp_path, capsys):
    assert run("verify", "--file", tmp_path / "absent.json") == 2
    assert capsys.readouterr().err.startswith("FAIL:")


def test_no_candidate_body_or_filename_reaches_any_artifact(tmp_path, chain, capsys):
    """Sentinel bodies and their file names must both be absent from every artifact."""
    sentinel_body = "SENTINEL-RECORD-BODY-8f21"
    sentinel_name = "SENTINEL-FILENAME-4c07.txt"
    directory = tmp_path / "sentinel"
    directory.mkdir()
    (directory / sentinel_name).write_text(sentinel_body, encoding="utf-8")
    digests_out = tmp_path / "sentinel-digests.json"
    assert run("digests", "--dir", directory, "--out", digests_out) == 0
    diff_out = tmp_path / "sentinel-diff.json"
    assert (
        run(
            "uniqueness-diff", "--snapshot", chain["snapshot"],
            "--candidates", digests_out, "--canonical", chain["canonical_digests"],
            "--out", diff_out,
        )
        == 0
    )
    haystack = capsys.readouterr().out + "".join(
        path.read_text(encoding="utf-8")
        for path in (digests_out, diff_out, chain["snapshot"], chain["profile"], chain["treatment"])
    )
    assert sentinel_body not in haystack
    assert sentinel_name not in haystack
    assert "SENTINEL" not in haystack


def test_a_symlink_under_the_export_directory_is_refused(tmp_path, capsys):
    """Following one would fold bytes from outside the declared tree into the evidence."""
    outside = tmp_path / "outside-secret.txt"
    outside.write_text("OUTSIDE-BYTES", encoding="utf-8")
    directory = tmp_path / "export"
    directory.mkdir()
    (directory / "inside.txt").write_text("inside", encoding="utf-8")
    (directory / "link.txt").symlink_to(outside)
    assert run("digests", "--dir", directory) == 2
    captured = capsys.readouterr()
    assert "symlink" in captured.err
    assert sha256(b"OUTSIDE-BYTES").hexdigest() not in captured.out


def test_a_symlinked_out_path_is_not_written_through(tmp_path):
    """An --out symlink would redirect the artifact outside the intended directory."""
    target = tmp_path / "elsewhere.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "artifact.json"
    link.symlink_to(target)
    assert run(*snapshot_args(tmp_path, **{"--out": str(link)})) == 2
    assert target.read_text(encoding="utf-8") == "{}"


def test_a_refused_write_leaves_no_partial_artifact(tmp_path):
    out = tmp_path / "nested" / "deep" / "snapshot.json"
    assert run(*snapshot_args(tmp_path, **{"--out": str(out)})) == 2
    assert not out.exists()
    assert not (tmp_path / "nested").exists()

# --- guards whose tests were passing for the wrong reason ---------------------
# Mutation testing showed each of these could be deleted with the suite still
# green: the exit code stayed 2 because a *later* guard tripped instead. Exit
# codes alone are too coarse here, so these assert the specific refusal.


def test_verify_refuses_two_version_fields_by_that_reason(tmp_path, chain, capsys):
    spliced = {**json.loads(chain["snapshot"].read_text(encoding="utf-8")),
               "diff_version": "second-brain-migration-uniqueness-diff-v1"}
    path = tmp_path / "two-versions.json"
    path.write_text(json.dumps(spliced), encoding="utf-8")
    assert run("verify", "--file", path) == 2
    assert "exactly one version field" in capsys.readouterr().err


def test_verify_refuses_an_unrecognised_version_by_that_reason(tmp_path, capsys):
    path = tmp_path / "unknown-version.json"
    path.write_text(json.dumps({"snapshot_version": "second-brain-not-a-thing-v1"}),
                    encoding="utf-8")
    assert run("verify", "--file", path) == 2
    assert "unrecognised version" in capsys.readouterr().err


def test_an_empty_digest_list_is_refused_by_that_reason(tmp_path, chain, capsys):
    path = tmp_path / "empty-list.json"
    path.write_text("[]", encoding="utf-8")
    assert (
        run("uniqueness-diff", "--snapshot", chain["snapshot"],
            "--candidates", path, "--canonical", chain["canonical_digests"])
        == 2
    )
    assert "non-empty JSON array" in capsys.readouterr().err


def test_a_duplicate_digest_list_is_refused_by_that_reason(tmp_path, chain, capsys):
    path = tmp_path / "dupes.json"
    path.write_text(json.dumps([d("x"), d("y"), d("x")]), encoding="utf-8")
    assert (
        run("uniqueness-diff", "--snapshot", chain["snapshot"],
            "--candidates", path, "--canonical", chain["canonical_digests"])
        == 2
    )
    assert "duplicate digests" in capsys.readouterr().err


def test_a_non_digest_entry_is_refused_by_that_reason(tmp_path, chain, capsys):
    path = tmp_path / "not-digests.json"
    path.write_text(json.dumps(["short"]), encoding="utf-8")
    assert (
        run("uniqueness-diff", "--snapshot", chain["snapshot"],
            "--candidates", path, "--canonical", chain["canonical_digests"])
        == 2
    )
    assert "not a sha256 digest" in capsys.readouterr().err
