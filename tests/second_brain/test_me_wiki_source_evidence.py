"""Machine-safe me-wiki DB-03 body-free evidence contracts.

These tests pin the frozen Core contracts for the me-wiki migration-source
profile, its synthetic git mapping fixture, and the contract-and-fixture-only
evidence state. They are RED-first: the modules under test did not exist when
they were written.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
)
from wiki_spike.memory_core.me_wiki_source_evidence import (
    MeWikiSourceEvidenceV1,
)
from wiki_spike.memory_core.me_wiki_source_evidence_contracts import (
    DELETION_POLICY,
    DISCOVERY_MANIFEST_DIGEST,
    EVIDENCE_STATE,
    HISTORY_POLICY,
    IDENTITY_MAPPING,
    OVERLAP_POLICY,
    PAGINATION,
    RESTART_POLICY,
    RETENTION_HOURS,
    REVISION_MAPPING,
    ROW_ORDER,
    WATERMARK_MAPPING,
    FixtureScenario,
)
from wiki_spike.memory_core.me_wiki_source_evidence_fixture import (
    MeWikiMappingFixtureV1,
    build_synthetic_fixture,
)
from wiki_spike.memory_core.me_wiki_source_evidence_profile import (
    MeWikiGitTreeV1,
    MeWikiSourceProfileV1,
    MeWikiTrackedTreeRow,
    compute_tracked_tree_digest,
)

_SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schemas" / "second-brain"
_ROOT = "/Volumes/DevSpace/me-wiki"
_HEAD = "7c8b927a6168bc7757b13d064efdbe41c03a0e1c"


def _rows() -> tuple[MeWikiTrackedTreeRow, ...]:
    return (
        MeWikiTrackedTreeRow("100644", "7b4af37446e5d1fa9fa90868800a1ad4310758c9", "0", "AGENT_RULES.md"),
        MeWikiTrackedTreeRow("100644", "19cf12d8e2b143900a256273666dcdea382f5716", "0", "INDEX.md"),
    )


def _tree() -> MeWikiGitTreeV1:
    return MeWikiGitTreeV1(_HEAD, _rows())


def _fixture() -> MeWikiMappingFixtureV1:
    return build_synthetic_fixture(_HEAD)


def _profile() -> MeWikiSourceProfileV1:
    return MeWikiSourceProfileV1.create(_ROOT, _tree(), _fixture().fixture_digest)


def _evidence() -> MeWikiSourceEvidenceV1:
    return MeWikiSourceEvidenceV1.create(_profile())


def _validate(schema_name: str, payload: dict[str, JsonValue]) -> None:
    program = (
        "import json,jsonschema,sys;"
        "schema=json.loads(open(sys.argv[1]).read());"
        "jsonschema.Draft202012Validator.check_schema(schema);"
        "jsonschema.validate(instance=json.loads(sys.argv[2]),schema=schema)"
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(_SCHEMA_DIR / schema_name),
            json.dumps(payload),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _entry_payloads(fixture: MeWikiMappingFixtureV1) -> list[dict[str, JsonValue]]:
    return [dict(entry.to_mapping()) for entry in fixture.entries]


def _fixture_payload(
    fixture: MeWikiMappingFixtureV1, entries: list[dict[str, JsonValue]]
) -> dict[str, JsonValue]:
    return {
        "fixture_version": fixture.fixture_version,
        "source_name": fixture.source_name,
        "entries": [entry for entry in entries],
        "row_set_digest": fixture.row_set_digest,
        "fixture_digest": fixture.fixture_digest,
    }


def test_profile_roundtrips_and_binds_its_digest() -> None:
    profile = _profile()
    assert MeWikiSourceProfileV1.from_mapping(profile.to_mapping()) == profile
    tampered = profile.to_mapping()
    tampered["git_head"] = "d" * 40
    with pytest.raises(InvalidContractValue, match="profile_digest"):
        _ = MeWikiSourceProfileV1.from_mapping(tampered)


def test_profile_binds_exact_me_wiki_mapping_semantics() -> None:
    profile = _profile()
    assert profile.source_name == "me-wiki"
    assert profile.source_root == _ROOT
    assert profile.discovery_manifest_digest == DISCOVERY_MANIFEST_DIGEST
    assert profile.identity_mapping == IDENTITY_MAPPING == "ROOT_RELATIVE_POSIX_PATH"
    assert profile.revision_mapping == REVISION_MAPPING == "GIT_BLOB_OID"
    assert profile.watermark_mapping == WATERMARK_MAPPING == "GIT_HEAD_PLUS_MTIME_NS"
    assert profile.row_order == ROW_ORDER == "LEXICAL_CURSOR_ORDER"
    assert profile.overlap_policy == OVERLAP_POLICY == "INCLUSIVE_PREVIOUS_WATERMARK"
    assert profile.restart_policy == RESTART_POLICY == "REPLAY_AND_DEDUPE"
    assert profile.pagination == PAGINATION == "CANONICAL_DECIMAL_PAGINATION"
    assert profile.retention_hours == RETENTION_HOURS == "2160"
    assert profile.deletion_policy == DELETION_POLICY == "GIT_DIFF_TOMBSTONE"
    assert profile.history_policy == HISTORY_POLICY == "GIT_OBJECT_HISTORY_RETAINED"
    assert profile.tracked_count == "2"
    assert compute_tracked_tree_digest(profile.tracked_tree) == profile.tracked_tree_digest
    assert profile.fixture_digest == _fixture().fixture_digest


def test_profile_rejects_unknown_missing_and_non_string() -> None:
    profile = _profile()
    with pytest.raises(UnknownContractField):
        _ = MeWikiSourceProfileV1.from_mapping(profile.to_mapping() | {"extra": "no"})
    missing = profile.to_mapping()
    del missing["retention_hours"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = MeWikiSourceProfileV1.from_mapping(missing)
    broken = profile.to_mapping()
    broken["retention_hours"] = False
    with pytest.raises(InvalidContractValue, match="non-empty string"):
        _ = MeWikiSourceProfileV1.from_mapping(broken)


def test_profile_flags_must_be_false() -> None:
    profile = _profile()
    for field in (
        "source_mutation",
        "import_requested",
        "serve_requested",
        "promote_requested",
    ):
        flagged = profile.to_mapping()
        flagged[field] = True
        with pytest.raises(InvalidContractValue, match="false"):
            _ = MeWikiSourceProfileV1.from_mapping(flagged)


def test_profile_body_reads_must_be_zero() -> None:
    profile = _profile()
    assert profile.body_reads == "0"
    body = profile.to_mapping()
    body["body_reads"] = "1"
    with pytest.raises(InvalidContractValue, match="body_reads"):
        _ = MeWikiSourceProfileV1.from_mapping(body)


def test_fixture_covers_four_scenarios_with_sorted_unique_ids() -> None:
    fixture = _fixture()
    assert tuple(entry.scenario for entry in fixture.entries) == (
        FixtureScenario.CURRENT,
        FixtureScenario.UPDATED,
        FixtureScenario.DELETED_TOMBSTONE,
        FixtureScenario.HISTORY_UNAVAILABLE_BEFORE_FLOOR,
    )
    ids = [entry.native_id for entry in fixture.entries]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)
    assert {entry.scenario for entry in fixture.entries} == set(FixtureScenario)


def test_fixture_roundtrips_and_binds_its_rows() -> None:
    fixture = _fixture()
    assert MeWikiMappingFixtureV1.from_mapping(fixture.to_mapping()) == fixture
    entries = _entry_payloads(fixture)
    entries[0]["revision"] = "e" * 40
    with pytest.raises(InvalidContractValue, match="row_set_digest"):
        _ = MeWikiMappingFixtureV1.from_mapping(_fixture_payload(fixture, entries))


def test_fixture_rejects_missing_scenario_and_unsorted_or_duplicate_ids() -> None:
    fixture = _fixture()

    missing = _fixture_payload(fixture, _entry_payloads(fixture)[:3])
    with pytest.raises(InvalidContractValue, match="four scenarios"):
        _ = MeWikiMappingFixtureV1.from_mapping(missing)

    duplicate = _entry_payloads(fixture)
    duplicate[1]["native_id"] = duplicate[0]["native_id"]
    with pytest.raises(InvalidContractValue, match="unique"):
        _ = MeWikiMappingFixtureV1.from_mapping(_fixture_payload(fixture, duplicate))

    entries = _entry_payloads(fixture)
    unsorted = [entries[1], entries[0], entries[2], entries[3]]
    with pytest.raises(InvalidContractValue, match="sorted"):
        _ = MeWikiMappingFixtureV1.from_mapping(_fixture_payload(fixture, unsorted))


def test_fixture_entry_invariants_tombstone_updated_and_history() -> None:
    fixture = _fixture()
    tombstone = next(
        entry for entry in fixture.entries
        if entry.scenario is FixtureScenario.DELETED_TOMBSTONE
    )
    assert tombstone.tombstone is True
    assert tombstone.revision is None
    assert tombstone.previous_revision is not None
    assert tombstone.history_retained is True

    updated = next(
        entry for entry in fixture.entries
        if entry.scenario is FixtureScenario.UPDATED
    )
    assert updated.previous_revision is not None
    assert updated.previous_watermark is not None
    assert updated.watermark > updated.previous_watermark

    floor = next(
        entry for entry in fixture.entries
        if entry.scenario is FixtureScenario.HISTORY_UNAVAILABLE_BEFORE_FLOOR
    )
    assert floor.history_retained is False

    broken = _entry_payloads(fixture)
    for entry in broken:
        if entry["scenario"] == "deleted_tombstone":
            entry["revision"] = "a" * 40
    with pytest.raises(InvalidContractValue, match="tombstone"):
        _ = MeWikiMappingFixtureV1.from_mapping(_fixture_payload(fixture, broken))


def test_evidence_state_is_contract_and_synthetic_only_not_go() -> None:
    evidence = _evidence()
    assert evidence.state == EVIDENCE_STATE == "CONTRACT_AND_SYNTHETIC_FIXTURE_ONLY"
    assert evidence.authorized_go is False
    assert evidence.body_reads == "0"

    go = evidence.to_mapping()
    go["state"] = "GO"
    with pytest.raises(InvalidContractValue, match="state"):
        _ = MeWikiSourceEvidenceV1.from_mapping(go)
    authorized = evidence.to_mapping()
    authorized["authorized_go"] = True
    with pytest.raises(InvalidContractValue, match="authorized_go"):
        _ = MeWikiSourceEvidenceV1.from_mapping(authorized)


def test_evidence_binds_profile_and_fixture_digests() -> None:
    profile = _profile()
    evidence = MeWikiSourceEvidenceV1.create(profile)
    assert MeWikiSourceEvidenceV1.from_mapping(evidence.to_mapping()) == evidence
    assert evidence.profile_digest == profile.profile_digest
    assert evidence.fixture_digest == profile.fixture_digest

    wrong = evidence.to_mapping()
    wrong["fixture_digest"] = "f" * 64
    with pytest.raises(InvalidContractValue, match="evidence_digest"):
        _ = MeWikiSourceEvidenceV1.from_mapping(wrong)


def test_schemas_are_draft_2020_12_and_validate_canonical_artifacts() -> None:
    profile = _profile()
    evidence = _evidence()
    for schema_name, payload in (
        ("me-wiki-source-profile-v1.schema.json", profile.to_mapping()),
        ("me-wiki-mapping-fixture-v1.schema.json", _fixture().to_mapping()),
        ("me-wiki-source-evidence-v1.schema.json", evidence.to_mapping()),
    ):
        _validate(schema_name, payload)
        with pytest.raises(AssertionError):
            _validate(schema_name, dict(payload) | {"extra": "no"})
