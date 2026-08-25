"""Certified source taxonomy and unsigned certified-v2 expected scopes."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.second_brain_contracts import ExpectedScopeManifestV1

ROOT = Path(__file__).resolve().parents[2]
V1_SCOPES = ROOT / "artifacts/product-release/second-brain-v1/governance/expected-scopes.json"
V1_BINDINGS = ROOT / "artifacts/product-release/second-brain-v1/governance/trusted-bindings.json"
V2_SCOPES = ROOT / "artifacts/product-release/second-brain-v2/governance/expected-scopes.json"
V2_BINDINGS = ROOT / "artifacts/product-release/second-brain-v2/governance/trusted-bindings.json"
V1_SCOPE_SHA256 = "71ad9b501a0442b32752dba79aa0e0525812f3ec0f5927ba6038d54046f8d2ad"
V1_BINDING_SHA256 = "944855a53e6bb03d31ce70c02db37c86620a6068a60a3fdd8b3b6f6f6470904c"
V1_PROFILES = ("Claude/Memory Bank", "Codex", "Git", "Markdown")
V1_MIGRATIONS = ("legacy Mem0/RAG", "me-wiki", "unified-db")
V2_PROFILES = (
    "Database snapshot",
    "Document root",
    "GJC",
    "OMO/Senpi/pi",
    "OpenCode",
    "Orca exported records",
    "Project/JARVIS records",
)
PARSER_NAMES = (
    "text",
    "markdown",
    "csv",
    "json",
    "jsonl",
    "yaml",
    "toml",
    "pdf",
    "docx",
    "xlsx",
    "hwpx",
)


def load_mod() -> Any:
    try:
        from wiki_spike.memory_core import second_brain_source_profiles as mod
    except ImportError:
        pytest.fail("missing second_brain_source_profiles.py implementation")
    return mod


def file_digest(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def test_canonical_v1_identities_remain_byte_for_byte() -> None:
    # Given: the closed certified-v1 source and migration names.
    mod = load_mod()

    # When: each historical identity is parsed with no normalization.
    profiles = tuple(mod.parse_source_identity(name) for name in V1_PROFILES)
    migrations = tuple(mod.parse_source_identity(name) for name in V1_MIGRATIONS)

    # Then: names stay byte-for-byte and remain certified-v1.
    assert tuple(item.name for item in profiles) == V1_PROFILES
    assert {item.kind for item in profiles} == {mod.SourceKindV2.SOURCE_PROFILE}
    assert {item.generation for item in profiles} == {mod.SourceGenerationV2.CERTIFIED_V1}
    assert tuple(item.name for item in migrations) == V1_MIGRATIONS
    assert {item.kind for item in migrations} == {mod.SourceKindV2.MIGRATION_SOURCE}
    assert {item.generation for item in migrations} == {mod.SourceGenerationV2.CERTIFIED_V1}


def test_certified_v2_profiles_parse_as_new_source_identities() -> None:
    # Given: the seven certified-v2 source profile names.
    mod = load_mod()

    # When: each new profile is parsed.
    parsed = tuple(mod.parse_source_identity(name) for name in V2_PROFILES)

    # Then: they are certified-v2 source profiles and not v1 identities.
    assert tuple(item.name for item in parsed) == V2_PROFILES
    assert {item.kind for item in parsed} == {mod.SourceKindV2.SOURCE_PROFILE}
    assert {item.generation for item in parsed} == {mod.SourceGenerationV2.CERTIFIED_V2}
    assert {item.name for item in parsed}.isdisjoint(V1_PROFILES)


def test_alias_or_spelling_normalization_does_not_grant_identity() -> None:
    # Given: near-miss spellings of canonical identities.
    mod = load_mod()

    # When: those aliases are parsed as source identities.
    # Then: none become an authorized identity.
    for alias in ("codex", "Open Code", "opencode", "markdown", "ME-WIKI", "unified_db"):
        with pytest.raises(InvalidContractValue, match="source identity"):
            mod.parse_source_identity(alias)


def test_parser_capability_does_not_create_source_authority() -> None:
    # Given: a well-formed parser capability nested under no source profile.
    mod = load_mod()
    payload = {
        "name": "pdf",
        "version": "1",
        "media_types": ("application/pdf",),
        "max_bytes": 1024,
    }

    # When: the capability is parsed.
    capability = mod.ParserCapabilityV2.from_mapping(payload)

    # Then: it is not a source identity and grants no expected-scope authority.
    assert capability.name.value == "pdf"
    assert {name.value for name in mod.ParserCapabilityNameV2} == set(PARSER_NAMES)
    assert capability.name.value not in {item.name for item in mod.certified_source_identities()}
    with pytest.raises(InvalidContractValue, match="source identity"):
        mod.parse_source_identity(capability.name.value)
    assert mod.parser_capability_grants_source_authority(capability) is False


def test_v1_governance_artifacts_remain_byte_identical() -> None:
    # Given: the signed certified-v1 expected-scope and trusted-binding files.
    # When: their bytes are hashed.
    # Then: the committed v1 artifacts are unchanged.
    assert file_digest(V1_SCOPES) == V1_SCOPE_SHA256
    assert file_digest(V1_BINDINGS) == V1_BINDING_SHA256
    parsed = ExpectedScopeManifestV1.from_mapping(
        __import__("json").loads(V1_SCOPES.read_text(encoding="utf-8"))
    )
    assert {name for _, kind, name in parsed.expected_scopes if kind == "source_profile"} == set(V1_PROFILES)
    assert "OpenCode" not in {name for _, _, name in parsed.expected_scopes}


def test_certified_v2_expected_scope_template_is_non_authorizing_and_exact() -> None:
    # Given: the unsigned certified-v2 expected-scope template.
    mod = load_mod()

    # When: the template is parsed and the inner roster is resolved.
    template = mod.parse_certified_v2_expected_scopes_template(V2_SCOPES.read_bytes())
    manifest = ExpectedScopeManifestV1.from_mapping(template.manifest)

    # Then: the template cannot authorize live use and the roster is exactly v1 plus v2.
    assert template.authorization_state == "NON_AUTHORIZING"
    assert template.live_operation_authorized is False
    names = tuple(name for _, kind, name in manifest.expected_scopes if kind == "source_profile")
    assert names == tuple(sorted((*V1_PROFILES, *V2_PROFILES)))
    assert {name for _, kind, name in manifest.expected_scopes if kind == "migration_source"} == set(V1_MIGRATIONS)


def test_incomplete_certified_v2_roster_fails() -> None:
    # Given: the exact certified-v2 roster minus one new profile.
    mod = load_mod()
    scopes = tuple(
        item for item in mod.certified_v2_expected_scope_tuples() if item[2] != "OpenCode"
    )

    # When: the incomplete roster is parsed as an expected-scope manifest.
    # Then: inventory matching fails closed.
    with pytest.raises(InvalidContractValue, match="required inventory"):
        ExpectedScopeManifestV1.from_tuples(scopes)


def test_extra_certified_v2_roster_entry_fails() -> None:
    # Given: the exact certified-v2 roster plus an unauthorized name.
    mod = load_mod()
    scopes = tuple(sorted((*mod.certified_v2_expected_scope_tuples(), ("DB-02", "source_profile", "Other"))))

    # When: the extra roster is parsed as an expected-scope manifest.
    # Then: inventory matching fails closed.
    with pytest.raises(InvalidContractValue, match="required inventory"):
        ExpectedScopeManifestV1.from_tuples(scopes)


def test_new_session_profile_cannot_use_a_v1_decision() -> None:
    # Given: a certified-v2 profile and the immutable v1 expected-scope roster.
    mod = load_mod()
    identity = mod.parse_source_identity("OpenCode")
    v1 = ExpectedScopeManifestV1.from_mapping(
        __import__("json").loads(V1_SCOPES.read_text(encoding="utf-8"))
    )

    # When: authorization is evaluated against the v1 decision roster.
    # Then: the new profile cannot inherit a v1 decision.
    with pytest.raises(InvalidContractValue, match="certified-v1"):
        mod.authorize_identity_against_manifest(identity, v1)
    assert identity.name not in {name for _, _, name in v1.expected_scopes}


def test_parser_capability_bounds_and_closed_names() -> None:
    # Given: closed parser names and the declared byte bound.
    mod = load_mod()

    # When: valid and invalid capability payloads are parsed.
    valid = mod.ParserCapabilityV2.from_mapping(
        {"name": "hwpx", "version": "1", "media_types": ("application/haansofthwpx",), "max_bytes": 67_108_864}
    )
    # Then: the closed set and numeric bound are enforced.
    assert valid.max_bytes == 67_108_864
    for payload in (
        {"name": "hwp", "version": "1", "media_types": ("application/x-hwp",), "max_bytes": 1},
        {"name": "pdf", "version": "", "media_types": ("application/pdf",), "max_bytes": 1},
        {"name": "pdf", "version": "1", "media_types": ("application/pdf",), "max_bytes": 0},
        {"name": "pdf", "version": "1", "media_types": ("application/pdf",), "max_bytes": 67_108_865},
    ):
        with pytest.raises(InvalidContractValue):
            mod.ParserCapabilityV2.from_mapping(payload)


def test_certified_v2_trusted_bindings_template_is_non_authorizing() -> None:
    # Given: the unsigned certified-v2 trusted-bindings template.
    mod = load_mod()

    # When: the template is parsed.
    template = mod.parse_certified_v2_trusted_bindings_template(V2_BINDINGS.read_bytes())

    # Then: it lists the exact v2 identities and carries no usable authority keys.
    assert template.authorization_state == "NON_AUTHORIZING"
    assert template.live_operation_authorized is False
    names = {item[2] for item in template.decision_identities if item[1] == "source_profile"}
    assert names == set((*V1_PROFILES, *V2_PROFILES))
    assert template.key_material_present is False


def test_empty_certified_v2_expected_scope_roster_fails() -> None:
    # Given: a certified-v2 expected-scope template whose roster is empty.
    mod = load_mod()
    payload = {
        "authorization_state": "NON_AUTHORIZING",
        "kind": "expected_scopes",
        "live_operation_authorized": False,
        "manifest": {"expected_scopes": [], "manifest_version": "second-brain-expected-scope-manifest-v1"},
        "template_version": "second-brain-certified-v2-governance-template/v1",
    }

    # When: the expected-scope template parser reads the empty roster.
    # Then: the parser fails closed and does not emit a template.
    with pytest.raises(InvalidContractValue, match="non-empty"):
        mod.parse_certified_v2_expected_scopes_template(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )


def test_empty_certified_v2_trusted_bindings_roster_fails() -> None:
    # Given: a certified-v2 trusted-bindings template whose identity roster is empty.
    mod = load_mod()
    payload = {
        "authorization_state": "NON_AUTHORIZING",
        "decision_identities": [],
        "kind": "trusted_bindings",
        "live_operation_authorized": False,
        "template_version": "second-brain-certified-v2-governance-template/v1",
    }

    # When: the trusted-bindings template parser reads the empty roster.
    # Then: the parser fails closed and does not emit a template.
    with pytest.raises(InvalidContractValue, match="non-empty"):
        mod.parse_certified_v2_trusted_bindings_template(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        )


def test_v1_bundle_decisions_cannot_carry_a_v2_profile() -> None:
    # Given: a v1 expected-scope roster and a certified-v2 decision identity.
    mod = load_mod()
    v1 = ExpectedScopeManifestV1.from_mapping(
        __import__("json").loads(V1_SCOPES.read_text(encoding="utf-8"))
    )

    # When: bundle taxonomy validation sees OpenCode under the v1 roster.
    # Then: the v2 profile is rejected before any source I/O.
    with pytest.raises(InvalidContractValue, match="certified-v1"):
        mod.reject_unbound_source_identities((("source_profile", "OpenCode"),), v1.expected_scopes)
