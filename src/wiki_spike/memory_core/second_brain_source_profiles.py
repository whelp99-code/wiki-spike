"""Sole owner of SourceIdentityV2, ParserCapabilityV2, and certified-v2 rosters."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

TEMPLATE_VERSION: Final = "second-brain-certified-v2-governance-template/v1"
PARSER_MAX_BYTES: Final = 67_108_864
V1_SOURCE_PROFILES: Final = frozenset({"Claude/Memory Bank", "Codex", "Git", "Markdown"})
V1_MIGRATION_SOURCES: Final = frozenset({"legacy Mem0/RAG", "me-wiki", "unified-db"})
V2_SOURCE_PROFILES: Final = V1_SOURCE_PROFILES | frozenset(
    {
        "Database snapshot",
        "Document root",
        "GJC",
        "OMO/Senpi/pi",
        "OpenCode",
        "Orca exported records",
        "Project/JARVIS records",
    }
)
_TEMPLATE_COMMON: Final = frozenset(
    {"template_version", "authorization_state", "kind", "live_operation_authorized"}
)


class SourceKindV2(StrEnum):
    SOURCE_PROFILE = "source_profile"
    MIGRATION_SOURCE = "migration_source"


class SourceGenerationV2(StrEnum):
    CERTIFIED_V1 = "certified-v1"
    CERTIFIED_V2 = "certified-v2"


class ParserCapabilityNameV2(StrEnum):
    text = "text"
    markdown = "markdown"
    csv = "csv"
    json = "json"
    jsonl = "jsonl"
    yaml = "yaml"
    toml = "toml"
    pdf = "pdf"
    docx = "docx"
    xlsx = "xlsx"
    hwpx = "hwpx"


class _HasExpectedScopes(Protocol):
    expected_scopes: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True, slots=True)
class SourceIdentityV2:
    name: str
    kind: SourceKindV2
    generation: SourceGenerationV2


@dataclass(frozen=True, slots=True)
class ParserCapabilityV2:
    name: ParserCapabilityNameV2
    version: str
    media_types: tuple[str, ...]
    max_bytes: int

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> ParserCapabilityV2:
        values = _strict(data, frozenset({"name", "version", "media_types", "max_bytes"}))
        try:
            name = ParserCapabilityNameV2(_text(values["name"], "name"))
        except ValueError as exc:
            raise InvalidContractValue("parser capability name is not closed") from exc
        version = _text(values["version"], "version")
        media_types = tuple(_text(item, "media_types") for item in _seq(values["media_types"], "media_types"))
        if len(media_types) != len(set(media_types)):
            raise InvalidContractValue("media_types must be unique")
        max_bytes = values["max_bytes"]
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1 or max_bytes > PARSER_MAX_BYTES:
            raise InvalidContractValue("max_bytes must be an integer in 1..67108864")
        return cls(name, version, media_types, max_bytes)


@dataclass(frozen=True, slots=True)
class CertifiedV2ExpectedScopesTemplateV1:
    authorization_state: str
    live_operation_authorized: bool
    manifest: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class CertifiedV2TrustedBindingsTemplateV1:
    authorization_state: str
    live_operation_authorized: bool
    decision_identities: tuple[tuple[str, str, str | None], ...]
    key_material_present: bool


_IDENTITIES: Final[dict[str, tuple[SourceKindV2, SourceGenerationV2]]] = {
    **{name: (SourceKindV2.SOURCE_PROFILE, SourceGenerationV2.CERTIFIED_V1) for name in V1_SOURCE_PROFILES},
    **{name: (SourceKindV2.MIGRATION_SOURCE, SourceGenerationV2.CERTIFIED_V1) for name in V1_MIGRATION_SOURCES},
    **{
        name: (SourceKindV2.SOURCE_PROFILE, SourceGenerationV2.CERTIFIED_V2)
        for name in V2_SOURCE_PROFILES - V1_SOURCE_PROFILES
    },
}


def _strict(data: Mapping[str, object], fields: frozenset[str]) -> dict[str, object]:
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _text(value: object, field: str) -> str:
    if isinstance(value, str) and value and "\x00" not in value:
        return value
    raise InvalidContractValue(f"{field} must be a non-empty string")


def _seq(value: object, field: str) -> tuple[object, ...]:
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return tuple(value)
    raise InvalidContractValue(f"{field} must be an array")


def require_complete_typed_adapter_owners(owners: Mapping[str, str]) -> None:
    """Reject missing, extra, duplicate, or generic adapter owners."""
    expected = {item.name for item in certified_source_identities()}
    if set(owners) != expected:
        raise InvalidContractValue("adapter roster must name every certified identity exactly once")
    names = tuple(owners.values())
    if len(names) != len(set(names)):
        raise InvalidContractValue("adapter owner must be unique")
    if "SourceAdapter" in names:
        raise InvalidContractValue("generic adapter family is forbidden")


def parse_source_identity(name: object) -> SourceIdentityV2:
    """Parse one exact canonical identity. Aliases never match."""
    if not isinstance(name, str) or name not in _IDENTITIES:
        raise InvalidContractValue("source identity is not a canonical closed name")
    kind, generation = _IDENTITIES[name]
    return SourceIdentityV2(name=name, kind=kind, generation=generation)


def certified_source_identities() -> tuple[SourceIdentityV2, ...]:
    """Return every closed source and migration identity."""
    return tuple(parse_source_identity(name) for name in sorted(_IDENTITIES))


def certified_v2_expected_scope_tuples() -> tuple[tuple[str, str, str], ...]:
    """Return the exact resolver-compatible certified-v2 expected-scope roster."""
    return tuple(
        sorted(
            (
                *(("DB-02", "source_profile", name) for name in V2_SOURCE_PROFILES),
                *(("DB-03", "migration_source", name) for name in V1_MIGRATION_SOURCES),
                ("DB-06", "external_model_route", "model-a"),
                ("DB-08", "export_destination", "archive"),
            )
        )
    )


def allowed_scope_inventories() -> dict[str, frozenset[frozenset[str]]]:
    """Return the exact allowed DB-02/DB-03 inventories for v1 or v2 rosters."""
    return {
        "DB-02": frozenset({V1_SOURCE_PROFILES, V2_SOURCE_PROFILES}),
        "DB-03": frozenset({V1_MIGRATION_SOURCES}),
    }


def parser_capability_grants_source_authority(_capability: ParserCapabilityV2) -> bool:
    """Parser extensions never create or widen source authority."""
    return False


def reject_unbound_source_identities(
    scoped_names: tuple[tuple[str, str | None], ...],
    expected_scopes: tuple[tuple[str, str, str], ...],
) -> None:
    """Reject aliases and certified-v2 names under a certified-v1 roster."""
    expected = {(kind, name) for _, kind, name in expected_scopes}
    v1_pairs = {("source_profile", name) for name in V1_SOURCE_PROFILES} | {
        ("migration_source", name) for name in V1_MIGRATION_SOURCES
    }
    expected_sources = {pair for pair in expected if pair[0] in {"source_profile", "migration_source"}}
    v1_only = expected_sources <= v1_pairs
    for kind, name in scoped_names:
        if kind not in {"source_profile", "migration_source"} or name is None:
            continue
        identity = parse_source_identity(name)
        if identity.kind.value != kind:
            raise InvalidContractValue("source identity kind mismatch")
        if (kind, name) in expected:
            continue
        if identity.generation is SourceGenerationV2.CERTIFIED_V2 and v1_only:
            raise InvalidContractValue("certified-v1 expected scopes do not authorize a certified-v2 profile")
        raise InvalidContractValue("source identity is absent from the expected-scope manifest")


def authorize_identity_against_manifest(identity: SourceIdentityV2, manifest: _HasExpectedScopes) -> None:
    """Allow a source identity only when the expected-scope roster names it."""
    reject_unbound_source_identities(((identity.kind.value, identity.name),), manifest.expected_scopes)


def _load_object(raw: bytes) -> dict[str, object]:
    try:
        payload: object = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidContractValue("governance template must be JSON") from exc
    if not isinstance(payload, dict):
        raise InvalidContractValue("governance template must be an object")
    return payload


def _template_root(data: Mapping[str, object], kind: str, extra: frozenset[str]) -> dict[str, object]:
    values = _strict(data, _TEMPLATE_COMMON | extra)
    if values["template_version"] != TEMPLATE_VERSION:
        raise UnsupportedContractVersion("unsupported template_version")
    if values["authorization_state"] != "NON_AUTHORIZING":
        raise InvalidContractValue("certified-v2 templates must be NON_AUTHORIZING")
    if values["kind"] != kind:
        raise InvalidContractValue("governance template kind mismatch")
    if values["live_operation_authorized"] is not False:
        raise InvalidContractValue("certified-v2 templates cannot authorize live operation")
    return values


def parse_certified_v2_expected_scopes_template(raw: bytes) -> CertifiedV2ExpectedScopesTemplateV1:
    """Parse the unsigned certified-v2 expected-scope template."""
    values = _template_root(_load_object(raw), "expected_scopes", frozenset({"manifest"}))
    manifest = values["manifest"]
    if not isinstance(manifest, Mapping):
        raise InvalidContractValue("manifest must be an object")
    scopes = manifest.get("expected_scopes")
    if not isinstance(scopes, list) or not scopes:
        raise InvalidContractValue("expected_scopes must be a non-empty roster")
    return CertifiedV2ExpectedScopesTemplateV1("NON_AUTHORIZING", False, dict(manifest))


def parse_certified_v2_trusted_bindings_template(raw: bytes) -> CertifiedV2TrustedBindingsTemplateV1:
    """Parse the unsigned certified-v2 trusted-bindings template. No key material."""
    values = _template_root(_load_object(raw), "trusted_bindings", frozenset({"decision_identities"}))
    entries = _seq(values["decision_identities"], "decision_identities")
    identities: list[tuple[str, str, str | None]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise InvalidContractValue("decision_identities entries must be objects")
        item = _strict(entry, frozenset({"decision_id", "scope_kind", "scope_name"}))
        scope_name = item["scope_name"]
        if scope_name is not None:
            scope_name = _text(scope_name, "scope_name")
        identities.append(
            (_text(item["decision_id"], "decision_id"), _text(item["scope_kind"], "scope_kind"), scope_name)
        )
    parsed = tuple(identities)
    if not parsed:
        raise InvalidContractValue("decision_identities must be a non-empty roster")
    if parsed != tuple(sorted(parsed, key=lambda item: (item[0], item[1], item[2] or ""))):
        raise InvalidContractValue("decision_identities must be sorted")
    return CertifiedV2TrustedBindingsTemplateV1("NON_AUTHORIZING", False, parsed, False)


__all__ = (
    "PARSER_MAX_BYTES",
    "TEMPLATE_VERSION",
    "V1_MIGRATION_SOURCES",
    "V1_SOURCE_PROFILES",
    "V2_SOURCE_PROFILES",
    "CertifiedV2ExpectedScopesTemplateV1",
    "CertifiedV2TrustedBindingsTemplateV1",
    "ParserCapabilityNameV2",
    "ParserCapabilityV2",
    "SourceGenerationV2",
    "SourceIdentityV2",
    "SourceKindV2",
    "allowed_scope_inventories",
    "authorize_identity_against_manifest",
    "certified_source_identities",
    "certified_v2_expected_scope_tuples",
    "parse_certified_v2_expected_scopes_template",
    "parse_certified_v2_trusted_bindings_template",
    "parse_source_identity",
    "parser_capability_grants_source_authority",
    "require_complete_typed_adapter_owners",
    "reject_unbound_source_identities",
)
