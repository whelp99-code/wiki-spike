"""Pinned Mac production trusted public-key bindings."""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import NoReturn

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.second_brain_contracts import (
    ExpectedScopeManifestV1,
    TrustedAuthorityBindingsV1,
    TrustedDecisionKeyBindingsV1,
)
from wiki_spike.resources import (
    load_pinned_expected_scopes_bytes,
    load_pinned_trusted_bindings_bytes,
)

_VERSION = "second-brain-trusted-decision-key-bindings-v1"
_ROOT_FIELDS = frozenset(
    {"trusted_bindings_version", "decision_bindings", "aggregate_binding"}
)
_AUTHORITY_FIELDS = frozenset(
    {
        "approver_key_id",
        "approver_public_key_b64",
        "owner_key_id",
        "owner_public_key_b64",
    }
)
_DECISION_FIELDS = _AUTHORITY_FIELDS | {"decision_id", "scope_kind", "scope_name"}


def _reject_number(_token: str) -> NoReturn:
    raise InvalidContractValue("raw JSON numbers are forbidden")


def _no_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    parsed: dict[str, JsonValue] = {}
    for key, value in pairs:
        if key in parsed:
            raise InvalidContractValue(f"duplicate JSON key: {key}")
        parsed[key] = value
    return parsed


def _strict(
    data: Mapping[str, JsonValue], fields: frozenset[str]
) -> dict[str, JsonValue]:
    unknown, missing = set(data) - fields, fields - set(data)
    if unknown:
        raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _authority(data: Mapping[str, JsonValue]) -> TrustedAuthorityBindingsV1:
    values = _strict(data, _AUTHORITY_FIELDS)
    return TrustedAuthorityBindingsV1(
        _text(values["approver_key_id"], "approver_key_id"),
        _text(values["approver_public_key_b64"], "approver_public_key_b64"),
        _text(values["owner_key_id"], "owner_key_id"),
        _text(values["owner_public_key_b64"], "owner_public_key_b64"),
    )


def load_pinned_trusted_keys() -> TrustedDecisionKeyBindingsV1:
    """Parse packaged public trusted-bindings into pinned production keys."""
    payload: object = json.loads(
        load_pinned_trusted_bindings_bytes().decode("utf-8"),
        parse_int=_reject_number,
        parse_float=_reject_number,
        object_pairs_hook=_no_duplicates,
    )
    if not isinstance(payload, dict):
        raise InvalidContractValue("trusted bindings must be an object")
    values = _strict(payload, _ROOT_FIELDS)
    if values["trusted_bindings_version"] != _VERSION:
        raise InvalidContractValue("unsupported trusted_bindings_version")
    entries = values["decision_bindings"]
    if not isinstance(entries, list):
        raise InvalidContractValue("decision_bindings must be an array")
    aggregate = values["aggregate_binding"]
    if not isinstance(aggregate, Mapping):
        raise InvalidContractValue("aggregate_binding must be an object")
    bindings: dict[tuple[str, str, str | None], TrustedAuthorityBindingsV1] = {}
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise InvalidContractValue("decision_bindings entries must be objects")
        item = _strict(entry, _DECISION_FIELDS)
        scope_name = item["scope_name"]
        if scope_name is not None:
            scope_name = _text(scope_name, "scope_name")
        identity = (
            _text(item["decision_id"], "decision_id"),
            _text(item["scope_kind"], "scope_kind"),
            scope_name,
        )
        if identity in bindings:
            raise InvalidContractValue("duplicate decision identity")
        bindings[identity] = _authority(
            {field: item[field] for field in _AUTHORITY_FIELDS}
        )
    return TrustedDecisionKeyBindingsV1(bindings, _authority(aggregate))


def load_pinned_expected_scope_manifest() -> ExpectedScopeManifestV1:
    """Parse packaged public expected-scopes into the production pin."""
    payload: object = json.loads(
        load_pinned_expected_scopes_bytes().decode("utf-8"),
        parse_int=_reject_number,
        parse_float=_reject_number,
        object_pairs_hook=_no_duplicates,
    )
    if not isinstance(payload, dict):
        raise InvalidContractValue("expected scopes must be an object")
    return ExpectedScopeManifestV1.from_mapping(payload)
