"""Closed workspace-bound identity authorization V2 contracts."""
from __future__ import annotations

import json
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

import pytest

from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.identity_auth_v2_contracts import (
    DeviceRevocationV2,
    TrustedDeviceEnrollmentV2,
    WorkspaceTrustRootV2,
)
from wiki_spike.memory_core.identity_auth_v2_delegation import (
    DelegatedReviewGrantV2,
    DelegatedReviewRevocationV2,
)
from wiki_spike.memory_core.identity_auth_v2_parse import identity_auth_digest
from wiki_spike.memory_core.identity_auth_v2_request import CapabilityRequestV2
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_ROOT = Path(__file__).resolve().parents[2]


class _Wire(Protocol):
    def to_mapping(self) -> dict[str, JsonValue]: ...


def _assert_schema_valid(mapping: Mapping[str, JsonValue]) -> None:
    schema = _ROOT / "schemas/second-brain/identity-authorization-v2.schema.json"
    program = (
        "import json,jsonschema,sys;"
        "schema=json.loads(open(sys.argv[1]).read());"
        "jsonschema.Draft202012Validator(schema).validate(json.loads(sys.argv[2]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", program, str(schema), json.dumps(mapping)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def _ref(kind: str, digit: str) -> str:
    return f"{kind}:{digit * 64}"


def _seal(
    kind: str,
    digest_field: str,
    body: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    sealed = dict(body)
    sealed[digest_field] = identity_auth_digest(kind, body)
    return sealed


def _root() -> dict[str, JsonValue]:
    return _seal(
        "workspace-trust-root",
        "root_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "trust_root_ref": _ref("trust-root", "1"),
            "root_revision": "1",
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "owner_key_ref": _ref("key", "4"),
            "approver_key_ref": _ref("key", "5"),
        },
    )


def _enrollment() -> dict[str, JsonValue]:
    return _seal(
        "trusted-device-enrollment",
        "enrollment_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "enrollment_ref": _ref("enrollment", "6"),
            "trust_root_ref": _ref("trust-root", "1"),
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "device_key_ref": _ref("device", "7"),
            "subject_key_ref": _ref("key", "4"),
            "enrolled_by_key_ref": _ref("key", "4"),
            "enrolled_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-02-01T00:00:00Z",
        },
    )


def _device_revocation() -> dict[str, JsonValue]:
    return _seal(
        "device-revocation",
        "revocation_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "revocation_ref": _ref("revocation", "8"),
            "trust_root_ref": _ref("trust-root", "1"),
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "device_key_ref": _ref("device", "7"),
            "revoked_by_key_ref": _ref("key", "4"),
            "revoked_at": "2030-01-02T00:00:00Z",
            "reason_code": "lost",
            "revocation_epoch": "1",
        },
    )


def _grant() -> dict[str, JsonValue]:
    return _seal(
        "delegated-review-grant",
        "grant_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "grant_ref": _ref("grant", "9"),
            "grant_revision": "1",
            "trust_root_ref": _ref("trust-root", "1"),
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "grantor_key_ref": _ref("key", "4"),
            "reviewer_key_ref": _ref("key", "a"),
            "actions": ["review.approve"],
            "granted_at": "2030-01-01T00:00:00Z",
            "expires_at": "2030-02-01T00:00:00Z",
        },
    )


def _grant_revocation() -> dict[str, JsonValue]:
    return _seal(
        "delegated-review-revocation",
        "revocation_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "revocation_ref": _ref("revocation", "b"),
            "grant_ref": _ref("grant", "9"),
            "trust_root_ref": _ref("trust-root", "1"),
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "revoked_by_key_ref": _ref("key", "4"),
            "revoked_at": "2030-01-02T00:00:00Z",
            "reason_code": "owner_revoked",
        },
    )


def _request() -> dict[str, JsonValue]:
    return _seal(
        "capability-request",
        "request_digest",
        {
            "identity_auth_version": "second-brain-identity-auth-v2",
            "request_ref": _ref("request", "c"),
            "capability_ref": _ref("capability", "d"),
            "workspace_ref": _ref("workspace", "2"),
            "profile_ref": _ref("profile", "3"),
            "subject_key_ref": _ref("key", "a"),
            "device_key_ref": _ref("device", "e"),
            "actions": ["review.approve"],
            "requested_at": "2030-01-03T00:00:00Z",
        },
    )


def test_all_v2_contracts_parse_and_match_schema() -> None:
    cases: tuple[
        tuple[
            Callable[[], dict[str, JsonValue]],
            Callable[[Mapping[str, JsonValue]], _Wire],
        ],
        ...,
    ] = (
        (_root, WorkspaceTrustRootV2.from_mapping),
        (_enrollment, TrustedDeviceEnrollmentV2.from_mapping),
        (_device_revocation, DeviceRevocationV2.from_mapping),
        (_grant, DelegatedReviewGrantV2.from_mapping),
        (_grant_revocation, DelegatedReviewRevocationV2.from_mapping),
        (_request, CapabilityRequestV2.from_mapping),
    )
    for factory, parser in cases:
        mapping = factory()
        parsed = parser(mapping)
        assert parsed.to_mapping() == mapping
        _assert_schema_valid(mapping)


@pytest.mark.parametrize(
    ("factory", "contract", "field", "value"),
    [
        (_grant, DelegatedReviewGrantV2.from_mapping, "actions", ["workspace.owner.transfer"]),
        (_grant, DelegatedReviewGrantV2.from_mapping, "actions", ["review.reject", "review.approve"]),
        (_grant, DelegatedReviewGrantV2.from_mapping, "expires_at", "2030-01-01T00:00:00Z"),
        (_enrollment, TrustedDeviceEnrollmentV2.from_mapping, "expires_at", "2030-01-01T00:00:00Z"),
        (_device_revocation, DeviceRevocationV2.from_mapping, "reason_code", "unknown"),
        (_request, CapabilityRequestV2.from_mapping, "requested_at", "2030-01-03T00:00:00+00:00"),
    ],
)
def test_contracts_refuse_invalid_policy_values(
    factory: Callable[[], dict[str, JsonValue]],
    contract: Callable[[Mapping[str, JsonValue]], object],
    field: str,
    value: JsonValue,
) -> None:
    mapping = factory()
    mapping[field] = value
    with pytest.raises(InvalidContractValue):
        _ = contract(mapping)


def test_digest_tamper_extra_fields_and_raw_numbers_refuse() -> None:
    mapping = _root()
    mapping["workspace_ref"] = _ref("workspace", "f")
    with pytest.raises(InvalidContractValue, match="digest"):
        _ = WorkspaceTrustRootV2.from_mapping(mapping)
    extra = _root()
    extra["escape"] = "forbidden"
    with pytest.raises(UnknownContractField):
        _ = WorkspaceTrustRootV2.from_mapping(extra)
    with pytest.raises(UnifiedDbExportError):
        _ = decode_json_object(json.dumps({**_root(), "root_revision": 1}))
