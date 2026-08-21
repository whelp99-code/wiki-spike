"""Workspace-bound capability request contract for identity auth V2."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .identity_auth_v2_parse import (
    IDENTITY_AUTH_VERSION,
    parse_actions,
    parse_const,
    parse_header,
    parse_instant,
    parse_ref,
    require_digest,
)

_REQUEST_KIND: Final = "capability-request"
_REQUEST_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "request_ref",
        "capability_ref",
        "workspace_ref",
        "profile_ref",
        "subject_key_ref",
        "device_key_ref",
        "actions",
        "requested_at",
        "request_digest",
    }
)


@dataclass(frozen=True, slots=True)
class CapabilityRequestV2:
    identity_auth_version: str
    request_ref: str
    capability_ref: str
    workspace_ref: str
    profile_ref: str
    subject_key_ref: str
    device_key_ref: str
    actions: tuple[str, ...]
    requested_at: str
    request_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> CapabilityRequestV2:
        parse_header(data, _REQUEST_FIELDS)
        request = cls(
            IDENTITY_AUTH_VERSION,
            parse_ref(data["request_ref"], "request_ref", "request"),
            parse_ref(data["capability_ref"], "capability_ref", "capability"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["subject_key_ref"], "subject_key_ref", "key"),
            parse_ref(data["device_key_ref"], "device_key_ref", "device"),
            parse_actions(data["actions"], "actions"),
            parse_instant(data["requested_at"], "requested_at"),
            parse_const(
                data["request_digest"],
                "request_digest",
                str(data["request_digest"]),
            ),
        )
        require_digest(
            data["request_digest"],
            "request_digest",
            _REQUEST_KIND,
            request.body_mapping(),
        )
        return request

    def body_mapping(self) -> dict[str, JsonValue]:
        body = self.to_mapping()
        del body["request_digest"]
        return body

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_auth_version": self.identity_auth_version,
            "request_ref": self.request_ref,
            "capability_ref": self.capability_ref,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "subject_key_ref": self.subject_key_ref,
            "device_key_ref": self.device_key_ref,
            "actions": list(self.actions),
            "requested_at": self.requested_at,
            "request_digest": self.request_digest,
        }
