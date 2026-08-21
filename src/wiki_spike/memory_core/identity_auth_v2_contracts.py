"""Workspace-bound trust-root and device contracts for identity auth V2."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue
from .identity_auth_v2_parse import (
    parse_const,
    parse_header,
    parse_instant,
    parse_positive,
    parse_ref,
    require_before,
    require_digest,
)

_VERSION: Final = "second-brain-identity-auth-v2"
_ROOT_KIND: Final = "workspace-trust-root"
_ENROLLMENT_KIND: Final = "trusted-device-enrollment"
_DEVICE_REVOCATION_KIND: Final = "device-revocation"
_ROOT_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "trust_root_ref",
        "root_revision",
        "workspace_ref",
        "profile_ref",
        "owner_key_ref",
        "approver_key_ref",
        "root_digest",
    }
)
_ENROLLMENT_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "enrollment_ref",
        "trust_root_ref",
        "workspace_ref",
        "profile_ref",
        "device_key_ref",
        "subject_key_ref",
        "enrolled_by_key_ref",
        "enrolled_at",
        "expires_at",
        "enrollment_digest",
    }
)
_DEVICE_REVOCATION_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "revocation_ref",
        "trust_root_ref",
        "workspace_ref",
        "profile_ref",
        "device_key_ref",
        "revoked_by_key_ref",
        "revoked_at",
        "reason_code",
        "revocation_epoch",
        "revocation_digest",
    }
)


@dataclass(frozen=True, slots=True)
class WorkspaceTrustRootV2:
    identity_auth_version: str
    trust_root_ref: str
    root_revision: str
    workspace_ref: str
    profile_ref: str
    owner_key_ref: str
    approver_key_ref: str
    root_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> WorkspaceTrustRootV2:
        parse_header(data, _ROOT_FIELDS)
        root = cls(
            _VERSION,
            parse_ref(data["trust_root_ref"], "trust_root_ref", "trust-root"),
            parse_positive(data["root_revision"], "root_revision"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["owner_key_ref"], "owner_key_ref", "key"),
            parse_ref(data["approver_key_ref"], "approver_key_ref", "key"),
            parse_const(data["root_digest"], "root_digest", str(data["root_digest"])),
        )
        if root.owner_key_ref == root.approver_key_ref:
            raise InvalidContractValue("owner and approver keys must be distinct")
        require_digest(data["root_digest"], "root_digest", _ROOT_KIND, root.body_mapping())
        return root

    def body_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_auth_version": self.identity_auth_version,
            "trust_root_ref": self.trust_root_ref,
            "root_revision": self.root_revision,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "owner_key_ref": self.owner_key_ref,
            "approver_key_ref": self.approver_key_ref,
        }

    def to_mapping(self) -> dict[str, JsonValue]:
        return {**self.body_mapping(), "root_digest": self.root_digest}


@dataclass(frozen=True, slots=True)
class TrustedDeviceEnrollmentV2:
    identity_auth_version: str
    enrollment_ref: str
    trust_root_ref: str
    workspace_ref: str
    profile_ref: str
    device_key_ref: str
    subject_key_ref: str
    enrolled_by_key_ref: str
    enrolled_at: str
    expires_at: str
    enrollment_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> TrustedDeviceEnrollmentV2:
        parse_header(data, _ENROLLMENT_FIELDS)
        enrollment = cls(
            _VERSION,
            parse_ref(data["enrollment_ref"], "enrollment_ref", "enrollment"),
            parse_ref(data["trust_root_ref"], "trust_root_ref", "trust-root"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["device_key_ref"], "device_key_ref", "device"),
            parse_ref(data["subject_key_ref"], "subject_key_ref", "key"),
            parse_ref(data["enrolled_by_key_ref"], "enrolled_by_key_ref", "key"),
            parse_instant(data["enrolled_at"], "enrolled_at"),
            parse_instant(data["expires_at"], "expires_at"),
            parse_const(
                data["enrollment_digest"],
                "enrollment_digest",
                str(data["enrollment_digest"]),
            ),
        )
        require_before(enrollment.enrolled_at, enrollment.expires_at, "expires_at")
        require_digest(
            data["enrollment_digest"],
            "enrollment_digest",
            _ENROLLMENT_KIND,
            enrollment.body_mapping(),
        )
        return enrollment

    def body_mapping(self) -> dict[str, JsonValue]:
        body = self.to_mapping()
        del body["enrollment_digest"]
        return body

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_auth_version": self.identity_auth_version,
            "enrollment_ref": self.enrollment_ref,
            "trust_root_ref": self.trust_root_ref,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "device_key_ref": self.device_key_ref,
            "subject_key_ref": self.subject_key_ref,
            "enrolled_by_key_ref": self.enrolled_by_key_ref,
            "enrolled_at": self.enrolled_at,
            "expires_at": self.expires_at,
            "enrollment_digest": self.enrollment_digest,
        }


@dataclass(frozen=True, slots=True)
class DeviceRevocationV2:
    identity_auth_version: str
    revocation_ref: str
    trust_root_ref: str
    workspace_ref: str
    profile_ref: str
    device_key_ref: str
    revoked_by_key_ref: str
    revoked_at: str
    reason_code: str
    revocation_epoch: str
    revocation_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> DeviceRevocationV2:
        parse_header(data, _DEVICE_REVOCATION_FIELDS)
        reason = parse_const(
            data["reason_code"], "reason_code", str(data["reason_code"])
        )
        if reason not in {"lost", "compromised", "retired"}:
            raise InvalidContractValue("reason_code is not a device revocation reason")
        revocation = cls(
            _VERSION,
            parse_ref(data["revocation_ref"], "revocation_ref", "revocation"),
            parse_ref(data["trust_root_ref"], "trust_root_ref", "trust-root"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["device_key_ref"], "device_key_ref", "device"),
            parse_ref(data["revoked_by_key_ref"], "revoked_by_key_ref", "key"),
            parse_instant(data["revoked_at"], "revoked_at"),
            reason,
            parse_positive(data["revocation_epoch"], "revocation_epoch"),
            parse_const(
                data["revocation_digest"],
                "revocation_digest",
                str(data["revocation_digest"]),
            ),
        )
        require_digest(
            data["revocation_digest"],
            "revocation_digest",
            _DEVICE_REVOCATION_KIND,
            revocation.body_mapping(),
        )
        return revocation

    def body_mapping(self) -> dict[str, JsonValue]:
        body = self.to_mapping()
        del body["revocation_digest"]
        return body

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_auth_version": self.identity_auth_version,
            "revocation_ref": self.revocation_ref,
            "trust_root_ref": self.trust_root_ref,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "device_key_ref": self.device_key_ref,
            "revoked_by_key_ref": self.revoked_by_key_ref,
            "revoked_at": self.revoked_at,
            "reason_code": self.reason_code,
            "revocation_epoch": self.revocation_epoch,
            "revocation_digest": self.revocation_digest,
        }
