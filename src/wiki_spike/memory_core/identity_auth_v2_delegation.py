"""Workspace-bound delegation and capability request contracts."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from .contracts import JsonValue
from .errors import InvalidContractValue
from .identity_auth_v2_parse import (
    IDENTITY_AUTH_VERSION,
    parse_actions,
    parse_const,
    parse_header,
    parse_instant,
    parse_positive,
    parse_ref,
    refuse_reserved_review_actions,
    require_before,
    require_digest,
)

_GRANT_KIND: Final = "delegated-review-grant"
_REVOCATION_KIND: Final = "delegated-review-revocation"
_GRANT_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "grant_ref",
        "grant_revision",
        "trust_root_ref",
        "workspace_ref",
        "profile_ref",
        "grantor_key_ref",
        "reviewer_key_ref",
        "actions",
        "granted_at",
        "expires_at",
        "grant_digest",
    }
)
_REVOCATION_FIELDS: Final = frozenset(
    {
        "identity_auth_version",
        "revocation_ref",
        "grant_ref",
        "trust_root_ref",
        "workspace_ref",
        "profile_ref",
        "revoked_by_key_ref",
        "revoked_at",
        "reason_code",
        "revocation_digest",
    }
)
@dataclass(frozen=True, slots=True)
class DelegatedReviewGrantV2:
    identity_auth_version: str
    grant_ref: str
    grant_revision: str
    trust_root_ref: str
    workspace_ref: str
    profile_ref: str
    grantor_key_ref: str
    reviewer_key_ref: str
    actions: tuple[str, ...]
    granted_at: str
    expires_at: str
    grant_digest: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> DelegatedReviewGrantV2:
        parse_header(data, _GRANT_FIELDS)
        actions = parse_actions(data["actions"], "actions")
        refuse_reserved_review_actions(actions)
        grant = cls(
            IDENTITY_AUTH_VERSION,
            parse_ref(data["grant_ref"], "grant_ref", "grant"),
            parse_positive(data["grant_revision"], "grant_revision"),
            parse_ref(data["trust_root_ref"], "trust_root_ref", "trust-root"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["grantor_key_ref"], "grantor_key_ref", "key"),
            parse_ref(data["reviewer_key_ref"], "reviewer_key_ref", "key"),
            actions,
            parse_instant(data["granted_at"], "granted_at"),
            parse_instant(data["expires_at"], "expires_at"),
            parse_const(data["grant_digest"], "grant_digest", str(data["grant_digest"])),
        )
        if grant.grantor_key_ref == grant.reviewer_key_ref:
            raise InvalidContractValue("reviewer must not be the grantor")
        require_before(grant.granted_at, grant.expires_at, "expires_at")
        require_digest(
            data["grant_digest"],
            "grant_digest",
            _GRANT_KIND,
            grant.body_mapping(),
        )
        return grant

    def body_mapping(self) -> dict[str, JsonValue]:
        body = self.to_mapping()
        del body["grant_digest"]
        return body

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "identity_auth_version": self.identity_auth_version,
            "grant_ref": self.grant_ref,
            "grant_revision": self.grant_revision,
            "trust_root_ref": self.trust_root_ref,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "grantor_key_ref": self.grantor_key_ref,
            "reviewer_key_ref": self.reviewer_key_ref,
            "actions": list(self.actions),
            "granted_at": self.granted_at,
            "expires_at": self.expires_at,
            "grant_digest": self.grant_digest,
        }


@dataclass(frozen=True, slots=True)
class DelegatedReviewRevocationV2:
    identity_auth_version: str
    revocation_ref: str
    grant_ref: str
    trust_root_ref: str
    workspace_ref: str
    profile_ref: str
    revoked_by_key_ref: str
    revoked_at: str
    reason_code: str
    revocation_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> DelegatedReviewRevocationV2:
        parse_header(data, _REVOCATION_FIELDS)
        revocation = cls(
            IDENTITY_AUTH_VERSION,
            parse_ref(data["revocation_ref"], "revocation_ref", "revocation"),
            parse_ref(data["grant_ref"], "grant_ref", "grant"),
            parse_ref(data["trust_root_ref"], "trust_root_ref", "trust-root"),
            parse_ref(data["workspace_ref"], "workspace_ref", "workspace"),
            parse_ref(data["profile_ref"], "profile_ref", "profile"),
            parse_ref(data["revoked_by_key_ref"], "revoked_by_key_ref", "key"),
            parse_instant(data["revoked_at"], "revoked_at"),
            parse_const(
                data["reason_code"], "reason_code", "owner_revoked"
            ),
            parse_const(
                data["revocation_digest"],
                "revocation_digest",
                str(data["revocation_digest"]),
            ),
        )
        require_digest(
            data["revocation_digest"],
            "revocation_digest",
            _REVOCATION_KIND,
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
            "grant_ref": self.grant_ref,
            "trust_root_ref": self.trust_root_ref,
            "workspace_ref": self.workspace_ref,
            "profile_ref": self.profile_ref,
            "revoked_by_key_ref": self.revoked_by_key_ref,
            "revoked_at": self.revoked_at,
            "reason_code": self.reason_code,
            "revocation_digest": self.revocation_digest,
        }
