"""Immutable contracts for the signed macOS field-AEAD persistence profile."""
from __future__ import annotations

import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import ClassVar

from .contracts import JsonValue
from .errors import InvalidContractValue, UnknownContractField
from .second_brain_ledger_contracts import canonical_ledger_digest

MAC_FIELD_AEAD_PROFILE_V1 = "mac-field-aead-profile-v1"
PERSISTENCE_PROFILE_RECEIPT_V1 = "persistence-profile-receipt-v1"
PERSISTENCE_PROFILE_SIGNATURE_DOMAIN = "second-brain-persistence-profile-v1"

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
_KEY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_UTC_SECONDS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _strict_strings(
    data: Mapping[str, JsonValue], fields: frozenset[str]
) -> dict[str, str]:
    unknown = set(data) - fields
    missing = fields - set(data)
    if unknown or missing:
        raise UnknownContractField(
            f"contract fields invalid unknown={sorted(unknown)} missing={sorted(missing)}"
        )
    values: dict[str, str] = {}
    for field in fields:
        value = data[field]
        if not isinstance(value, str):
            raise InvalidContractValue(f"{field} must be a string")
        values[field] = value
    return values


def _digest(value: str, field: str) -> str:
    if _DIGEST.fullmatch(value) is None:
        raise InvalidContractValue(f"{field} must be a lowercase sha256 digest")
    return value


@dataclass(frozen=True, slots=True)
class MacPersistenceProfileV1:
    """Exact field-AEAD persistence selection for stdlib SQLite on macOS."""

    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "profile_version",
            "profile_name",
            "sqlite_runtime",
            "state_authority",
            "content_store",
            "content_cipher",
            "database_page_cipher",
            "sqlcipher_status",
            "sqlcipher_must_verdict",
            "sqlcipher_artifact_digest",
            "profile_digest",
        }
    )
    profile_version: str
    profile_name: str
    sqlite_runtime: str
    state_authority: str
    content_store: str
    content_cipher: str
    database_page_cipher: str
    sqlcipher_status: str
    sqlcipher_must_verdict: str
    sqlcipher_artifact_digest: str
    profile_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> MacPersistenceProfileV1:
        values = _strict_strings(data, cls.FIELDS)
        expected = {
            "profile_version": MAC_FIELD_AEAD_PROFILE_V1,
            "profile_name": "mac-field-aead-v1",
            "sqlite_runtime": f"python-stdlib-sqlite3/{sqlite3.sqlite_version}",
            "state_authority": "LifecycleDatabase",
            "content_store": "EncryptedContentStore",
            "content_cipher": "AES-256-GCM",
            "database_page_cipher": "none",
        }
        for field, expected_value in expected.items():
            if values[field] != expected_value:
                raise InvalidContractValue(f"{field} must be exactly {expected_value}")
        if (
            values["sqlcipher_status"] != "platform_unavailable"
            or values["sqlcipher_must_verdict"] != "NOT_RUN"
        ):
            raise InvalidContractValue(
                "SQLCipher must remain platform_unavailable with MUST verdict NOT_RUN"
            )
        artifact_digest = _digest(
            values["sqlcipher_artifact_digest"], "sqlcipher_artifact_digest"
        )
        body: dict[str, JsonValue] = {
            field: values[field] for field in cls.FIELDS - {"profile_digest"}
        }
        profile_digest = _digest(values["profile_digest"], "profile_digest")
        if profile_digest != canonical_ledger_digest(
            "mac-persistence-profile-v1", body
        ):
            raise InvalidContractValue("profile_digest does not bind the profile body")
        return cls(
            values["profile_version"],
            values["profile_name"],
            values["sqlite_runtime"],
            values["state_authority"],
            values["content_store"],
            values["content_cipher"],
            values["database_page_cipher"],
            values["sqlcipher_status"],
            values["sqlcipher_must_verdict"],
            artifact_digest,
            profile_digest,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "profile_version": self.profile_version,
            "profile_name": self.profile_name,
            "sqlite_runtime": self.sqlite_runtime,
            "state_authority": self.state_authority,
            "content_store": self.content_store,
            "content_cipher": self.content_cipher,
            "database_page_cipher": self.database_page_cipher,
            "sqlcipher_status": self.sqlcipher_status,
            "sqlcipher_must_verdict": self.sqlcipher_must_verdict,
            "sqlcipher_artifact_digest": self.sqlcipher_artifact_digest,
            "profile_digest": self.profile_digest,
        }

def persistence_profile_authorization_payload(
    *,
    receipt_version: str,
    profile_digest: str,
    owner_key_id: str,
    approver_key_id: str,
    authorized_at: str,
) -> dict[str, JsonValue]:
    """Return the unsigned receipt fields that both roles must sign."""
    return {
        "receipt_version": receipt_version,
        "profile_digest": profile_digest,
        "owner_key_id": owner_key_id,
        "approver_key_id": approver_key_id,
        "authorized_at": authorized_at,
    }


@dataclass(frozen=True, slots=True)
class PersistenceProfileReceiptV1:
    """Two-party authorization receipt binding the selected profile."""

    FIELDS: ClassVar[frozenset[str]] = frozenset(
        {
            "receipt_version",
            "profile_digest",
            "owner_key_id",
            "approver_key_id",
            "owner_signature",
            "approver_signature",
            "authorized_at",
            "receipt_digest",
        }
    )
    receipt_version: str
    profile_digest: str
    owner_key_id: str
    approver_key_id: str
    owner_signature: str
    approver_signature: str
    authorized_at: str
    receipt_digest: str

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> PersistenceProfileReceiptV1:
        values = _strict_strings(data, cls.FIELDS)
        if values["receipt_version"] != PERSISTENCE_PROFILE_RECEIPT_V1:
            raise InvalidContractValue("unsupported persistence profile receipt version")
        profile_digest = _digest(values["profile_digest"], "profile_digest")
        for field in ("owner_key_id", "approver_key_id"):
            if _KEY_ID.fullmatch(values[field]) is None:
                raise InvalidContractValue(f"{field} has an invalid key-id shape")
        for field in ("owner_signature", "approver_signature"):
            if _SIGNATURE.fullmatch(values[field]) is None:
                raise InvalidContractValue(f"{field} must be a raw Ed25519 signature")
        authorized_at = values["authorized_at"]
        if _UTC_SECONDS.fullmatch(authorized_at) is None:
            raise InvalidContractValue("authorized_at must be canonical UTC seconds")
        try:
            parsed_at = datetime.strptime(
                authorized_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC)
        except ValueError as exc:
            raise InvalidContractValue("authorized_at is not a real UTC instant") from exc
        if parsed_at.strftime("%Y-%m-%dT%H:%M:%SZ") != authorized_at:
            raise InvalidContractValue("authorized_at must be canonical UTC seconds")
        body: dict[str, JsonValue] = {
            field: values[field] for field in cls.FIELDS - {"receipt_digest"}
        }
        receipt_digest = _digest(values["receipt_digest"], "receipt_digest")
        if receipt_digest != canonical_ledger_digest(
            "persistence-profile-receipt-v1", body
        ):
            raise InvalidContractValue("receipt_digest does not bind the receipt body")
        return cls(
            values["receipt_version"],
            profile_digest,
            values["owner_key_id"],
            values["approver_key_id"],
            values["owner_signature"],
            values["approver_signature"],
            authorized_at,
            receipt_digest,
        )

    def to_mapping(self) -> dict[str, JsonValue]:
        return {
            "receipt_version": self.receipt_version,
            "profile_digest": self.profile_digest,
            "owner_key_id": self.owner_key_id,
            "approver_key_id": self.approver_key_id,
            "owner_signature": self.owner_signature,
            "approver_signature": self.approver_signature,
            "authorized_at": self.authorized_at,
            "receipt_digest": self.receipt_digest,
        }

    def signature_payload(self) -> Mapping[str, JsonValue]:
        return persistence_profile_authorization_payload(
            receipt_version=self.receipt_version,
            profile_digest=self.profile_digest,
            owner_key_id=self.owner_key_id,
            approver_key_id=self.approver_key_id,
            authorized_at=self.authorized_at,
        )
