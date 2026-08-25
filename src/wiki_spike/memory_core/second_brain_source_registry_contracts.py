"""Versioned contracts for the encrypted source registry."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

type JsonValue = str | int | bool | None | list[JsonValue] | dict[str, JsonValue]

SOURCE_REGISTRATION_REQUEST_VERSION: Final = "second-brain-source-registration-request/v1"
ENCRYPTED_SOURCE_DESCRIPTOR_VERSION: Final = "second-brain-encrypted-source-descriptor/v1"
ENCRYPTED_SOURCE_REGISTRY_VERSION: Final = "second-brain-encrypted-source-registry/v1"
_KEYED_REF: Final = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")


class SourceProfileV1(StrEnum):
    CODEX = "Codex"
    CLAUDE_MEMORY_BANK = "Claude/Memory Bank"
    GIT = "Git"
    MARKDOWN = "Markdown"


class SourceProfileStateV1(StrEnum):
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"


def _ref(value: str, field: str, kind: str) -> str:
    if _KEYED_REF.fullmatch(value) is None or not value.startswith(f"{kind}:"):
        raise InvalidContractValue(f"{field} must be an opaque {kind} reference")
    return value


def _text(value: JsonValue, field: str) -> str:
    if not isinstance(value, str):
        raise InvalidContractValue(f"{field} must be text")
    return value


@dataclass(frozen=True, slots=True)
class SourceRegistrationRequestV1:
    version: str
    workspace_ref: str
    profile: SourceProfileV1
    root_ref: str

    def __post_init__(self) -> None:
        if self.version != SOURCE_REGISTRATION_REQUEST_VERSION:
            raise UnsupportedContractVersion("unsupported source registration request version")
        _ref(self.workspace_ref, "workspace_ref", "workspace")
        _ref(self.root_ref, "root_ref", "source-root")


@dataclass(frozen=True, slots=True)
class EncryptedSourceDescriptorV1:
    """Transient descriptor result; root identity is never registry state."""

    version: str
    root_ref: str
    source_ref: str
    encrypted_descriptor_ref: str

    def __post_init__(self) -> None:
        if self.version != ENCRYPTED_SOURCE_DESCRIPTOR_VERSION:
            raise UnsupportedContractVersion("unsupported encrypted source descriptor version")
        _ref(self.root_ref, "root_ref", "source-root")
        _ref(self.source_ref, "source_ref", "source")
        _ref(self.encrypted_descriptor_ref, "encrypted_descriptor_ref", "encrypted-source-descriptor")


@dataclass(frozen=True, slots=True)
class EncryptedSourceRegistryEntryV1:
    """Plaintext-safe registry row containing opaque identity and ciphertext refs only."""

    version: str
    workspace_ref: str
    profile: SourceProfileV1
    state: SourceProfileStateV1
    source_ref: str
    root_binding_digest: str
    encrypted_descriptor_ref: str

    def __post_init__(self) -> None:
        if self.version != ENCRYPTED_SOURCE_REGISTRY_VERSION:
            raise UnsupportedContractVersion("unsupported encrypted source registry version")
        _ref(self.workspace_ref, "workspace_ref", "workspace")
        _ref(self.source_ref, "source_ref", "source")
        if re.fullmatch(r"[0-9a-f]{64}", self.root_binding_digest) is None:
            raise InvalidContractValue("root_binding_digest must be a lowercase SHA-256 digest")
        _ref(self.encrypted_descriptor_ref, "encrypted_descriptor_ref", "encrypted-source-descriptor")

    def to_json(self) -> bytes:
        return json.dumps(
            {
                "encrypted_descriptor_ref": self.encrypted_descriptor_ref,
                "profile": self.profile.value,
                "root_binding_digest": self.root_binding_digest,
                "source_ref": self.source_ref,
                "state": self.state.value,
                "version": self.version,
                "workspace_ref": self.workspace_ref,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    @classmethod
    def from_json(cls, raw: bytes) -> EncryptedSourceRegistryEntryV1:
        try:
            value: JsonValue = json.loads(raw.decode())
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise InvalidContractValue("encrypted source registry row must be JSON") from exc
        fields = {
            "encrypted_descriptor_ref",
            "profile",
            "root_binding_digest",
            "source_ref",
            "state",
            "version",
            "workspace_ref",
        }
        if not isinstance(value, Mapping):
            raise InvalidContractValue("encrypted source registry row must be an object")
        unknown, missing = set(value) - fields, fields - set(value)
        if unknown:
            raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
        if missing or any(not isinstance(value[field], str) for field in fields):
            raise InvalidContractValue("encrypted source registry row fields must be text")
        try:
            profile = SourceProfileV1(_text(value["profile"], "profile"))
            state = SourceProfileStateV1(_text(value["state"], "state"))
        except ValueError as exc:
            raise InvalidContractValue("source profile or state is not closed") from exc
        return cls(
            version=_text(value["version"], "version"),
            workspace_ref=_text(value["workspace_ref"], "workspace_ref"),
            profile=profile,
            state=state,
            source_ref=_text(value["source_ref"], "source_ref"),
            root_binding_digest=_text(value["root_binding_digest"], "root_binding_digest"),
            encrypted_descriptor_ref=_text(value["encrypted_descriptor_ref"], "encrypted_descriptor_ref"),
        )


@dataclass(frozen=True, slots=True)
class SourceRegistryAuthorityV1:
    profile_states: Mapping[SourceProfileV1, SourceProfileStateV1]
    known_root_refs: frozenset[str]

    def __post_init__(self) -> None:
        if set(self.profile_states) != set(SourceProfileV1):
            raise InvalidContractValue("source authority must state every v1 source profile")
        for root_ref in self.known_root_refs:
            _ref(root_ref, "known_root_refs", "source-root")
        object.__setattr__(self, "profile_states", MappingProxyType(dict(self.profile_states)))


__all__ = (
    "ENCRYPTED_SOURCE_DESCRIPTOR_VERSION",
    "ENCRYPTED_SOURCE_REGISTRY_VERSION",
    "SOURCE_REGISTRATION_REQUEST_VERSION",
    "EncryptedSourceDescriptorV1",
    "EncryptedSourceRegistryEntryV1",
    "SourceProfileStateV1",
    "SourceProfileV1",
    "SourceRegistrationRequestV1",
    "SourceRegistryAuthorityV1",
)
