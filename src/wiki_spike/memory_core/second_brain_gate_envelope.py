"""Signed gate, role, bundle, input, output, target, and grant contracts."""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Final, TypeAlias

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

EnvelopeValue: TypeAlias = str | bool | list[str] | list[dict[str, str]] | dict[str, str] | JsonValue  # noqa: UP040

GATE_ENVELOPE_VERSION: Final = "second-brain-gate-envelope/v1"
ROLE_APPROVAL_VERSION: Final = "second-brain-role-approval/v1"
DESTRUCTIVE_APPROVAL_VERSION: Final = "second-brain-destructive-approval/v1"
EXECUTOR_BUNDLE_VERSION: Final = "second-brain-protected-executor-bundle/v1"
INPUT_MANIFEST_VERSION: Final = "second-brain-protected-input-manifest/v1"
OUTPUT_CAPABILITY_VERSION: Final = "second-brain-output-capability/v1"
TARGET_MANIFEST_VERSION: Final = "second-brain-protected-target-manifest/v1"
PREPARED_GRANT_VERSION: Final = "second-brain-prepared-execution-grant/v1"


class ProtectedOperation(StrEnum):
    CERTIFIED_IMPORT = "certified_import"
    CERTIFIED_ACTIVATION = "certified_activation"
    ROUTE_REHEARSAL = "route_rehearsal"
    ROUTE_SWITCH = "route_switch"
    RETENTION_CLOSE = "retention_close"
    DECOMMISSION = "decommission"


class ApprovalRole(StrEnum):
    MIGRATION = "migration"
    QUALITY = "quality"
    SECURITY = "security"
    PRODUCT = "product"


def digest_fields(payload: Mapping[str, EnvelopeValue], exclude: tuple[str, ...] = ()) -> str:
    return sha256(canonical_bytes({key: payload[key] for key in payload if key not in exclude})).hexdigest()


def signing_message(version: str, payload: Mapping[str, EnvelopeValue], exclude: tuple[str, ...] = ("signature",)) -> bytes:
    return version.encode("ascii") + b"\x00" + canonical_bytes({key: payload[key] for key in payload if key not in exclude})


def load_object(raw: bytes) -> dict[str, JsonValue]:
    try: data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise InvalidContractValue("payload must be canonical JSON") from exc
    if type(data) is not dict: raise InvalidContractValue("payload must be an object")
    return data


def require_fields(data: Mapping[str, JsonValue], fields: tuple[str, ...]) -> dict[str, JsonValue]:
    unknown, missing = set(data) - set(fields), set(fields) - set(data)
    if unknown: raise UnknownContractField(f"unknown fields: {sorted(unknown)}")
    if missing: raise InvalidContractValue(f"missing required fields: {sorted(missing)}")
    return dict(data)


def require_text(value: JsonValue, field: str) -> str:
    if type(value) is not str or not value: raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def require_digest(value: JsonValue, field: str) -> str:
    text = require_text(value, field)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text): raise InvalidContractValue(f"{field} must be a lowercase SHA-256 digest")
    return text


def require_bool(value: JsonValue, field: str, expected: bool) -> bool:
    if type(value) is not bool or value is not expected: raise InvalidContractValue(f"{field} must be {expected}")
    return value


def parse_operation(value: JsonValue) -> ProtectedOperation:
    try: return ProtectedOperation(require_text(value, "operation"))
    except ValueError as exc: raise InvalidContractValue("operation is not a protected operation") from exc


def parse_role(value: JsonValue) -> ApprovalRole:
    try: return ApprovalRole(require_text(value, "role"))
    except ValueError as exc: raise InvalidContractValue("role is not an approval role") from exc


def _require_version(values: Mapping[str, JsonValue], version: str, label: str) -> None:
    if values["version"] != version: raise UnsupportedContractVersion(f"unsupported {label} version")


@dataclass(frozen=True, slots=True)
class InputManifestEntryV1:
    ref: str
    kind: str
    sha256: str
    size: str
    media_type: str

    def to_mapping(self) -> dict[str, str]:
        return {"ref": self.ref, "kind": self.kind, "sha256": self.sha256, "size": self.size, "media_type": self.media_type}


def parse_entries(value: JsonValue) -> tuple[InputManifestEntryV1, ...]:
    if type(value) is not list: raise InvalidContractValue("entries must be an array")
    items = tuple(
        InputManifestEntryV1(require_text(item["ref"], "ref"), require_text(item["kind"], "kind"), require_digest(item["sha256"], "sha256"), require_text(item["size"], "size"), require_text(item["media_type"], "media_type"))
        for item in value if isinstance(item, Mapping)
    )
    if len(items) != len(value) or tuple(item.ref for item in items) != tuple(sorted(item.ref for item in items)):
        raise InvalidContractValue("entries must be sorted unique objects")
    return items


@dataclass(frozen=True, slots=True)
class ProtectedInputManifestV1:
    version: str
    operation: ProtectedOperation
    workspace_ref: str
    entries: tuple[InputManifestEntryV1, ...]
    manifest_sha256: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> ProtectedInputManifestV1:
        values = require_fields(data, ("version", "operation", "workspace_ref", "entries", "manifest_sha256")); _require_version(values, INPUT_MANIFEST_VERSION, "input manifest")
        entries = parse_entries(values["entries"])
        digest = digest_fields({"version": INPUT_MANIFEST_VERSION, "operation": require_text(values["operation"], "operation"), "workspace_ref": require_text(values["workspace_ref"], "workspace_ref"), "entries": [item.to_mapping() for item in entries]})
        if digest != require_digest(values["manifest_sha256"], "manifest_sha256"): raise InvalidContractValue("manifest_sha256 mismatch")
        return cls(INPUT_MANIFEST_VERSION, parse_operation(values["operation"]), require_text(values["workspace_ref"], "workspace_ref"), entries, digest)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ProtectedInputManifestV1:
        return cls.from_mapping(load_object(raw))


_BUNDLE_FIELDS: Final = ("version", "host_artifact_sha256", "executor_artifact_sha256", "lockfile_sha256", "operation", "callable_id", "request_schema_sha256", "authority_type", "bundle_sha256", "signer_ref", "key_id", "signature")


@dataclass(frozen=True, slots=True)
class ProtectedExecutorBundleV1:
    version: str
    host_artifact_sha256: str
    executor_artifact_sha256: str
    lockfile_sha256: str
    operation: ProtectedOperation
    callable_id: str
    request_schema_sha256: str
    authority_type: str
    bundle_sha256: str
    signer_ref: str
    key_id: str
    signature: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> ProtectedExecutorBundleV1:
        values = require_fields(data, _BUNDLE_FIELDS); _require_version(values, EXECUTOR_BUNDLE_VERSION, "executor bundle")
        digest = digest_fields({key: values[key] for key in _BUNDLE_FIELDS[:8]})
        if digest != require_digest(values["bundle_sha256"], "bundle_sha256"): raise InvalidContractValue("bundle_sha256 mismatch")
        return cls(EXECUTOR_BUNDLE_VERSION, require_digest(values["host_artifact_sha256"], "host_artifact_sha256"), require_digest(values["executor_artifact_sha256"], "executor_artifact_sha256"), require_digest(values["lockfile_sha256"], "lockfile_sha256"), parse_operation(values["operation"]), require_text(values["callable_id"], "callable_id"), require_digest(values["request_schema_sha256"], "request_schema_sha256"), require_text(values["authority_type"], "authority_type"), digest, require_text(values["signer_ref"], "signer_ref"), require_text(values["key_id"], "key_id"), require_text(values["signature"], "signature"))

    @classmethod
    def from_bytes(cls, raw: bytes) -> ProtectedExecutorBundleV1:
        return cls.from_mapping(load_object(raw))


_CAP_FIELDS: Final = ("version", "operation", "workspace_ref", "destination_ref", "create_only", "no_follow", "overwrite", "expires_at", "registry_ref", "registry_version", "capability_sha256")


@dataclass(frozen=True, slots=True)
class OutputCapabilityV1:
    version: str
    operation: ProtectedOperation
    workspace_ref: str
    destination_ref: str
    create_only: bool
    no_follow: bool
    overwrite: bool
    expires_at: str
    registry_ref: str
    registry_version: str
    capability_sha256: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> OutputCapabilityV1:
        values = require_fields(data, _CAP_FIELDS); _require_version(values, OUTPUT_CAPABILITY_VERSION, "output capability")
        digest = digest_fields({key: values[key] for key in _CAP_FIELDS[:-1]})
        if digest != require_digest(values["capability_sha256"], "capability_sha256"): raise InvalidContractValue("capability_sha256 mismatch")
        return cls(OUTPUT_CAPABILITY_VERSION, parse_operation(values["operation"]), require_text(values["workspace_ref"], "workspace_ref"), require_text(values["destination_ref"], "destination_ref"), require_bool(values["create_only"], "create_only", True), require_bool(values["no_follow"], "no_follow", True), require_bool(values["overwrite"], "overwrite", False), require_text(values["expires_at"], "expires_at"), require_text(values["registry_ref"], "registry_ref"), require_text(values["registry_version"], "registry_version"), digest)

    @classmethod
    def from_bytes(cls, raw: bytes) -> OutputCapabilityV1:
        return cls.from_mapping(load_object(raw))


@dataclass(frozen=True, slots=True)
class ProtectedTargetManifestV1:
    version: str
    operation: ProtectedOperation
    workspace_ref: str
    targets: tuple[tuple[str, str, str], ...]
    target_manifest_sha256: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> ProtectedTargetManifestV1:
        values = require_fields(data, ("version", "operation", "workspace_ref", "targets", "target_manifest_sha256")); _require_version(values, TARGET_MANIFEST_VERSION, "target manifest")
        if type(values["targets"]) is not list: raise InvalidContractValue("targets must be an array")
        targets = tuple((require_text(item["kind"], "kind"), require_text(item["ref"], "ref"), require_digest(item["sha256"], "sha256")) for item in values["targets"] if isinstance(item, Mapping))
        if len(targets) != len(values["targets"]) or targets != tuple(sorted(targets)): raise InvalidContractValue("targets must be sorted unique objects")
        digest = digest_fields({"version": TARGET_MANIFEST_VERSION, "operation": require_text(values["operation"], "operation"), "workspace_ref": require_text(values["workspace_ref"], "workspace_ref"), "targets": [{"kind": kind, "ref": ref, "sha256": digest} for kind, ref, digest in targets]})
        if digest != require_digest(values["target_manifest_sha256"], "target_manifest_sha256"): raise InvalidContractValue("target_manifest_sha256 mismatch")
        return cls(TARGET_MANIFEST_VERSION, parse_operation(values["operation"]), require_text(values["workspace_ref"], "workspace_ref"), targets, digest)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ProtectedTargetManifestV1:
        return cls.from_mapping(load_object(raw))


_GATE_FIELDS: Final = ("version", "gate_id", "operation", "workspace_ref", "authority_digest", "executor_bundle_sha256", "protected_input_manifest_sha256", "output_capability_ref", "output_capability_sha256", "output_registry_version", "request_digest", "role_approval_refs", "issued_at", "expires_at", "signer_ref", "key_id", "signature")


@dataclass(frozen=True, slots=True)
class GateEnvelopeV1:
    version: str
    gate_id: str
    operation: ProtectedOperation
    workspace_ref: str
    authority_digest: str
    executor_bundle_sha256: str
    protected_input_manifest_sha256: str
    output_capability_ref: str
    output_capability_sha256: str
    output_registry_version: str
    request_digest: str
    role_approval_refs: tuple[str, ...]
    issued_at: str
    expires_at: str
    signer_ref: str
    key_id: str
    signature: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> GateEnvelopeV1:
        values = require_fields(data, _GATE_FIELDS); _require_version(values, GATE_ENVELOPE_VERSION, "gate envelope")
        refs = values["role_approval_refs"]
        if type(refs) is not list or any(type(item) is not str or not item for item in refs) or len(set(refs)) != len(refs):
            raise InvalidContractValue("role_approval_refs must be unique strings")
        return cls(GATE_ENVELOPE_VERSION, require_text(values["gate_id"], "gate_id"), parse_operation(values["operation"]), require_text(values["workspace_ref"], "workspace_ref"), require_digest(values["authority_digest"], "authority_digest"), require_digest(values["executor_bundle_sha256"], "executor_bundle_sha256"), require_digest(values["protected_input_manifest_sha256"], "protected_input_manifest_sha256"), require_text(values["output_capability_ref"], "output_capability_ref"), require_digest(values["output_capability_sha256"], "output_capability_sha256"), require_text(values["output_registry_version"], "output_registry_version"), require_digest(values["request_digest"], "request_digest"), tuple(require_text(item, "role_approval_refs") for item in refs), require_text(values["issued_at"], "issued_at"), require_text(values["expires_at"], "expires_at"), require_text(values["signer_ref"], "signer_ref"), require_text(values["key_id"], "key_id"), require_text(values["signature"], "signature"))

    @classmethod
    def from_bytes(cls, raw: bytes) -> GateEnvelopeV1:
        return cls.from_mapping(load_object(raw))

    def to_mapping(self) -> dict[str, str | list[str]]:
        return {"version": self.version, "gate_id": self.gate_id, "operation": self.operation.value, "workspace_ref": self.workspace_ref, "authority_digest": self.authority_digest, "executor_bundle_sha256": self.executor_bundle_sha256, "protected_input_manifest_sha256": self.protected_input_manifest_sha256, "output_capability_ref": self.output_capability_ref, "output_capability_sha256": self.output_capability_sha256, "output_registry_version": self.output_registry_version, "request_digest": self.request_digest, "role_approval_refs": list(self.role_approval_refs), "issued_at": self.issued_at, "expires_at": self.expires_at, "signer_ref": self.signer_ref, "key_id": self.key_id, "signature": self.signature}


_ROLE_FIELDS: Final = ("version", "gate_id", "authority_digest", "role", "operation", "workspace_ref", "executor_bundle_sha256", "protected_input_manifest_sha256", "request_digest", "issued_at", "expires_at", "signer_ref", "key_id", "signature")


@dataclass(frozen=True, slots=True)
class RoleApprovalEnvelopeV1:
    version: str
    gate_id: str
    authority_digest: str
    role: ApprovalRole
    operation: ProtectedOperation
    workspace_ref: str
    executor_bundle_sha256: str
    protected_input_manifest_sha256: str
    request_digest: str
    issued_at: str
    expires_at: str
    signer_ref: str
    key_id: str
    signature: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> RoleApprovalEnvelopeV1:
        values = require_fields(data, _ROLE_FIELDS); _require_version(values, ROLE_APPROVAL_VERSION, "role approval")
        return cls(ROLE_APPROVAL_VERSION, require_text(values["gate_id"], "gate_id"), require_digest(values["authority_digest"], "authority_digest"), parse_role(values["role"]), parse_operation(values["operation"]), require_text(values["workspace_ref"], "workspace_ref"), require_digest(values["executor_bundle_sha256"], "executor_bundle_sha256"), require_digest(values["protected_input_manifest_sha256"], "protected_input_manifest_sha256"), require_digest(values["request_digest"], "request_digest"), require_text(values["issued_at"], "issued_at"), require_text(values["expires_at"], "expires_at"), require_text(values["signer_ref"], "signer_ref"), require_text(values["key_id"], "key_id"), require_text(values["signature"], "signature"))

    @classmethod
    def from_bytes(cls, raw: bytes) -> RoleApprovalEnvelopeV1:
        return cls.from_mapping(load_object(raw))


DESTRUCTIVE_APPROVAL_FIELDS: Final = ("version", "gate_id", "workspace_ref", "authority_digest", "decommission_certificate_sha256", "executor_bundle_sha256", "target_manifest_sha256", "issued_at", "expires_at", "signer_ref", "key_id", "signature")
_GRANT_FIELDS: Final = ("version", "journal_id", "gate_envelope_sha256", "role_approval_set_sha256", "protected_input_manifest_sha256", "output_capability_sha256", "request_digest", "executor_bundle_sha256", "workspace_ref", "target_manifest_sha256", "prepared_at", "recovery_authorized", "host_key_id", "grant_sha256", "host_signature")


@dataclass(frozen=True, slots=True)
class PreparedExecutionGrantV1:
    version: str
    journal_id: str
    gate_envelope_sha256: str
    role_approval_set_sha256: str
    protected_input_manifest_sha256: str
    output_capability_sha256: str
    request_digest: str
    executor_bundle_sha256: str
    workspace_ref: str
    target_manifest_sha256: str
    prepared_at: str
    recovery_authorized: bool
    host_key_id: str
    grant_sha256: str
    host_signature: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, JsonValue]) -> PreparedExecutionGrantV1:
        values = require_fields(data, _GRANT_FIELDS); _require_version(values, PREPARED_GRANT_VERSION, "prepared grant")
        digest = digest_fields({key: values[key] for key in _GRANT_FIELDS[:-2]})
        if digest != require_digest(values["grant_sha256"], "grant_sha256"): raise InvalidContractValue("grant_sha256 mismatch")
        return cls(PREPARED_GRANT_VERSION, require_text(values["journal_id"], "journal_id"), require_digest(values["gate_envelope_sha256"], "gate_envelope_sha256"), require_digest(values["role_approval_set_sha256"], "role_approval_set_sha256"), require_digest(values["protected_input_manifest_sha256"], "protected_input_manifest_sha256"), require_digest(values["output_capability_sha256"], "output_capability_sha256"), require_digest(values["request_digest"], "request_digest"), require_digest(values["executor_bundle_sha256"], "executor_bundle_sha256"), require_text(values["workspace_ref"], "workspace_ref"), require_digest(values["target_manifest_sha256"], "target_manifest_sha256"), require_text(values["prepared_at"], "prepared_at"), require_bool(values["recovery_authorized"], "recovery_authorized", True), require_text(values["host_key_id"], "host_key_id"), digest, require_text(values["host_signature"], "host_signature"))

    @classmethod
    def from_bytes(cls, raw: bytes) -> PreparedExecutionGrantV1:
        return cls.from_mapping(load_object(raw))

    def signing_payload(self) -> dict[str, str | bool]:
        return {key: getattr(self, key) for key in _GRANT_FIELDS[:-1]}
