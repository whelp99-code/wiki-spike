"""Fail-closed Recovery Set contracts and clean-room orchestration.

The RecoveryCoordinator treats signed Generation artifacts and the Recovery Set as
inputs to restore. SQLite/projections are rebuilt materializations, never truth.
The module is intentionally storage-independent; concrete filesystem/Git/SQLite
adapters live outside ``memory_core``.
"""
from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass
from enum import Enum
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from typing import Mapping, Protocol, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion
from .registries import HistoricalKeyRegistry, HistoricalPublicKey, signature_frame

RECOVERY_ITEM_VERSION = "phase3-recovery-item-v1"
RECOVERY_MANIFEST_VERSION = "phase3-recovery-manifest-v1"
RECOVERY_ENVELOPE_VERSION = "phase3-signed-recovery-manifest-v1"
RECOVERY_TRUST_VERSION = "phase3-recovery-trust-v1"
RECOVERY_QUERY_VERSION = "phase3-recovery-query-v1"
RECOVERY_SIGNATURE_VERSION = "phase3-recovery-signature-v1"
RECOVERY_EVIDENCE_VERSION = "phase3-recovery-evidence-v1"
RECOVERY_SIGNING_PURPOSE = "recovery_manifest"
RECOVERY_SIGNING_DOMAIN = "wiki.recovery.manifest.v1"

HEX40_OR_64 = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})$")


class RecoveryError(RuntimeError):
    """A stable, fail-closed recovery failure."""

    def __init__(self, error_code: str, message: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class RecoveryItemCategory(str, Enum):
    CAS_OBJECT = "cas_object"
    CAS_TOMBSTONE = "cas_tombstone"
    GIT_OBJECT = "git_object"
    GIT_REF = "git_ref"
    GENERATION_MANIFEST = "generation_manifest"
    RELEASE_MANIFEST = "release_manifest"
    EXPORT_MANIFEST = "export_manifest"
    HISTORICAL_KEY_REGISTRY = "historical_key_registry"
    SECRET_SIDECAR = "secret_sidecar"
    CONTROL_PLANE_CHECKPOINT = "control_plane_checkpoint"
    SCHEMA_REGISTRY = "schema_registry"
    KIND_REGISTRY = "kind_registry"
    POLICY_REGISTRY = "policy_registry"


MINIMUM_RECOVERY_CATEGORIES = frozenset(
    {
        RecoveryItemCategory.CAS_OBJECT,
        RecoveryItemCategory.GIT_OBJECT,
        RecoveryItemCategory.GIT_REF,
        RecoveryItemCategory.GENERATION_MANIFEST,
        RecoveryItemCategory.RELEASE_MANIFEST,
        RecoveryItemCategory.HISTORICAL_KEY_REGISTRY,
        RecoveryItemCategory.CONTROL_PLANE_CHECKPOINT,
        RecoveryItemCategory.SCHEMA_REGISTRY,
        RecoveryItemCategory.KIND_REGISTRY,
    }
)
SINGLETON_CATEGORIES = frozenset(
    {
        RecoveryItemCategory.HISTORICAL_KEY_REGISTRY,
        RecoveryItemCategory.CONTROL_PLANE_CHECKPOINT,
        RecoveryItemCategory.SCHEMA_REGISTRY,
        RecoveryItemCategory.KIND_REGISTRY,
        RecoveryItemCategory.POLICY_REGISTRY,
    }
)
MINIMUM_PROJECTIONS = frozenset({"identity", "chronology"})


def _strict_mapping(
    data: Mapping[str, object], allowed: set[str], required: set[str], *, label: str
) -> dict[str, object]:
    unknown = set(data) - allowed
    missing = required - set(data)
    if unknown:
        raise UnknownContractField(f"unknown {label} fields: {sorted(unknown)}")
    if missing:
        raise InvalidContractValue(f"missing {label} fields: {sorted(missing)}")
    return dict(data)


def _require_nonempty(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidContractValue(f"{field} must be a non-empty string")
    return value


def _require_hex64(value: object, field: str) -> str:
    text = _require_nonempty(value, field)
    if not HEX64.fullmatch(text):
        raise InvalidContractValue(f"{field} must be lowercase sha256 hex")
    return text


def _require_timestamp(value: object, field: str) -> str:
    text = _require_nonempty(value, field)
    if not TIMESTAMP.fullmatch(text):
        raise InvalidContractValue(f"{field} must be RFC3339 with seconds and zone")
    return text


def _canonical_nonnegative_integer(value: object, field: str) -> int:
    if not isinstance(value, str) or not re.fullmatch(r"0|[1-9][0-9]*", value):
        raise InvalidContractValue(f"{field} must be a canonical non-negative integer string")
    return int(value)


def _string_tuple(value: object, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or isinstance(value, (str, bytes)):
        raise InvalidContractValue(f"{field} must be an array of strings")
    result = tuple(value)
    if not allow_empty and not result:
        raise InvalidContractValue(f"{field} must not be empty")
    if any(not isinstance(item, str) or not item for item in result):
        raise InvalidContractValue(f"{field} must contain non-empty strings")
    return result


def _sorted_unique(values: Sequence[str], field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    result = tuple(values)
    if not allow_empty and not result:
        raise InvalidContractValue(f"{field} must not be empty")
    if any(not isinstance(item, str) or not item for item in result):
        raise InvalidContractValue(f"{field} must contain non-empty strings")
    if tuple(sorted(set(result))) != result:
        raise InvalidContractValue(f"{field} must be sorted and unique")
    return result


def _validate_relative_path(value: object) -> str:
    path = _require_nonempty(value, "logical_path")
    if "\\" in path or "\x00" in path:
        raise InvalidContractValue("logical_path must be canonical POSIX text")
    parsed = PurePosixPath(path)
    if parsed.is_absolute() or path in {".", ".."} or any(part in {"", ".", ".."} for part in parsed.parts):
        raise InvalidContractValue("logical_path must be a normalized relative POSIX path")
    if parsed.as_posix() != path:
        raise InvalidContractValue("logical_path is not canonical")
    return path


def _digest_mapping(value: Mapping[str, object]) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _strict_json_bytes(payload: bytes, *, label: str) -> dict[str, object]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RecoveryError("registry_invalid", f"{label} is not UTF-8") from exc

    def no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        out: dict[str, object] = {}
        for key, value in pairs:
            if key in out:
                raise RecoveryError("registry_invalid", f"duplicate JSON key in {label}: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(text, object_pairs_hook=no_duplicates)
    except RecoveryError:
        raise
    except Exception as exc:
        raise RecoveryError("registry_invalid", f"invalid JSON in {label}") from exc
    if not isinstance(value, dict):
        raise RecoveryError("registry_invalid", f"{label} must be a JSON object")
    try:
        encoded = canonical_bytes(value)
    except Exception as exc:
        raise RecoveryError("registry_invalid", f"non-canonical value in {label}") from exc
    if encoded != payload:
        raise RecoveryError("registry_invalid", f"{label} is not canonical JSON")
    return value


def _verify_snapshot_digest(value: Mapping[str, object], *, label: str) -> str:
    digest = value.get("snapshot_digest")
    if not isinstance(digest, str) or not HEX64.fullmatch(digest):
        raise RecoveryError("registry_invalid", f"{label} snapshot_digest is invalid")
    body = {key: item for key, item in value.items() if key != "snapshot_digest"}
    if _digest_mapping(body) != digest:
        raise RecoveryError("registry_invalid", f"{label} snapshot digest mismatch")
    return digest


@dataclass(frozen=True)
class RecoveryItem:
    recovery_item_version: str
    item_id: str
    category: str
    logical_path: str
    content_digest: str
    byte_length: str
    encrypted: bool
    encryption_key_id: str | None
    dependencies: tuple[str, ...]

    FIELDS = {
        "recovery_item_version",
        "item_id",
        "category",
        "logical_path",
        "content_digest",
        "byte_length",
        "encrypted",
        "encryption_key_id",
        "dependencies",
    }

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "recovery_item_version": values["recovery_item_version"],
            "category": values["category"],
            "logical_path": values["logical_path"],
            "content_digest": values["content_digest"],
            "byte_length": values["byte_length"],
            "encrypted": values["encrypted"],
            "encryption_key_id": values["encryption_key_id"],
            "dependencies": list(values["dependencies"]),
        }

    def __post_init__(self) -> None:
        if self.recovery_item_version != RECOVERY_ITEM_VERSION:
            raise UnsupportedContractVersion("unsupported recovery item version")
        RecoveryItemCategory(self.category)
        _validate_relative_path(self.logical_path)
        _require_hex64(self.content_digest, "content_digest")
        _canonical_nonnegative_integer(self.byte_length, "byte_length")
        _sorted_unique(self.dependencies, "dependencies", allow_empty=True)
        if self.item_id in self.dependencies:
            raise InvalidContractValue("recovery item cannot depend on itself")
        if self.encrypted:
            _require_nonempty(self.encryption_key_id, "encryption_key_id")
        elif self.encryption_key_id is not None:
            raise InvalidContractValue("unencrypted item cannot name an encryption key")
        if self.category == RecoveryItemCategory.SECRET_SIDECAR.value and not self.encrypted:
            raise InvalidContractValue("secret sidecar must be encrypted")
        if self.item_id != _digest_mapping(self._body(self.to_mapping())):
            raise InvalidContractValue("item_id does not match recovery item")

    @classmethod
    def create(
        cls,
        *,
        category: RecoveryItemCategory | str,
        logical_path: str,
        payload: bytes,
        encrypted: bool = False,
        encryption_key_id: str | None = None,
        dependencies: Sequence[str] = (),
    ) -> "RecoveryItem":
        if not isinstance(payload, bytes):
            raise InvalidContractValue("recovery payload must be bytes")
        values: dict[str, object] = {
            "recovery_item_version": RECOVERY_ITEM_VERSION,
            "category": RecoveryItemCategory(category).value,
            "logical_path": _validate_relative_path(logical_path),
            "content_digest": sha256(payload).hexdigest(),
            "byte_length": str(len(payload)),
            "encrypted": bool(encrypted),
            "encryption_key_id": encryption_key_id,
            "dependencies": tuple(sorted(set(dependencies))),
        }
        return cls(item_id=_digest_mapping(cls._body(values)), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RecoveryItem":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="recovery item")
        values["dependencies"] = _string_tuple(
            values["dependencies"], "dependencies", allow_empty=True
        )
        if not isinstance(values["encrypted"], bool):
            raise InvalidContractValue("encrypted must be boolean")
        if values["encryption_key_id"] is not None and not isinstance(
            values["encryption_key_id"], str
        ):
            raise InvalidContractValue("encryption_key_id must be string or null")
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "recovery_item_version": self.recovery_item_version,
            "item_id": self.item_id,
            "category": self.category,
            "logical_path": self.logical_path,
            "content_digest": self.content_digest,
            "byte_length": self.byte_length,
            "encrypted": self.encrypted,
            "encryption_key_id": self.encryption_key_id,
            "dependencies": list(self.dependencies),
        }


@dataclass(frozen=True)
class RecoverySignatureBinding:
    recovery_signature_version: str
    binding_id: str
    payload_item_id: str
    key_id: str
    purpose: str
    domain: str
    signed_at: str
    signature_b64: str

    FIELDS = {
        "recovery_signature_version",
        "binding_id",
        "payload_item_id",
        "key_id",
        "purpose",
        "domain",
        "signed_at",
        "signature_b64",
    }

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "recovery_signature_version": values["recovery_signature_version"],
            "payload_item_id": values["payload_item_id"],
            "key_id": values["key_id"],
            "purpose": values["purpose"],
            "domain": values["domain"],
            "signed_at": values["signed_at"],
            "signature_b64": values["signature_b64"],
        }

    def __post_init__(self) -> None:
        if self.recovery_signature_version != RECOVERY_SIGNATURE_VERSION:
            raise UnsupportedContractVersion("unsupported recovery signature version")
        _require_hex64(self.payload_item_id, "payload_item_id")
        for field in ("key_id", "purpose", "domain"):
            _require_nonempty(getattr(self, field), field)
        _require_timestamp(self.signed_at, "signed_at")
        try:
            raw = b64decode(self.signature_b64, validate=True)
        except Exception as exc:
            raise InvalidContractValue("signature_b64 is not strict base64") from exc
        if len(raw) != 64:
            raise InvalidContractValue("Ed25519 signature must be 64 bytes")
        if self.binding_id != _digest_mapping(self._body(self.to_mapping())):
            raise InvalidContractValue("binding_id does not match signature binding")

    @classmethod
    def create(
        cls,
        *,
        payload_item_id: str,
        key_id: str,
        purpose: str,
        domain: str,
        signed_at: str,
        signature: bytes,
    ) -> "RecoverySignatureBinding":
        values: dict[str, object] = {
            "recovery_signature_version": RECOVERY_SIGNATURE_VERSION,
            "payload_item_id": payload_item_id,
            "key_id": key_id,
            "purpose": purpose,
            "domain": domain,
            "signed_at": signed_at,
            "signature_b64": b64encode(signature).decode("ascii"),
        }
        return cls(binding_id=_digest_mapping(cls._body(values)), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RecoverySignatureBinding":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="signature binding")
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "recovery_signature_version": self.recovery_signature_version,
            "binding_id": self.binding_id,
            "payload_item_id": self.payload_item_id,
            "key_id": self.key_id,
            "purpose": self.purpose,
            "domain": self.domain,
            "signed_at": self.signed_at,
            "signature_b64": self.signature_b64,
        }


@dataclass(frozen=True)
class RecoveryQuerySpec:
    recovery_query_version: str
    query_id: str
    query_type: str
    as_of_generation_id: str
    parameters: dict[str, JsonValue]
    expected_result_digest: str

    FIELDS = {
        "recovery_query_version",
        "query_id",
        "query_type",
        "as_of_generation_id",
        "parameters",
        "expected_result_digest",
    }

    def __post_init__(self) -> None:
        if self.recovery_query_version != RECOVERY_QUERY_VERSION:
            raise UnsupportedContractVersion("unsupported recovery query version")
        _require_nonempty(self.query_id, "query_id")
        _require_nonempty(self.query_type, "query_type")
        if not HEX64.fullmatch(self.as_of_generation_id):
            raise InvalidContractValue("as_of_generation_id must be sha256 hex")
        if not isinstance(self.parameters, dict):
            raise InvalidContractValue("query parameters must be an object")
        normalized = json.loads(canonical_bytes({"parameters": self.parameters}))["parameters"]
        object.__setattr__(self, "parameters", normalized)
        _require_hex64(self.expected_result_digest, "expected_result_digest")

    @classmethod
    def create(
        cls,
        *,
        query_id: str,
        query_type: str,
        as_of_generation_id: str,
        parameters: Mapping[str, JsonValue],
        expected_result: Mapping[str, JsonValue],
    ) -> "RecoveryQuerySpec":
        digest = sha256(canonical_bytes(dict(expected_result))).hexdigest()
        return cls(
            RECOVERY_QUERY_VERSION,
            query_id,
            query_type,
            as_of_generation_id,
            dict(parameters),
            digest,
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RecoveryQuerySpec":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="recovery query")
        if not isinstance(values["parameters"], Mapping):
            raise InvalidContractValue("query parameters must be an object")
        values["parameters"] = dict(values["parameters"])
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "recovery_query_version": self.recovery_query_version,
            "query_id": self.query_id,
            "query_type": self.query_type,
            "as_of_generation_id": self.as_of_generation_id,
            "parameters": self.parameters,
            "expected_result_digest": self.expected_result_digest,
        }


def recovery_state_root(items: Sequence[RecoveryItem]) -> str:
    leaves = [
        {
            "item_id": item.item_id,
            "category": item.category,
            "logical_path": item.logical_path,
            "content_digest": item.content_digest,
        }
        for item in sorted(items, key=lambda value: value.item_id)
    ]
    return _digest_mapping({"domain": "wiki.recovery.state.v1", "items": leaves})


@dataclass(frozen=True)
class RecoveryManifest:
    recovery_manifest_version: str
    manifest_id: str
    workspace_id: str
    source_generation_id: str
    publication_generation_id: str
    publication_release_commit_oid: str
    state_root: str
    key_registry_item_id: str
    schema_registry_item_id: str
    kind_registry_item_id: str
    control_plane_checkpoint_item_id: str
    required_projection_names: tuple[str, ...]
    items: tuple[RecoveryItem, ...]
    signatures: tuple[RecoverySignatureBinding, ...]
    sample_queries: tuple[RecoveryQuerySpec, ...]

    FIELDS = {
        "recovery_manifest_version",
        "manifest_id",
        "workspace_id",
        "source_generation_id",
        "publication_generation_id",
        "publication_release_commit_oid",
        "state_root",
        "key_registry_item_id",
        "schema_registry_item_id",
        "kind_registry_item_id",
        "control_plane_checkpoint_item_id",
        "required_projection_names",
        "items",
        "signatures",
        "sample_queries",
    }

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "recovery_manifest_version": values["recovery_manifest_version"],
            "workspace_id": values["workspace_id"],
            "source_generation_id": values["source_generation_id"],
            "publication_generation_id": values["publication_generation_id"],
            "publication_release_commit_oid": values["publication_release_commit_oid"],
            "state_root": values["state_root"],
            "key_registry_item_id": values["key_registry_item_id"],
            "schema_registry_item_id": values["schema_registry_item_id"],
            "kind_registry_item_id": values["kind_registry_item_id"],
            "control_plane_checkpoint_item_id": values["control_plane_checkpoint_item_id"],
            "required_projection_names": list(values["required_projection_names"]),
            "items": [item.to_mapping() for item in values["items"]],
            "signatures": [item.to_mapping() for item in values["signatures"]],
            "sample_queries": [item.to_mapping() for item in values["sample_queries"]],
        }

    def __post_init__(self) -> None:
        if self.recovery_manifest_version != RECOVERY_MANIFEST_VERSION:
            raise UnsupportedContractVersion("unsupported recovery manifest version")
        _require_nonempty(self.workspace_id, "workspace_id")
        if not HEX64.fullmatch(self.source_generation_id):
            raise InvalidContractValue("source_generation_id must be sha256 hex")
        if not HEX64.fullmatch(self.publication_generation_id):
            raise InvalidContractValue("publication_generation_id must be sha256 hex")
        if not HEX40_OR_64.fullmatch(self.publication_release_commit_oid):
            raise InvalidContractValue("publication_release_commit_oid must be Git hex oid")
        _require_hex64(self.state_root, "state_root")
        for field in (
            "key_registry_item_id",
            "schema_registry_item_id",
            "kind_registry_item_id",
            "control_plane_checkpoint_item_id",
        ):
            _require_hex64(getattr(self, field), field)
        _sorted_unique(self.required_projection_names, "required_projection_names")
        if not MINIMUM_PROJECTIONS.issubset(set(self.required_projection_names)):
            raise InvalidContractValue("identity and chronology projections are required")
        if tuple(sorted(self.items, key=lambda item: item.item_id)) != self.items:
            raise InvalidContractValue("items must be sorted by item_id")
        if tuple(sorted(self.signatures, key=lambda item: item.binding_id)) != self.signatures:
            raise InvalidContractValue("signatures must be sorted by binding_id")
        if tuple(sorted(self.sample_queries, key=lambda item: item.query_id)) != self.sample_queries:
            raise InvalidContractValue("sample_queries must be sorted by query_id")
        if not self.sample_queries:
            raise InvalidContractValue("at least one strict sample query is required")
        if any(query.as_of_generation_id != self.publication_generation_id for query in self.sample_queries):
            raise InvalidContractValue("sample queries must pin the publication generation")
        self._validate_inventory()
        if recovery_state_root(self.items) != self.state_root:
            raise InvalidContractValue("state_root does not match recovery items")
        if self.manifest_id != _digest_mapping(self._body(self.__dict__)):
            raise InvalidContractValue("manifest_id does not match recovery manifest")

    def _validate_inventory(self) -> None:
        ids = [item.item_id for item in self.items]
        paths = [item.logical_path for item in self.items]
        if len(ids) != len(set(ids)):
            raise InvalidContractValue("duplicate recovery item_id")
        if len(paths) != len(set(paths)):
            raise InvalidContractValue("duplicate recovery logical_path")
        by_id = {item.item_id: item for item in self.items}
        categories = [RecoveryItemCategory(item.category) for item in self.items]
        missing_categories = MINIMUM_RECOVERY_CATEGORIES - set(categories)
        if missing_categories:
            raise InvalidContractValue(
                f"minimum Recovery Set categories missing: {sorted(item.value for item in missing_categories)}"
            )
        for category in SINGLETON_CATEGORIES:
            if sum(item.category == category.value for item in self.items) > 1:
                raise InvalidContractValue(f"multiple singleton recovery items: {category.value}")
        references = {
            self.key_registry_item_id: RecoveryItemCategory.HISTORICAL_KEY_REGISTRY,
            self.schema_registry_item_id: RecoveryItemCategory.SCHEMA_REGISTRY,
            self.kind_registry_item_id: RecoveryItemCategory.KIND_REGISTRY,
            self.control_plane_checkpoint_item_id: RecoveryItemCategory.CONTROL_PLANE_CHECKPOINT,
        }
        for item_id, expected_category in references.items():
            item = by_id.get(item_id)
            if item is None or item.category != expected_category.value:
                raise InvalidContractValue(
                    f"referenced item {item_id} is not {expected_category.value}"
                )
        for item in self.items:
            for dependency in item.dependencies:
                if dependency not in by_id:
                    raise InvalidContractValue(
                        f"recovery item {item.item_id} has missing dependency {dependency}"
                    )
        self._assert_acyclic(by_id)
        binding_ids = [binding.binding_id for binding in self.signatures]
        if len(binding_ids) != len(set(binding_ids)):
            raise InvalidContractValue("duplicate recovery signature binding")
        query_ids = [query.query_id for query in self.sample_queries]
        if len(query_ids) != len(set(query_ids)):
            raise InvalidContractValue("duplicate recovery query_id")
        bindings_by_payload: dict[str, list[RecoverySignatureBinding]] = {}
        for binding in self.signatures:
            if binding.payload_item_id not in by_id:
                raise InvalidContractValue("signature binding references an unknown payload item")
            bindings_by_payload.setdefault(binding.payload_item_id, []).append(binding)
        expected_signature_context = {
            RecoveryItemCategory.GENERATION_MANIFEST.value: ("generation", "wiki.generation.v1"),
            RecoveryItemCategory.RELEASE_MANIFEST.value: ("release", "wiki.release.v1"),
            RecoveryItemCategory.EXPORT_MANIFEST.value: ("export", "wiki.export.v1"),
        }
        for item in self.items:
            expected = expected_signature_context.get(item.category)
            if expected is None:
                continue
            bindings = bindings_by_payload.get(item.item_id, [])
            if not any((binding.purpose, binding.domain) == expected for binding in bindings):
                raise InvalidContractValue(
                    f"signed artifact lacks required purpose/domain binding: {item.logical_path}"
                )

    @staticmethod
    def _assert_acyclic(by_id: Mapping[str, RecoveryItem]) -> None:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(item_id: str) -> None:
            if item_id in visited:
                return
            if item_id in visiting:
                raise InvalidContractValue("recovery item dependency cycle detected")
            visiting.add(item_id)
            for dependency in by_id[item_id].dependencies:
                visit(dependency)
            visiting.remove(item_id)
            visited.add(item_id)

        for item_id in sorted(by_id):
            visit(item_id)

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        source_generation_id: str,
        publication_generation_id: str,
        publication_release_commit_oid: str,
        key_registry_item_id: str,
        schema_registry_item_id: str,
        kind_registry_item_id: str,
        control_plane_checkpoint_item_id: str,
        required_projection_names: Sequence[str],
        items: Sequence[RecoveryItem],
        signatures: Sequence[RecoverySignatureBinding],
        sample_queries: Sequence[RecoveryQuerySpec],
    ) -> "RecoveryManifest":
        sorted_items = tuple(sorted(items, key=lambda item: item.item_id))
        values: dict[str, object] = {
            "recovery_manifest_version": RECOVERY_MANIFEST_VERSION,
            "workspace_id": workspace_id,
            "source_generation_id": source_generation_id,
            "publication_generation_id": publication_generation_id,
            "publication_release_commit_oid": publication_release_commit_oid,
            "state_root": recovery_state_root(sorted_items),
            "key_registry_item_id": key_registry_item_id,
            "schema_registry_item_id": schema_registry_item_id,
            "kind_registry_item_id": kind_registry_item_id,
            "control_plane_checkpoint_item_id": control_plane_checkpoint_item_id,
            "required_projection_names": tuple(sorted(set(required_projection_names))),
            "items": sorted_items,
            "signatures": tuple(sorted(signatures, key=lambda item: item.binding_id)),
            "sample_queries": tuple(sorted(sample_queries, key=lambda item: item.query_id)),
        }
        return cls(manifest_id=_digest_mapping(cls._body(values)), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RecoveryManifest":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="recovery manifest")
        if not isinstance(values["items"], list):
            raise InvalidContractValue("items must be an array")
        if not isinstance(values["signatures"], list):
            raise InvalidContractValue("signatures must be an array")
        if not isinstance(values["sample_queries"], list):
            raise InvalidContractValue("sample_queries must be an array")
        values["items"] = tuple(RecoveryItem.from_mapping(item) for item in values["items"])
        values["signatures"] = tuple(
            RecoverySignatureBinding.from_mapping(item) for item in values["signatures"]
        )
        values["sample_queries"] = tuple(
            RecoveryQuerySpec.from_mapping(item) for item in values["sample_queries"]
        )
        values["required_projection_names"] = _string_tuple(
            values["required_projection_names"], "required_projection_names"
        )
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {"manifest_id": self.manifest_id, **self._body(self.__dict__)}

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


@dataclass(frozen=True)
class RecoveryTrustAnchor:
    recovery_trust_version: str
    anchor_id: str
    workspace_id: str
    recovery_signer_key_id: str
    recovery_signer_public_key_b64: str
    key_registry_snapshot_digest: str
    expected_manifest_id: str

    FIELDS = {
        "recovery_trust_version",
        "anchor_id",
        "workspace_id",
        "recovery_signer_key_id",
        "recovery_signer_public_key_b64",
        "key_registry_snapshot_digest",
        "expected_manifest_id",
    }

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "recovery_trust_version": values["recovery_trust_version"],
            "workspace_id": values["workspace_id"],
            "recovery_signer_key_id": values["recovery_signer_key_id"],
            "recovery_signer_public_key_b64": values["recovery_signer_public_key_b64"],
            "key_registry_snapshot_digest": values["key_registry_snapshot_digest"],
            "expected_manifest_id": values["expected_manifest_id"],
        }

    def __post_init__(self) -> None:
        if self.recovery_trust_version != RECOVERY_TRUST_VERSION:
            raise UnsupportedContractVersion("unsupported recovery trust version")
        _require_nonempty(self.workspace_id, "workspace_id")
        _require_nonempty(self.recovery_signer_key_id, "recovery_signer_key_id")
        try:
            raw = b64decode(self.recovery_signer_public_key_b64, validate=True)
            Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise InvalidContractValue("invalid recovery signer public key") from exc
        _require_hex64(self.key_registry_snapshot_digest, "key_registry_snapshot_digest")
        _require_hex64(self.expected_manifest_id, "expected_manifest_id")
        if self.anchor_id != _digest_mapping(self._body(self.to_mapping())):
            raise InvalidContractValue("anchor_id does not match recovery trust anchor")

    @classmethod
    def create(
        cls,
        *,
        workspace_id: str,
        recovery_signer_key_id: str,
        recovery_signer_public_key: bytes,
        key_registry_snapshot_digest: str,
        expected_manifest_id: str,
    ) -> "RecoveryTrustAnchor":
        values: dict[str, object] = {
            "recovery_trust_version": RECOVERY_TRUST_VERSION,
            "workspace_id": workspace_id,
            "recovery_signer_key_id": recovery_signer_key_id,
            "recovery_signer_public_key_b64": b64encode(recovery_signer_public_key).decode("ascii"),
            "key_registry_snapshot_digest": key_registry_snapshot_digest,
            "expected_manifest_id": expected_manifest_id,
        }
        return cls(anchor_id=_digest_mapping(cls._body(values)), **values)

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "RecoveryTrustAnchor":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="recovery trust")
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {"anchor_id": self.anchor_id, **self._body(self.__dict__)}


@dataclass(frozen=True)
class SignedRecoveryManifest:
    recovery_envelope_version: str
    manifest: RecoveryManifest
    signer_key_id: str
    signed_at: str
    signature_b64: str

    FIELDS = {
        "recovery_envelope_version",
        "manifest",
        "signer_key_id",
        "signed_at",
        "signature_b64",
    }

    def __post_init__(self) -> None:
        if self.recovery_envelope_version != RECOVERY_ENVELOPE_VERSION:
            raise UnsupportedContractVersion("unsupported recovery envelope version")
        _require_nonempty(self.signer_key_id, "signer_key_id")
        _require_timestamp(self.signed_at, "signed_at")
        try:
            raw = b64decode(self.signature_b64, validate=True)
        except Exception as exc:
            raise InvalidContractValue("recovery manifest signature is not strict base64") from exc
        if len(raw) != 64:
            raise InvalidContractValue("recovery manifest signature must be 64 bytes")

    @classmethod
    def sign(
        cls,
        manifest: RecoveryManifest,
        *,
        signer_key_id: str,
        private_key: Ed25519PrivateKey,
        signed_at: str,
    ) -> "SignedRecoveryManifest":
        signature = private_key.sign(
            signature_frame(
                RECOVERY_SIGNING_PURPOSE,
                RECOVERY_SIGNING_DOMAIN,
                manifest.canonical_bytes(),
            )
        )
        return cls(
            RECOVERY_ENVELOPE_VERSION,
            manifest,
            signer_key_id,
            signed_at,
            b64encode(signature).decode("ascii"),
        )

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "SignedRecoveryManifest":
        values = _strict_mapping(data, cls.FIELDS, cls.FIELDS, label="signed recovery manifest")
        if not isinstance(values["manifest"], Mapping):
            raise InvalidContractValue("manifest must be an object")
        values["manifest"] = RecoveryManifest.from_mapping(values["manifest"])
        return cls(**values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "recovery_envelope_version": self.recovery_envelope_version,
            "manifest": self.manifest.to_mapping(),
            "signer_key_id": self.signer_key_id,
            "signed_at": self.signed_at,
            "signature_b64": self.signature_b64,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())

    def verify(self, trust: RecoveryTrustAnchor) -> None:
        if trust.workspace_id != self.manifest.workspace_id:
            raise RecoveryError("trust_anchor_mismatch", "recovery workspace does not match trust anchor")
        if trust.expected_manifest_id != self.manifest.manifest_id:
            raise RecoveryError("trust_anchor_mismatch", "manifest id does not match trust anchor")
        if trust.recovery_signer_key_id != self.signer_key_id:
            raise RecoveryError("trust_anchor_mismatch", "recovery signer id does not match trust anchor")
        try:
            public = Ed25519PublicKey.from_public_bytes(
                b64decode(trust.recovery_signer_public_key_b64, validate=True)
            )
            public.verify(
                b64decode(self.signature_b64, validate=True),
                signature_frame(
                    RECOVERY_SIGNING_PURPOSE,
                    RECOVERY_SIGNING_DOMAIN,
                    self.manifest.canonical_bytes(),
                ),
            )
        except InvalidSignature as exc:
            raise RecoveryError("manifest_signature_invalid", "recovery manifest signature failed") from exc
        except Exception as exc:
            raise RecoveryError("manifest_signature_invalid", "invalid recovery manifest signature") from exc


@dataclass(frozen=True)
class RecoveryTargetStatus:
    state_root: str
    publication_generation_id: str
    publication_release_commit_oid: str
    control_plane_checkpoint_digest: str
    projection_pointers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        _require_hex64(self.state_root, "state_root")
        if not HEX64.fullmatch(self.publication_generation_id):
            raise InvalidContractValue("publication_generation_id must be sha256 hex")
        if not HEX40_OR_64.fullmatch(self.publication_release_commit_oid):
            raise InvalidContractValue("publication_release_commit_oid must be Git hex oid")
        _require_hex64(self.control_plane_checkpoint_digest, "control_plane_checkpoint_digest")
        if tuple(sorted(set(self.projection_pointers))) != self.projection_pointers:
            raise InvalidContractValue("projection_pointers must be sorted and unique")
        if any(not name or not HEX64.fullmatch(generation) for name, generation in self.projection_pointers):
            raise InvalidContractValue("projection pointer entries are invalid")


@dataclass(frozen=True)
class RecoveryEvidence:
    recovery_evidence_version: str
    evidence_id: str
    manifest_id: str
    workspace_id: str
    status: str
    verified_item_count: str
    verified_signature_count: str
    state_root: str
    publication_generation_id: str
    publication_release_commit_oid: str
    projection_pointers: tuple[tuple[str, str], ...]
    query_result_digests: tuple[tuple[str, str], ...]
    completed_at: str

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "recovery_evidence_version": values["recovery_evidence_version"],
            "manifest_id": values["manifest_id"],
            "workspace_id": values["workspace_id"],
            "status": values["status"],
            "verified_item_count": values["verified_item_count"],
            "verified_signature_count": values["verified_signature_count"],
            "state_root": values["state_root"],
            "publication_generation_id": values["publication_generation_id"],
            "publication_release_commit_oid": values["publication_release_commit_oid"],
            "projection_pointers": [
                {"projection_name": name, "generation_id": generation}
                for name, generation in values["projection_pointers"]
            ],
            "query_result_digests": [
                {"query_id": query_id, "result_digest": digest}
                for query_id, digest in values["query_result_digests"]
            ],
            "completed_at": values["completed_at"],
        }

    def __post_init__(self) -> None:
        if self.recovery_evidence_version != RECOVERY_EVIDENCE_VERSION:
            raise UnsupportedContractVersion("unsupported recovery evidence version")
        if self.status not in {"verified", "restored"}:
            raise InvalidContractValue("recovery evidence status is invalid")
        _require_hex64(self.manifest_id, "manifest_id")
        _require_nonempty(self.workspace_id, "workspace_id")
        _canonical_nonnegative_integer(self.verified_item_count, "verified_item_count")
        _canonical_nonnegative_integer(self.verified_signature_count, "verified_signature_count")
        _require_hex64(self.state_root, "state_root")
        if not HEX64.fullmatch(self.publication_generation_id):
            raise InvalidContractValue("publication_generation_id must be sha256 hex")
        if not HEX40_OR_64.fullmatch(self.publication_release_commit_oid):
            raise InvalidContractValue("publication_release_commit_oid must be Git hex oid")
        _require_timestamp(self.completed_at, "completed_at")
        if tuple(sorted(set(self.projection_pointers))) != self.projection_pointers:
            raise InvalidContractValue("projection_pointers must be sorted and unique")
        if tuple(sorted(set(self.query_result_digests))) != self.query_result_digests:
            raise InvalidContractValue("query_result_digests must be sorted and unique")
        if self.evidence_id != _digest_mapping(self._body(self.__dict__)):
            raise InvalidContractValue("evidence_id does not match recovery evidence")

    @classmethod
    def create(
        cls,
        *,
        manifest: RecoveryManifest,
        status: str,
        projection_pointers: Sequence[tuple[str, str]],
        query_result_digests: Sequence[tuple[str, str]],
        completed_at: str,
    ) -> "RecoveryEvidence":
        values: dict[str, object] = {
            "recovery_evidence_version": RECOVERY_EVIDENCE_VERSION,
            "manifest_id": manifest.manifest_id,
            "workspace_id": manifest.workspace_id,
            "status": status,
            "verified_item_count": str(len(manifest.items)),
            "verified_signature_count": str(len(manifest.signatures)),
            "state_root": manifest.state_root,
            "publication_generation_id": manifest.publication_generation_id,
            "publication_release_commit_oid": manifest.publication_release_commit_oid,
            "projection_pointers": tuple(sorted(set(projection_pointers))),
            "query_result_digests": tuple(sorted(set(query_result_digests))),
            "completed_at": completed_at,
        }
        return cls(evidence_id=_digest_mapping(cls._body(values)), **values)

    def to_mapping(self) -> dict[str, object]:
        return {"evidence_id": self.evidence_id, **self._body(self.__dict__)}

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())


class RecoverySource(Protocol):
    def signed_manifest(self, workspace_id: str) -> SignedRecoveryManifest: ...

    def read_item(self, workspace_id: str, item_id: str) -> bytes: ...


class WriteFreezePort(Protocol):
    def acquire(self, workspace_id: str, manifest_id: str) -> str | None: ...

    def release(self, workspace_id: str, token: str) -> None: ...


class RecoveryTarget(Protocol):
    def begin_restore(self, manifest: RecoveryManifest) -> str: ...

    def stage_item(self, session_id: str, item: RecoveryItem, payload: bytes) -> None: ...

    def restore_authoritative(self, session_id: str, manifest: RecoveryManifest) -> str: ...

    def rebuild_materializations(self, session_id: str, manifest: RecoveryManifest) -> None: ...

    def status(self, session_id: str) -> RecoveryTargetStatus: ...

    def strict_query(
        self, session_id: str, query: RecoveryQuerySpec
    ) -> Mapping[str, JsonValue]: ...

    def commit_restore(self, session_id: str, manifest_id: str) -> None: ...

    def abort_restore(self, session_id: str) -> None: ...


@dataclass(frozen=True)
class _VerifiedRecoverySet:
    signed: SignedRecoveryManifest
    payloads: dict[str, bytes]
    key_registry: HistoricalKeyRegistry
    query_expected_digests: tuple[tuple[str, str], ...]


class RecoveryCoordinator:
    def __init__(
        self,
        source: RecoverySource,
        trust_anchor: RecoveryTrustAnchor,
        *,
        target: RecoveryTarget | None = None,
        freeze: WriteFreezePort | None = None,
        completed_at: str,
    ) -> None:
        self.source = source
        self.trust_anchor = trust_anchor
        self.target = target
        self.freeze = freeze
        self.completed_at = _require_timestamp(completed_at, "completed_at")

    def dry_run(self, workspace_id: str) -> RecoveryEvidence:
        verified = self._verify_bundle(workspace_id)
        manifest = verified.signed.manifest
        return RecoveryEvidence.create(
            manifest=manifest,
            status="verified",
            projection_pointers=[
                (name, manifest.publication_generation_id)
                for name in manifest.required_projection_names
            ],
            query_result_digests=verified.query_expected_digests,
            completed_at=self.completed_at,
        )

    def restore(self, workspace_id: str) -> RecoveryEvidence:
        if self.target is None or self.freeze is None:
            raise RecoveryError("recovery_adapter_missing", "restore target and write freeze are required")
        token: str | None = None
        session_id: str | None = None
        restore_succeeded = False
        try:
            preview = self.source.signed_manifest(workspace_id)
            manifest_id = preview.manifest.manifest_id
            token = self.freeze.acquire(workspace_id, manifest_id)
            if token is None:
                raise RecoveryError("write_freeze_unavailable", "could not acquire recovery write freeze")
            verified = self._verify_bundle(workspace_id, expected_signed=preview)
            manifest = verified.signed.manifest
            session_id = self.target.begin_restore(manifest)
            for item in manifest.items:
                self.target.stage_item(session_id, item, verified.payloads[item.item_id])
            restored_root = self.target.restore_authoritative(session_id, manifest)
            if restored_root != manifest.state_root:
                raise RecoveryError("state_root_mismatch", "restored authoritative state root mismatch")
            self.target.rebuild_materializations(session_id, manifest)
            status = self.target.status(session_id)
            self._verify_status(manifest, status, verified.payloads)
            query_digests: list[tuple[str, str]] = []
            for query in manifest.sample_queries:
                try:
                    result = self.target.strict_query(session_id, query)
                    if not isinstance(result, Mapping):
                        raise TypeError("strict query result must be a mapping")
                    digest = sha256(canonical_bytes(dict(result))).hexdigest()
                except Exception as exc:
                    raise RecoveryError(
                        "query_verification_failed",
                        f"strict sample query could not be verified: {query.query_id}",
                    ) from exc
                if digest != query.expected_result_digest:
                    raise RecoveryError(
                        "query_verification_failed", f"strict sample query failed: {query.query_id}"
                    )
                query_digests.append((query.query_id, digest))
            self.target.commit_restore(session_id, manifest.manifest_id)
            restore_succeeded = True
            return RecoveryEvidence.create(
                manifest=manifest,
                status="restored",
                projection_pointers=status.projection_pointers,
                query_result_digests=query_digests,
                completed_at=self.completed_at,
            )
        except RecoveryError:
            if session_id is not None:
                self._abort_safely(session_id)
            raise
        except Exception as exc:
            if session_id is not None:
                self._abort_safely(session_id)
            raise RecoveryError("restore_failed", "recovery adapter failed") from exc
        finally:
            if token is not None:
                try:
                    self.freeze.release(workspace_id, token)
                except Exception as exc:
                    if restore_succeeded:
                        raise RecoveryError(
                            "write_freeze_release_failed", "recovery write freeze release failed"
                        ) from exc

    def _abort_safely(self, session_id: str) -> None:
        assert self.target is not None
        try:
            self.target.abort_restore(session_id)
        except Exception:
            pass

    def _verify_bundle(
        self,
        workspace_id: str,
        *,
        expected_signed: SignedRecoveryManifest | None = None,
    ) -> _VerifiedRecoverySet:
        try:
            signed = self.source.signed_manifest(workspace_id)
        except Exception as exc:
            raise RecoveryError("manifest_unavailable", "signed recovery manifest is unavailable") from exc
        if expected_signed is not None and signed.canonical_bytes() != expected_signed.canonical_bytes():
            raise RecoveryError("manifest_changed", "recovery manifest changed after write freeze")
        signed.verify(self.trust_anchor)
        manifest = signed.manifest
        if manifest.workspace_id != workspace_id:
            raise RecoveryError("workspace_mismatch", "recovery manifest workspace mismatch")

        payloads: dict[str, bytes] = {}
        for item in manifest.items:
            try:
                payload = self.source.read_item(workspace_id, item.item_id)
            except Exception as exc:
                raise RecoveryError("missing_item", f"missing recovery item: {item.logical_path}") from exc
            if not isinstance(payload, (bytes, bytearray, memoryview)):
                raise RecoveryError("invalid_item", f"recovery item is not bytes: {item.logical_path}")
            frozen = bytes(payload)
            if len(frozen) != _canonical_nonnegative_integer(item.byte_length, "byte_length"):
                raise RecoveryError("item_length_mismatch", f"item length mismatch: {item.logical_path}")
            if sha256(frozen).hexdigest() != item.content_digest:
                raise RecoveryError("item_digest_mismatch", f"item digest mismatch: {item.logical_path}")
            payloads[item.item_id] = frozen

        key_snapshot_payload = payloads[manifest.key_registry_item_id]
        key_registry, key_snapshot_digest = self._load_key_registry(key_snapshot_payload)
        if key_snapshot_digest != self.trust_anchor.key_registry_snapshot_digest:
            raise RecoveryError("trust_anchor_mismatch", "historical key registry digest mismatch")
        self._verify_registry_snapshot(
            payloads[manifest.schema_registry_item_id],
            label="schema registry",
            required_keys={
                "registry_snapshot_version", "schemas", "write_versions", "migrations", "snapshot_digest"
            },
        )
        self._verify_registry_snapshot(
            payloads[manifest.kind_registry_item_id],
            label="kind registry",
            required_keys={"registry_snapshot_version", "kinds", "snapshot_digest"},
        )
        for item in manifest.items:
            if item.category == RecoveryItemCategory.POLICY_REGISTRY.value:
                self._verify_registry_snapshot(
                    payloads[item.item_id], label="policy registry", required_keys=None
                )

        for binding in manifest.signatures:
            payload = payloads[binding.payload_item_id]
            signature = b64decode(binding.signature_b64, validate=True)
            if not key_registry.verify(
                key_id=binding.key_id,
                purpose=binding.purpose,
                domain=binding.domain,
                payload=payload,
                signature=signature,
                signed_at=binding.signed_at,
            ):
                raise RecoveryError(
                    "artifact_signature_invalid",
                    f"artifact signature verification failed: {binding.binding_id}",
                )

        expected = tuple(
            sorted((query.query_id, query.expected_result_digest) for query in manifest.sample_queries)
        )
        return _VerifiedRecoverySet(signed, payloads, key_registry, expected)

    @staticmethod
    def _verify_registry_snapshot(
        payload: bytes, *, label: str, required_keys: set[str] | None
    ) -> tuple[dict[str, object], str]:
        value = _strict_json_bytes(payload, label=label)
        if required_keys is not None and set(value) != required_keys:
            raise RecoveryError("registry_invalid", f"{label} keys mismatch")
        if value.get("registry_snapshot_version") != "phase3-registry-snapshot-v1":
            raise RecoveryError("registry_invalid", f"unsupported {label} snapshot version")
        digest = _verify_snapshot_digest(value, label=label)
        return value, digest

    @classmethod
    def _load_key_registry(cls, payload: bytes) -> tuple[HistoricalKeyRegistry, str]:
        value, digest = cls._verify_registry_snapshot(
            payload,
            label="historical key registry",
            required_keys={"registry_snapshot_version", "keys", "active", "snapshot_digest"},
        )
        keys = value.get("keys")
        active = value.get("active")
        if not isinstance(keys, list) or not isinstance(active, list):
            raise RecoveryError("registry_invalid", "historical key registry arrays are invalid")
        registry = HistoricalKeyRegistry()
        try:
            records: dict[str, HistoricalPublicKey] = {}
            for raw in keys:
                if not isinstance(raw, Mapping):
                    raise RecoveryError("registry_invalid", "historical key record is invalid")
                expected_fields = {
                    "key_id", "algorithm", "public_key_b64", "purposes", "domains",
                    "valid_from", "valid_until", "predecessor_key_id", "record_id",
                }
                if set(raw) != expected_fields:
                    raise RecoveryError("registry_invalid", "historical key record keys mismatch")
                record = HistoricalPublicKey(
                    key_id=raw["key_id"],
                    algorithm=raw["algorithm"],
                    public_key_b64=raw["public_key_b64"],
                    purposes=_string_tuple(raw["purposes"], "purposes"),
                    domains=_string_tuple(raw["domains"], "domains"),
                    valid_from=raw["valid_from"],
                    valid_until=raw["valid_until"],
                    predecessor_key_id=raw["predecessor_key_id"],
                    record_id=raw["record_id"],
                )
                if record.key_id in records:
                    raise RecoveryError("registry_invalid", "duplicate historical key id")
                records[record.key_id] = record
            pending = dict(records)
            while pending:
                progressed = False
                for key_id, record in list(pending.items()):
                    if record.predecessor_key_id is None or record.predecessor_key_id not in pending:
                        registry.register(record)
                        del pending[key_id]
                        progressed = True
                if not progressed:
                    raise RecoveryError("registry_invalid", "historical key predecessor cycle")
            seen_active: set[tuple[str, str]] = set()
            for entry in active:
                if not isinstance(entry, Mapping) or set(entry) != {"purpose", "domain", "key_id"}:
                    raise RecoveryError("registry_invalid", "active key entry is invalid")
                active_key = entry["purpose"], entry["domain"]
                if active_key in seen_active:
                    raise RecoveryError("registry_invalid", "duplicate active key binding")
                seen_active.add(active_key)
                record = registry.record(entry["key_id"])
                if entry["purpose"] not in record.purposes or entry["domain"] not in record.domains:
                    raise RecoveryError("registry_invalid", "active key usage is not allowed")
        except RecoveryError:
            raise
        except Exception as exc:
            raise RecoveryError("registry_invalid", "historical key registry is invalid") from exc
        return registry, digest

    @staticmethod
    def _verify_status(
        manifest: RecoveryManifest,
        status: RecoveryTargetStatus,
        payloads: Mapping[str, bytes],
    ) -> None:
        if status.state_root != manifest.state_root:
            raise RecoveryError("state_root_mismatch", "target status state root mismatch")
        if status.publication_generation_id != manifest.publication_generation_id:
            raise RecoveryError("publication_pointer_mismatch", "publication generation pointer mismatch")
        if status.publication_release_commit_oid != manifest.publication_release_commit_oid:
            raise RecoveryError("publication_pointer_mismatch", "publication release pointer mismatch")
        checkpoint_digest = sha256(payloads[manifest.control_plane_checkpoint_item_id]).hexdigest()
        if status.control_plane_checkpoint_digest != checkpoint_digest:
            raise RecoveryError("checkpoint_mismatch", "control-plane checkpoint digest mismatch")
        pointers = dict(status.projection_pointers)
        for name in manifest.required_projection_names:
            if pointers.get(name) != manifest.publication_generation_id:
                raise RecoveryError(
                    "projection_pointer_mismatch", f"required projection pointer mismatch: {name}"
                )
