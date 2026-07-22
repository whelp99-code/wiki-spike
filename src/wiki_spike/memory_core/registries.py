"""Versioned schema, memory-kind, and historical public-key registries.

The registries are storage-independent Core contracts:
- schema reads may upcast old artifacts, while writes always use the selected latest version;
- kinds must be explicitly registered and bound to a writable schema family/version;
- signing keys are purpose/domain constrained, and rotation never deletes historical public keys.
"""
from __future__ import annotations

from base64 import b64decode, b64encode
from dataclasses import dataclass, replace
from hashlib import sha256
import json
import re
from typing import Callable, Mapping, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import JsonValue, canonical_bytes
from .errors import InvalidContractValue, UnknownContractField, UnsupportedContractVersion

REGISTRY_SNAPSHOT_VERSION = "phase3-registry-snapshot-v1"
SCHEMA_ARTIFACT_VERSION = "phase3-schema-artifact-v1"
KEY_ALGORITHM = "ed25519"


class RegistryError(ValueError):
    error_code = "registry_error"


class UnknownSchema(RegistryError):
    error_code = "unknown_schema"


class UnsupportedSchemaVersion(RegistryError):
    error_code = "unsupported_schema_version"


class SchemaValidationError(RegistryError):
    error_code = "schema_validation_failed"


class MigrationPathError(RegistryError):
    error_code = "migration_path_invalid"


class UnknownKind(RegistryError):
    error_code = "unknown_kind"


class KindRegistrationError(RegistryError):
    error_code = "kind_registration_failed"


class UnknownSigningKey(RegistryError):
    error_code = "unknown_signing_key"


class KeyUsageDenied(RegistryError):
    error_code = "key_usage_denied"


def _positive_version(value: str, field: str = "version") -> int:
    if not isinstance(value, str) or not re.fullmatch(r"[1-9][0-9]*", value):
        raise InvalidContractValue(f"{field} must be a canonical positive integer string")
    return int(value)


def _digest(value: Mapping[str, object]) -> str:
    return sha256(canonical_bytes(value)).hexdigest()


def _normalize_payload(payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    if not isinstance(payload, Mapping):
        raise SchemaValidationError("schema payload must be an object")
    return json.loads(canonical_bytes({"payload": dict(payload)}))["payload"]


@dataclass(frozen=True)
class VersionedArtifact:
    artifact_schema_version: str
    schema_family: str
    schema_version: str
    payload: dict[str, JsonValue]

    FIELDS = {"artifact_schema_version", "schema_family", "schema_version", "payload"}

    def __post_init__(self) -> None:
        if self.artifact_schema_version != SCHEMA_ARTIFACT_VERSION:
            raise UnsupportedContractVersion("unsupported artifact envelope version")
        if not self.schema_family:
            raise InvalidContractValue("schema_family is required")
        _positive_version(self.schema_version, "schema_version")
        object.__setattr__(self, "payload", _normalize_payload(self.payload))

    @classmethod
    def create(cls, schema_family: str, schema_version: str, payload: Mapping[str, JsonValue]):
        return cls(SCHEMA_ARTIFACT_VERSION, schema_family, schema_version, dict(payload))

    @classmethod
    def from_mapping(cls, data: Mapping[str, object]) -> "VersionedArtifact":
        unknown = set(data) - cls.FIELDS
        missing = cls.FIELDS - set(data)
        if unknown:
            raise UnknownContractField(f"unknown artifact fields: {sorted(unknown)}")
        if missing:
            raise InvalidContractValue(f"missing artifact fields: {sorted(missing)}")
        if not isinstance(data["payload"], Mapping):
            raise InvalidContractValue("payload must be an object")
        return cls(
            data["artifact_schema_version"],
            data["schema_family"],
            data["schema_version"],
            dict(data["payload"]),
        )

    def to_mapping(self) -> dict[str, object]:
        return {
            "artifact_schema_version": self.artifact_schema_version,
            "schema_family": self.schema_family,
            "schema_version": self.schema_version,
            "payload": self.payload,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_bytes(self.to_mapping())

    @property
    def artifact_digest(self) -> str:
        return sha256(self.canonical_bytes()).hexdigest()


@dataclass(frozen=True)
class SchemaDefinition:
    schema_family: str
    schema_version: str
    schema_digest: str
    readable: bool
    writable: bool
    canonical_fixture_digest: str

    def __post_init__(self) -> None:
        if not self.schema_family:
            raise InvalidContractValue("schema_family is required")
        _positive_version(self.schema_version, "schema_version")
        for field in ("schema_digest", "canonical_fixture_digest"):
            value = getattr(self, field)
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
                raise InvalidContractValue(f"{field} must be a sha256 hex digest")
        if not self.readable:
            raise InvalidContractValue("registered schema versions must remain readable")

    def to_mapping(self) -> dict[str, object]:
        return {
            "schema_family": self.schema_family,
            "schema_version": self.schema_version,
            "schema_digest": self.schema_digest,
            "readable": self.readable,
            "writable": self.writable,
            "canonical_fixture_digest": self.canonical_fixture_digest,
        }


SchemaValidator = Callable[[Mapping[str, JsonValue]], Mapping[str, JsonValue]]
SchemaMigration = Callable[[Mapping[str, JsonValue]], Mapping[str, JsonValue]]


class SchemaRegistry:
    def __init__(self) -> None:
        self._definitions: dict[tuple[str, str], SchemaDefinition] = {}
        self._validators: dict[tuple[str, str], SchemaValidator] = {}
        self._write_versions: dict[str, str] = {}
        self._migrations: dict[tuple[str, str], tuple[str, SchemaMigration]] = {}

    def register(
        self,
        definition: SchemaDefinition,
        validator: SchemaValidator,
        *,
        fixture: VersionedArtifact,
    ) -> None:
        key = definition.schema_family, definition.schema_version
        if fixture.schema_family != definition.schema_family or fixture.schema_version != definition.schema_version:
            raise SchemaValidationError("fixture family/version does not match schema definition")
        if fixture.artifact_digest != definition.canonical_fixture_digest:
            raise SchemaValidationError("canonical fixture digest mismatch")
        try:
            validated = _normalize_payload(validator(fixture.payload))
        except Exception as exc:
            raise SchemaValidationError("canonical fixture failed schema validation") from exc
        if validated != fixture.payload:
            raise SchemaValidationError("schema validator changed canonical fixture")
        existing = self._definitions.get(key)
        if existing is not None and existing != definition:
            raise SchemaValidationError("schema family/version already registered differently")
        self._definitions[key] = definition
        self._validators[key] = validator
        if definition.writable:
            self.set_write_version(definition.schema_family, definition.schema_version)

    def set_write_version(self, schema_family: str, schema_version: str) -> None:
        definition = self._definitions.get((schema_family, schema_version))
        if definition is None:
            raise UnknownSchema(f"schema is not registered: {schema_family}@{schema_version}")
        if not definition.writable:
            raise SchemaValidationError("schema version is not writable")
        current = self._write_versions.get(schema_family)
        if current is not None and _positive_version(schema_version) < _positive_version(current):
            raise SchemaValidationError("write version cannot move backwards")
        self._write_versions[schema_family] = schema_version

    def register_migration(
        self,
        schema_family: str,
        from_version: str,
        to_version: str,
        migration: SchemaMigration,
    ) -> None:
        _positive_version(from_version, "from_version")
        _positive_version(to_version, "to_version")
        if _positive_version(to_version) <= _positive_version(from_version):
            raise MigrationPathError("migration must move to a newer version")
        if (schema_family, from_version) not in self._definitions:
            raise UnknownSchema(f"source schema is not registered: {schema_family}@{from_version}")
        if (schema_family, to_version) not in self._definitions:
            raise UnknownSchema(f"target schema is not registered: {schema_family}@{to_version}")
        key = schema_family, from_version
        existing = self._migrations.get(key)
        if existing is not None and existing[0] != to_version:
            raise MigrationPathError("source version already has a different migration target")
        self._migrations[key] = to_version, migration

    def definition(self, schema_family: str, schema_version: str) -> SchemaDefinition:
        try:
            return self._definitions[(schema_family, schema_version)]
        except KeyError as exc:
            if not any(family == schema_family for family, _ in self._definitions):
                raise UnknownSchema(schema_family) from exc
            raise UnsupportedSchemaVersion(f"{schema_family}@{schema_version}") from exc

    def current_write_version(self, schema_family: str) -> str:
        try:
            return self._write_versions[schema_family]
        except KeyError as exc:
            raise UnknownSchema(f"no writable schema for family: {schema_family}") from exc

    def validate(self, artifact: VersionedArtifact) -> VersionedArtifact:
        definition = self.definition(artifact.schema_family, artifact.schema_version)
        if not definition.readable:
            raise UnsupportedSchemaVersion(
                f"schema is not readable: {artifact.schema_family}@{artifact.schema_version}"
            )
        validator = self._validators[(artifact.schema_family, artifact.schema_version)]
        try:
            payload = _normalize_payload(validator(artifact.payload))
        except Exception as exc:
            raise SchemaValidationError(
                f"payload failed {artifact.schema_family}@{artifact.schema_version}"
            ) from exc
        return VersionedArtifact.create(artifact.schema_family, artifact.schema_version, payload)

    def read_latest(self, artifact: VersionedArtifact) -> VersionedArtifact:
        current = self.validate(artifact)
        target_version = self.current_write_version(current.schema_family)
        visited: set[str] = set()
        while current.schema_version != target_version:
            if current.schema_version in visited:
                raise MigrationPathError("migration cycle detected")
            visited.add(current.schema_version)
            migration_entry = self._migrations.get((current.schema_family, current.schema_version))
            if migration_entry is None:
                raise MigrationPathError(
                    f"no migration from {current.schema_family}@{current.schema_version}"
                )
            next_version, migration = migration_entry
            try:
                payload = _normalize_payload(migration(current.payload))
            except Exception as exc:
                raise MigrationPathError(
                    f"migration failed: {current.schema_family}@{current.schema_version}"
                ) from exc
            current = self.validate(
                VersionedArtifact.create(current.schema_family, next_version, payload)
            )
            if _positive_version(current.schema_version) > _positive_version(target_version):
                raise MigrationPathError("migration overshot current write version")
        return current

    def write(self, schema_family: str, payload: Mapping[str, JsonValue]) -> VersionedArtifact:
        version = self.current_write_version(schema_family)
        return self.validate(VersionedArtifact.create(schema_family, version, payload))

    def snapshot(self) -> dict[str, object]:
        definitions = [
            definition.to_mapping()
            for _, definition in sorted(self._definitions.items())
        ]
        migrations = [
            {"schema_family": family, "from_version": version, "to_version": target}
            for (family, version), (target, _) in sorted(self._migrations.items())
        ]
        body = {
            "registry_snapshot_version": REGISTRY_SNAPSHOT_VERSION,
            "schemas": definitions,
            "write_versions": dict(sorted(self._write_versions.items())),
            "migrations": migrations,
        }
        return {**body, "snapshot_digest": _digest(body)}


BUILTIN_KINDS = frozenset({"fact", "decision", "note", "idea", "task", "event", "source_record"})


@dataclass(frozen=True)
class KindDefinition:
    kind: str
    schema_family: str
    schema_version: str
    lifecycle_states: tuple[str, ...]
    built_in: bool
    creatable: bool
    definition_id: str

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "kind": values["kind"],
            "schema_family": values["schema_family"],
            "schema_version": values["schema_version"],
            "lifecycle_states": list(values["lifecycle_states"]),
            "built_in": values["built_in"],
            "creatable": values["creatable"],
        }

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*", self.kind):
            raise KindRegistrationError("invalid kind name")
        if self.built_in != (self.kind in BUILTIN_KINDS):
            raise KindRegistrationError("built_in flag does not match reserved kind set")
        if not self.built_in and "." not in self.kind:
            raise KindRegistrationError("extension kinds require a namespace")
        _positive_version(self.schema_version, "schema_version")
        if not self.schema_family:
            raise KindRegistrationError("schema_family is required")
        if not self.lifecycle_states or tuple(sorted(set(self.lifecycle_states))) != self.lifecycle_states:
            raise KindRegistrationError("lifecycle_states must be sorted, unique, and non-empty")
        if self.definition_id != _digest(self._body(self.to_mapping())):
            raise KindRegistrationError("definition_id does not match kind definition")

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        schema_family: str,
        schema_version: str,
        lifecycle_states: Sequence[str],
        creatable: bool = True,
    ) -> "KindDefinition":
        states = tuple(sorted(set(lifecycle_states)))
        values = {
            "kind": kind,
            "schema_family": schema_family,
            "schema_version": schema_version,
            "lifecycle_states": states,
            "built_in": kind in BUILTIN_KINDS,
            "creatable": creatable,
        }
        return cls(definition_id=_digest(cls._body(values)), **values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "schema_family": self.schema_family,
            "schema_version": self.schema_version,
            "lifecycle_states": list(self.lifecycle_states),
            "built_in": self.built_in,
            "creatable": self.creatable,
            "definition_id": self.definition_id,
        }


class KindRegistry:
    def __init__(self, schemas: SchemaRegistry) -> None:
        self.schemas = schemas
        self._definitions: dict[str, KindDefinition] = {}

    def register(self, definition: KindDefinition) -> None:
        schema = self.schemas.definition(definition.schema_family, definition.schema_version)
        if not schema.readable:
            raise KindRegistrationError("kind schema must be readable")
        if definition.creatable and self.schemas.current_write_version(definition.schema_family) != definition.schema_version:
            raise KindRegistrationError("creatable kind must target the current write schema")
        existing = self._definitions.get(definition.kind)
        if existing is not None and existing != definition:
            raise KindRegistrationError("kind is already registered differently")
        self._definitions[definition.kind] = definition

    def resolve(self, kind: str) -> KindDefinition:
        try:
            return self._definitions[kind]
        except KeyError as exc:
            raise UnknownKind(kind) from exc

    def assert_creatable(self, kind: str) -> KindDefinition:
        definition = self.resolve(kind)
        if not definition.creatable:
            raise KindRegistrationError("kind is retired and cannot be created")
        return definition

    def retire(self, kind: str) -> KindDefinition:
        definition = self.resolve(kind)
        retired = KindDefinition.create(
            kind=definition.kind,
            schema_family=definition.schema_family,
            schema_version=definition.schema_version,
            lifecycle_states=definition.lifecycle_states,
            creatable=False,
        )
        self._definitions[kind] = retired
        return retired

    def validate_artifact(self, kind: str, artifact: VersionedArtifact) -> VersionedArtifact:
        definition = self.resolve(kind)
        if artifact.schema_family != definition.schema_family:
            raise KindRegistrationError("artifact schema family does not match kind")
        return self.schemas.read_latest(artifact)

    def snapshot(self) -> dict[str, object]:
        body = {
            "registry_snapshot_version": REGISTRY_SNAPSHOT_VERSION,
            "kinds": [item.to_mapping() for _, item in sorted(self._definitions.items())],
        }
        return {**body, "snapshot_digest": _digest(body)}


@dataclass(frozen=True)
class HistoricalPublicKey:
    key_id: str
    algorithm: str
    public_key_b64: str
    purposes: tuple[str, ...]
    domains: tuple[str, ...]
    valid_from: str
    valid_until: str | None
    predecessor_key_id: str | None
    record_id: str

    @staticmethod
    def _body(values: Mapping[str, object]) -> dict[str, object]:
        return {
            "key_id": values["key_id"],
            "algorithm": values["algorithm"],
            "public_key_b64": values["public_key_b64"],
            "purposes": list(values["purposes"]),
            "domains": list(values["domains"]),
            "valid_from": values["valid_from"],
            "valid_until": values["valid_until"],
            "predecessor_key_id": values["predecessor_key_id"],
        }

    def __post_init__(self) -> None:
        if not self.key_id or self.algorithm != KEY_ALGORITHM:
            raise InvalidContractValue("key_id and ed25519 algorithm are required")
        try:
            raw = b64decode(self.public_key_b64, validate=True)
            Ed25519PublicKey.from_public_bytes(raw)
        except Exception as exc:
            raise InvalidContractValue("invalid Ed25519 public key") from exc
        for field in ("purposes", "domains"):
            values = getattr(self, field)
            if not values or tuple(sorted(set(values))) != values:
                raise InvalidContractValue(f"{field} must be sorted, unique, and non-empty")
        if not self.valid_from:
            raise InvalidContractValue("valid_from is required")
        if self.valid_until is not None and self.valid_until <= self.valid_from:
            raise InvalidContractValue("valid_until must be after valid_from")
        if self.record_id != _digest(self._body(self.to_mapping())):
            raise InvalidContractValue("record_id does not match key record")

    @classmethod
    def create(
        cls,
        *,
        key_id: str,
        public_key_bytes: bytes,
        purposes: Sequence[str],
        domains: Sequence[str],
        valid_from: str,
        valid_until: str | None = None,
        predecessor_key_id: str | None = None,
    ) -> "HistoricalPublicKey":
        values = {
            "key_id": key_id,
            "algorithm": KEY_ALGORITHM,
            "public_key_b64": b64encode(public_key_bytes).decode("ascii"),
            "purposes": tuple(sorted(set(purposes))),
            "domains": tuple(sorted(set(domains))),
            "valid_from": valid_from,
            "valid_until": valid_until,
            "predecessor_key_id": predecessor_key_id,
        }
        return cls(record_id=_digest(cls._body(values)), **values)

    def to_mapping(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_b64": self.public_key_b64,
            "purposes": list(self.purposes),
            "domains": list(self.domains),
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "predecessor_key_id": self.predecessor_key_id,
            "record_id": self.record_id,
        }


def signature_frame(purpose: str, domain: str, payload: bytes) -> bytes:
    if not purpose or not domain or not isinstance(payload, bytes):
        raise InvalidContractValue("purpose, domain, and bytes payload are required")
    return purpose.encode("utf-8") + b"\x00" + domain.encode("utf-8") + b"\x00" + payload


class HistoricalKeyRegistry:
    def __init__(self) -> None:
        self._records: dict[str, HistoricalPublicKey] = {}
        self._active: dict[tuple[str, str], str] = {}

    def register(self, record: HistoricalPublicKey) -> None:
        if record.predecessor_key_id is not None and record.predecessor_key_id not in self._records:
            raise UnknownSigningKey(record.predecessor_key_id)
        existing = self._records.get(record.key_id)
        if existing is not None and existing != record:
            raise InvalidContractValue("key_id is already registered differently")
        self._records[record.key_id] = record

    def record(self, key_id: str) -> HistoricalPublicKey:
        try:
            return self._records[key_id]
        except KeyError as exc:
            raise UnknownSigningKey(key_id) from exc

    def activate(self, key_id: str, purpose: str, domain: str, *, at: str) -> None:
        record = self.record(key_id)
        self._assert_usage(record, purpose, domain, at)
        self._active[(purpose, domain)] = key_id

    def active_key_id(self, purpose: str, domain: str) -> str:
        try:
            return self._active[(purpose, domain)]
        except KeyError as exc:
            raise UnknownSigningKey(f"no active key for {purpose}/{domain}") from exc

    @staticmethod
    def _assert_usage(record: HistoricalPublicKey, purpose: str, domain: str, at: str) -> None:
        if purpose not in record.purposes or domain not in record.domains:
            raise KeyUsageDenied(f"key {record.key_id} is not allowed for {purpose}/{domain}")
        if at < record.valid_from or (record.valid_until is not None and at >= record.valid_until):
            raise KeyUsageDenied(f"key {record.key_id} was not valid at {at}")

    def verify(
        self,
        *,
        key_id: str,
        purpose: str,
        domain: str,
        payload: bytes,
        signature: bytes,
        signed_at: str,
    ) -> bool:
        try:
            record = self.record(key_id)
            self._assert_usage(record, purpose, domain, signed_at)
            public_key = Ed25519PublicKey.from_public_bytes(b64decode(record.public_key_b64))
            public_key.verify(signature, signature_frame(purpose, domain, payload))
            return True
        except (RegistryError, InvalidSignature, ValueError):
            return False

    def snapshot(self) -> dict[str, object]:
        body = {
            "registry_snapshot_version": REGISTRY_SNAPSHOT_VERSION,
            "keys": [item.to_mapping() for _, item in sorted(self._records.items())],
            "active": [
                {"purpose": purpose, "domain": domain, "key_id": key_id}
                for (purpose, domain), key_id in sorted(self._active.items())
            ],
        }
        return {**body, "snapshot_digest": _digest(body)}
