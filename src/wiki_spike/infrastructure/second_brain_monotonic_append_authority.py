"""Producer/verifier for signed shadow artifacts and the retained monotonic authority."""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from secrets import token_hex
from typing import Any, Final, TypeAlias

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.infrastructure.second_brain_authority_factory import InstalledArtifactIdentity, TrustedImmutableInputRegistry
from wiki_spike.memory_core.second_brain_gate_envelope import digest_fields, signing_message
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

BUNDLE_VERSION: Final = "second-brain-shadow-executor-bundle/v1"
ROOT_VERSION: Final = "second-brain-shadow-measurement-root/v1"
CONFIG_VERSION: Final = "second-brain-shadow-run-config/v1"
AUTHORITY_DOMAIN: Final = "second-brain-native-shadow-authority-v1"
STATE_SCHEMA: Final = "second-brain-deployment-monotonic-authority-state-v1"
RECEIPT_SCHEMA: Final = "second-brain-deployment-live-operation-receipt/v1"
EVIDENCE_SCHEMA: Final = "second-brain-deployment-authority-evidence-v1"
_HEX: Final = frozenset("0123456789abcdef")
_BUNDLE_BODY: Final = ("version", "roster_artifact_sha256", "authority_cli_artifact_sha256", "lockfile_sha256", "cohort_receipt_sha256")
_BUNDLE_FIELDS: Final = (*_BUNDLE_BODY, "bundle_sha256", "signer_ref", "key_id", "signature")
_ROOT_FIELDS: Final = ("version", "cohort_receipt_sha256", "shadow_executor_bundle_sha256", "shadow_run_config_payload_sha256", "initial_checkpoint_sha256", "resolved_scope_sha256", "contract_sha256", "issued_at", "signer_ref", "key_id", "signature")
_CONFIG_PAYLOAD: Final = ("version", "db_ref", "db_identity_sha256", "authority_endpoint_ref", "authority_endpoint_identity_sha256", "measurement_public_key_ref", "measurement_public_key_sha256", "measurement_key_fingerprint", "resolved_scope_ref", "resolved_scope_sha256", "contract_ref", "contract_sha256", "source_manifest_ref", "source_manifest_sha256", "capability_manifest_ref", "capability_manifest_sha256", "benchmark_manifest_ref", "benchmark_manifest_sha256", "holdout_manifest_ref", "holdout_manifest_sha256", "shadow_executor_bundle_ref", "shadow_executor_bundle_sha256")
_CONFIG_FIELDS: Final = (*_CONFIG_PAYLOAD, "shadow_measurement_root_ref", "shadow_measurement_root_sha256", "run_config_payload_sha256", "signer_ref", "key_id", "signature")
_REF_PAIRS: Final = (("db_ref", "db_identity_sha256"), ("authority_endpoint_ref", "authority_endpoint_identity_sha256"), ("measurement_public_key_ref", "measurement_public_key_sha256"), ("resolved_scope_ref", "resolved_scope_sha256"), ("contract_ref", "contract_sha256"), ("source_manifest_ref", "source_manifest_sha256"), ("capability_manifest_ref", "capability_manifest_sha256"), ("benchmark_manifest_ref", "benchmark_manifest_sha256"), ("holdout_manifest_ref", "holdout_manifest_sha256"))
_DIGEST_KEYS: Final = ("shadow_executor_bundle_sha256", "shadow_measurement_root_sha256", "shadow_run_config_payload_sha256")
Wire: TypeAlias = str | int | bool | list["Wire"] | dict[str, "Wire"]  # noqa: UP040


@dataclass(frozen=True, slots=True)
class DeploymentAuthorityError(Exception):
    detail: str
    def __str__(self) -> str: return self.detail


def _digest(value: Wire, field: str) -> str:
    if type(value) is not str or len(value) != 64 or any(char not in _HEX for char in value): raise DeploymentAuthorityError(f"{field} must be a lowercase sha256 digest")
    return value


def _text(value: Wire, field: str) -> str:
    if type(value) is not str or not value: raise DeploymentAuthorityError(f"{field} must be a non-empty string")
    return value


def _closed(data: Mapping[str, Wire], fields: tuple[str, ...]) -> dict[str, str]:
    if set(data) != set(fields): raise DeploymentAuthorityError("schema is invalid")
    return {field: _digest(data[field], field) if field.endswith(("_sha256", "_fingerprint")) or field == "bundle_sha256" else _text(data[field], field) for field in fields}


def _verify(key: Ed25519PublicKey, signature: str, message: bytes) -> None:
    try: key.verify(bytes.fromhex(signature), message)
    except (InvalidSignature, ValueError) as exc: raise DeploymentAuthorityError("signature is invalid") from exc


def _canonical(value: Mapping[str, Wire | int | list[dict[str, Wire]]]) -> bytes:
    try: return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()
    except (TypeError, ValueError) as exc: raise DeploymentAuthorityError("value is not canonicalizable") from exc


def _root_of(events: list[dict[str, Wire]]) -> str:
    return sha256(canonical_ledger_bytes(AUTHORITY_DOMAIN, {"events": events})).hexdigest()


def _stamp(value: datetime) -> str:
    if type(value) is not datetime or value.tzinfo is not UTC or value.utcoffset() != timedelta(0): raise DeploymentAuthorityError("trusted authority clock must return canonical UTC")
    return value.isoformat().replace("+00:00", "Z")


def _reject_alias(path: Path, label: str) -> None:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents): raise DeploymentAuthorityError(f"{label} alias is forbidden")


def _commit_file(path: Path, payload: bytes, *, replace: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600); offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0: raise OSError("short write")
            offset += written
        os.fsync(descriptor); os.close(descriptor); descriptor = -1
        os.replace(temporary, path) if replace else os.link(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY); os.fsync(directory); os.close(directory)
    except OSError as exc: raise DeploymentAuthorityError("durable write cannot be committed") from exc
    finally:
        if descriptor >= 0: os.close(descriptor)
        if os.path.exists(temporary): os.unlink(temporary)


class _Signed:
    __slots__ = ("_values",)
    def __init__(self, values: dict[str, str]) -> None: self._values = values
    def __getattr__(self, name: str) -> str: return self._values[name]
    def to_mapping(self) -> dict[str, str]: return dict(self._values)


def _load(data: Mapping[str, Wire], fields: tuple[str, ...], version: str, body: tuple[str, ...] | None, digest_field: str) -> dict[str, str]:
    values = _closed(data, fields)
    if values["version"] != version or (body is not None and digest_fields({k: values[k] for k in body}) != values[digest_field]): raise DeploymentAuthorityError("digest or version is invalid")
    return values


class ShadowExecutorBundleV1(_Signed):
    @classmethod
    def from_mapping(cls, data: Mapping[str, Wire]) -> ShadowExecutorBundleV1: return cls(_load(data, _BUNDLE_FIELDS, BUNDLE_VERSION, _BUNDLE_BODY, "bundle_sha256"))


class ShadowMeasurementRootV1(_Signed):
    @classmethod
    def from_mapping(cls, data: Mapping[str, Wire]) -> ShadowMeasurementRootV1: return cls(_load(data, _ROOT_FIELDS, ROOT_VERSION, None, ""))


class ShadowRunConfigV1(_Signed):
    @classmethod
    def from_mapping(cls, data: Mapping[str, Wire]) -> ShadowRunConfigV1: return cls(_load(data, _CONFIG_FIELDS, CONFIG_VERSION, _CONFIG_PAYLOAD, "run_config_payload_sha256"))


@dataclass(frozen=True, slots=True)
class ShadowProduceRequestV1:
    roster_artifact_sha256: str; authority_cli_artifact_sha256: str; lockfile_sha256: str; cohort_receipt_sha256: str; initial_checkpoint_sha256: str; issued_at: str
    db_ref: str; db_identity_sha256: str; authority_endpoint_ref: str; authority_endpoint_identity_sha256: str; measurement_public_key_ref: str; measurement_public_key_sha256: str; measurement_key_fingerprint: str
    resolved_scope_ref: str; resolved_scope_sha256: str; contract_ref: str; contract_sha256: str; source_manifest_ref: str; source_manifest_sha256: str; capability_manifest_ref: str; capability_manifest_sha256: str
    benchmark_manifest_ref: str; benchmark_manifest_sha256: str; holdout_manifest_ref: str; holdout_manifest_sha256: str; bundle_ref: str; root_ref: str; signer_ref: str; key_id: str


def produce_shadow_artifacts(request: ShadowProduceRequestV1, key: Ed25519PrivateKey) -> tuple[ShadowExecutorBundleV1, ShadowMeasurementRootV1, ShadowRunConfigV1]:
    if not isinstance(key, Ed25519PrivateKey): raise DeploymentAuthorityError("signing key is invalid")
    bundle_body = {"version": BUNDLE_VERSION, "roster_artifact_sha256": request.roster_artifact_sha256, "authority_cli_artifact_sha256": request.authority_cli_artifact_sha256, "lockfile_sha256": request.lockfile_sha256, "cohort_receipt_sha256": request.cohort_receipt_sha256}
    bundle_sha = digest_fields(bundle_body); bundle = ShadowExecutorBundleV1.from_mapping({**bundle_body, "bundle_sha256": bundle_sha, "signer_ref": request.signer_ref, "key_id": request.key_id, "signature": key.sign(signing_message(BUNDLE_VERSION, {**bundle_body, "bundle_sha256": bundle_sha})).hex()})
    payload = {field: CONFIG_VERSION if field == "version" else getattr(request, field) for field in _CONFIG_PAYLOAD if not field.startswith("shadow_executor_bundle_")} | {"shadow_executor_bundle_ref": request.bundle_ref, "shadow_executor_bundle_sha256": bundle_sha}
    payload_sha = digest_fields(payload); root_body = {"version": ROOT_VERSION, "cohort_receipt_sha256": request.cohort_receipt_sha256, "shadow_executor_bundle_sha256": bundle_sha, "shadow_run_config_payload_sha256": payload_sha, "initial_checkpoint_sha256": request.initial_checkpoint_sha256, "resolved_scope_sha256": request.resolved_scope_sha256, "contract_sha256": request.contract_sha256, "issued_at": request.issued_at, "signer_ref": request.signer_ref, "key_id": request.key_id}
    root = ShadowMeasurementRootV1.from_mapping({**root_body, "signature": key.sign(signing_message(ROOT_VERSION, root_body)).hex()})
    config_body = {**payload, "shadow_measurement_root_ref": request.root_ref, "shadow_measurement_root_sha256": digest_fields(root.to_mapping()), "run_config_payload_sha256": payload_sha, "signer_ref": request.signer_ref, "key_id": request.key_id}; return bundle, root, ShadowRunConfigV1.from_mapping({**config_body, "signature": key.sign(signing_message(CONFIG_VERSION, config_body)).hex()})


def verify_shadow_artifacts(*, bundle: ShadowExecutorBundleV1, root: ShadowMeasurementRootV1, config: ShadowRunConfigV1, inputs: TrustedImmutableInputRegistry, artifacts: InstalledArtifactIdentity, public_key: Ed25519PublicKey) -> None:
    _verify(public_key, bundle.signature, signing_message(BUNDLE_VERSION, {k: v for k, v in bundle.to_mapping().items() if k not in {"signer_ref", "key_id", "signature"}}))
    _verify(public_key, root.signature, signing_message(ROOT_VERSION, {k: v for k, v in root.to_mapping().items() if k != "signature"}))
    _verify(public_key, config.signature, signing_message(CONFIG_VERSION, {k: v for k, v in config.to_mapping().items() if k != "signature"}))
    if root.shadow_run_config_payload_sha256 != config.run_config_payload_sha256 or root.cohort_receipt_sha256 != bundle.cohort_receipt_sha256 or config.shadow_measurement_root_sha256 != digest_fields(root.to_mapping()) or root.shadow_executor_bundle_sha256 != bundle.bundle_sha256 or config.shadow_executor_bundle_sha256 != bundle.bundle_sha256:
        raise DeploymentAuthorityError("bundle, root, cohort, or payload binding mismatch")
    mapping = config.to_mapping()
    for ref_field, digest_field in _REF_PAIRS:
        try: raw = inputs.resolve(mapping[ref_field])
        except KeyError as exc: raise DeploymentAuthorityError(f"{ref_field} is missing") from exc
        if sha256(raw).hexdigest() != mapping[digest_field]: raise DeploymentAuthorityError(f"{digest_field} does not match resolved bytes")
    try:
        stored_bundle = ShadowExecutorBundleV1.from_mapping(json.loads(inputs.resolve(config.shadow_executor_bundle_ref))); stored_root = ShadowMeasurementRootV1.from_mapping(json.loads(inputs.resolve(config.shadow_measurement_root_ref))); inputs.resolve_digest(bundle.cohort_receipt_sha256)
    except (KeyError, json.JSONDecodeError, TypeError, ValueError) as exc: raise DeploymentAuthorityError("bundle, root, or cohort is missing") from exc
    if stored_bundle.to_mapping() != bundle.to_mapping() or stored_root.to_mapping() != root.to_mapping() or (artifacts.host_artifact_sha256, artifacts.executor_artifact_sha256, artifacts.lockfile_sha256) != (bundle.roster_artifact_sha256, bundle.authority_cli_artifact_sha256, bundle.lockfile_sha256):
        raise DeploymentAuthorityError("stored bundle, root, or installed artifact identity mismatch")


@dataclass(frozen=True, slots=True)
class DeploymentAuthorityEvidence:
    identity: str; endpoint: str; policy_id: str; measurement_binding: str; public_key_fingerprint: str
    shadow_executor_bundle_sha256: str; shadow_measurement_root_sha256: str; shadow_run_config_payload_sha256: str
    def __post_init__(self) -> None:
        for field in ("identity", "endpoint", "policy_id", "measurement_binding"): _text(getattr(self, field), field)
        if not self.endpoint.startswith("retention-authority://"): raise DeploymentAuthorityError("endpoint must be a retention-authority reference")
        for field in ("public_key_fingerprint", *_DIGEST_KEYS): _digest(getattr(self, field), field)


class DeploymentMonotonicAppendAuthority:
    def __init__(self, *, state_path: str | Path, evidence: DeploymentAuthorityEvidence, signing_key: Ed25519PrivateKey, snapshot_factory: Callable[..., Any], trusted_clock: Callable[[], datetime], max_age_seconds: int = 60) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey) or not callable(snapshot_factory) or not callable(trusted_clock): raise DeploymentAuthorityError("signer, snapshot factory, or trusted clock is invalid")
        if type(max_age_seconds) is not int or not 0 < max_age_seconds <= 300: raise DeploymentAuthorityError("receipt lifetime is invalid")
        if sha256(signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest() != evidence.public_key_fingerprint: raise DeploymentAuthorityError("signing key does not match evidence")
        original = Path(state_path)
        if not original.is_absolute() or original.name in {"", ".", ".."}: raise DeploymentAuthorityError("state path must be absolute and concrete")
        _reject_alias(original, "retained authority state")
        self._state_path, self._evidence, self._key, self._snapshot_factory, self._trusted_clock, self._max_age, self._last_revision, self._anchor, self.identity, self.endpoint, self.policy_id, self.public_key, self.shadow_executor_bundle_sha256, self.shadow_measurement_root_sha256, self.shadow_run_config_payload_sha256 = original.resolve(strict=False), evidence, signing_key, snapshot_factory, trusted_clock, max_age_seconds, -1, None, evidence.identity, evidence.endpoint, evidence.policy_id, signing_key.public_key(), evidence.shadow_executor_bundle_sha256, evidence.shadow_measurement_root_sha256, evidence.shadow_run_config_payload_sha256

    def _now(self) -> datetime:
        try: value = self._trusted_clock()
        except (RuntimeError, TypeError, ValueError) as exc: raise DeploymentAuthorityError("trusted authority clock is unavailable") from exc
        _stamp(value); return value

    def verify_deployment_evidence(self, evidence: Mapping[str, Wire], *, measurement_binding: str) -> None:
        required = {"evidence_version", "identity", "endpoint", "policy_id", "public_key_fingerprint", "measurement_binding", "authority_revision", "authority_root", "issued_at", "expires_at", "signature", *_DIGEST_KEYS}
        if not isinstance(evidence, Mapping) or set(evidence) != required or evidence.get("evidence_version") != EVIDENCE_SCHEMA: raise DeploymentAuthorityError("deployment authority evidence schema is invalid")
        pins = (evidence.get("identity"), evidence.get("endpoint"), evidence.get("policy_id"), evidence.get("public_key_fingerprint"), evidence.get("measurement_binding"), *(evidence.get(field) for field in _DIGEST_KEYS))
        expect = (self.identity, self.endpoint, self.policy_id, self._evidence.public_key_fingerprint, measurement_binding, *(getattr(self, field) for field in _DIGEST_KEYS))
        if pins != expect or measurement_binding != self._evidence.measurement_binding: raise DeploymentAuthorityError("deployment authority evidence pins or binding are invalid")
        revision = evidence.get("authority_revision")
        if type(revision) is not int or revision < 0 or not _digest(evidence["authority_root"], "authority_root"): raise DeploymentAuthorityError("deployment authority evidence head is invalid")
        now = self._now()
        try:
            issued = datetime.fromisoformat(str(evidence["issued_at"]).replace("Z", "+00:00")).astimezone(UTC)
            expires = datetime.fromisoformat(str(evidence["expires_at"]).replace("Z", "+00:00")).astimezone(UTC)
        except (TypeError, ValueError) as exc: raise DeploymentAuthorityError("evidence timestamp is invalid") from exc
        if expires <= issued or now < issued or now >= expires or expires - issued > timedelta(minutes=5): raise DeploymentAuthorityError("deployment authority evidence is stale")
        _verify(self.public_key, str(evidence["signature"]), canonical_ledger_bytes(EVIDENCE_SCHEMA, {key: evidence[key] for key in required if key != "signature"}))
        head = (revision, evidence["authority_root"])
        try: events = self._read(create=False)
        except DeploymentAuthorityError as exc:
            if "missing" not in str(exc) or head != (0, _root_of([])): raise
            events = []
        if (len(events), _root_of(events)) != head: raise DeploymentAuthorityError("deployment authority evidence head does not match retained state")
        self._anchor = head

    def _locked(self):
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(self._state_path.with_suffix(self._state_path.suffix + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise DeploymentAuthorityError("retained authority lock is not a private regular file")
            os.fchmod(descriptor, 0o600); handle = os.fdopen(descriptor, "r+")
        except OSError as exc: raise DeploymentAuthorityError("retained authority lock alias is forbidden") from exc
        class _Lock:
            def __enter__(_self) -> _Lock: fcntl.flock(handle.fileno(), fcntl.LOCK_EX); return _self
            def __exit__(_self, *_unused) -> None: fcntl.flock(handle.fileno(), fcntl.LOCK_UN); handle.close()
        return _Lock()

    def _body(self, events: list[dict[str, Wire]]) -> dict[str, Wire | int | list[dict[str, Wire]]]:
        return {"schema": STATE_SCHEMA, "measurement_binding": self._evidence.measurement_binding, "revision": len(events), "root": _root_of(events), "signer_fingerprint": self._evidence.public_key_fingerprint, "events": events, **{field: getattr(self, field) for field in _DIGEST_KEYS}}

    def _read(self, *, create: bool) -> list[dict[str, Wire]]:
        try: descriptor = os.open(self._state_path, os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            if not create: raise DeploymentAuthorityError("retained authority state is missing")
            self._write([]); return []
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1: raise DeploymentAuthorityError("retained authority state is not a private regular file")
            raw = b"".join(iter(lambda: os.read(descriptor, 65536), b"")); value = json.loads(raw)
            if _canonical(value) != raw: raise DeploymentAuthorityError("retained authority state is noncanonical")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise DeploymentAuthorityError("retained authority state is unreadable") from exc
        finally: os.close(descriptor)
        expected = {"schema", "measurement_binding", "revision", "root", "signer_fingerprint", "events", "signature", *_DIGEST_KEYS}
        events = value.get("events") if isinstance(value, dict) else None
        if not isinstance(value, dict) or set(value) != expected or value.get("schema") != STATE_SCHEMA: raise DeploymentAuthorityError("retained authority state schema is invalid")
        if (value.get("measurement_binding") != self._evidence.measurement_binding or value.get("signer_fingerprint") != self._evidence.public_key_fingerprint or any(value.get(field) != getattr(self, field) for field in _DIGEST_KEYS) or not isinstance(events, list) or type(value.get("revision")) is not int or value["revision"] != len(events) or value.get("root") != _root_of(events) or not all(isinstance(event, dict) for event in events)):
            raise DeploymentAuthorityError("retained authority state binding is invalid")
        try: self.public_key.verify(bytes.fromhex(str(value["signature"])), canonical_ledger_bytes(STATE_SCHEMA, self._body(events)))
        except (InvalidSignature, ValueError, TypeError) as exc: raise DeploymentAuthorityError("retained authority state signature is invalid") from exc
        if len(events) < self._last_revision: raise DeploymentAuthorityError("retained authority rollback detected")
        self._last_revision = len(events); return events

    def _write(self, events: list[dict[str, Wire]]) -> None:
        body = self._body(events); body["signature"] = self._key.sign(canonical_ledger_bytes(STATE_SCHEMA, body)).hex()
        _commit_file(self._state_path, _canonical(body), replace=True)

    def _snapshot(self, *, events: list[dict[str, Wire]], request_nonce: str, issued_at: datetime) -> Any:
        if type(request_nonce) is not str or len(request_nonce) < 32: raise DeploymentAuthorityError("authority request nonce is invalid")
        payload = {"identity": self.identity, "endpoint": self.endpoint, "policy_id": self.policy_id, "public_key_fingerprint": self._evidence.public_key_fingerprint, "revision": len(events), "root": _root_of(events), "request_nonce": request_nonce, "issued_at": _stamp(issued_at), "expires_at": _stamp(issued_at + timedelta(seconds=self._max_age)), "events": tuple(events)}
        signature = self._key.sign(canonical_ledger_bytes(AUTHORITY_DOMAIN, payload)).hex()
        try:
            snapshot = self._snapshot_factory(**payload, signature=signature)
            if snapshot.payload() != payload | {"events": [dict(event) for event in events]} or snapshot.signature != signature: raise DeploymentAuthorityError("factory receipt does not preserve the signed payload")
        except (AttributeError, TypeError, ValueError, DeploymentAuthorityError) as exc: raise DeploymentAuthorityError("deployment authority snapshot factory is invalid") from exc
        return snapshot

    def _guarded(self, request_nonce: str, event: Mapping[str, Wire] | None, expected_revision: int | None) -> Any:
        with self._locked():
            if self._anchor is None: raise DeploymentAuthorityError("verified deployment evidence is required")
            try: events = self._read(create=False); missing = False
            except DeploymentAuthorityError as exc:
                if "missing" not in str(exc) or self._anchor != (0, _root_of([])): raise
                events, missing = [], True
            if (len(events), _root_of(events)) != self._anchor: raise DeploymentAuthorityError("retained authority head changed after evidence verification")
            if event is not None:
                if expected_revision != len(events): raise DeploymentAuthorityError("authority revision conflict")
                events = [*events, dict(event)]
            signed = self._snapshot(events=events, request_nonce=request_nonce, issued_at=self._now())
            if event is not None or missing:
                self._write(events)
                if event is not None: self._last_revision, self._anchor = len(events), (len(events), _root_of(events))
            return signed

    def snapshot(self, *, request_nonce: str) -> Any:
        return self._guarded(request_nonce, None, None)

    def compare_and_advance(self, *, expected_revision: int, event: Mapping[str, Wire], request_nonce: str) -> Any:
        if type(expected_revision) is not int or expected_revision < 0 or not isinstance(event, Mapping): raise DeploymentAuthorityError("authority advance request is invalid")
        return self._guarded(request_nonce, event, expected_revision)


def write_live_operation_denial_receipt(*, path: str | Path, authority: DeploymentMonotonicAppendAuthority, operation: str) -> dict[str, str | bool]:
    if operation not in {"init", "status", "append", "verify"}: raise DeploymentAuthorityError("receipt operation is invalid")
    snapshot = authority.snapshot(request_nonce=token_hex(32))
    receipt: dict[str, str | bool] = {"receipt_version": RECEIPT_SCHEMA, "identity": authority.identity, "endpoint": authority.endpoint, "policy_id": authority.policy_id, "public_key_fingerprint": authority._evidence.public_key_fingerprint, "measurement_binding": authority._evidence.measurement_binding, "authority_revision": str(snapshot.revision), "authority_root": snapshot.root, "operation": operation, "live_operation_authorized": False, "shadow_executor_bundle_sha256": authority.shadow_executor_bundle_sha256, "shadow_measurement_root_sha256": authority.shadow_measurement_root_sha256, "shadow_run_config_payload_sha256": authority.shadow_run_config_payload_sha256}
    receipt["receipt_digest"] = sha256(canonical_ledger_bytes(RECEIPT_SCHEMA, receipt)).hexdigest()
    original = Path(path)
    if not original.is_absolute(): raise DeploymentAuthorityError("receipt path must be absolute")
    _reject_alias(original, "receipt")
    _commit_file(original.resolve(strict=False), _canonical(receipt), replace=False)
    return receipt
