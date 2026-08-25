"""In-process verify-and-mint and prepared-grant recovery for protected operations."""
from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_gate_envelope import (
    DESTRUCTIVE_APPROVAL_FIELDS,
    DESTRUCTIVE_APPROVAL_VERSION,
    GATE_ENVELOPE_VERSION,
    PREPARED_GRANT_VERSION,
    ROLE_APPROVAL_VERSION,
    GateEnvelopeV1,
    OutputCapabilityV1,
    PreparedExecutionGrantV1,
    ProtectedExecutorBundleV1,
    ProtectedInputManifestV1,
    ProtectedOperation,
    RoleApprovalEnvelopeV1,
    digest_fields,
    load_object,
    require_digest,
    require_fields,
    require_text,
    signing_message,
)

_CALLABLE = {
    ProtectedOperation.CERTIFIED_IMPORT: "second_brain.import_and_reconcile.v1",
    ProtectedOperation.CERTIFIED_ACTIVATION: "second_brain.review_activate_and_freeze.v1",
    ProtectedOperation.ROUTE_REHEARSAL: "second_brain.route_rehearse.v1",
    ProtectedOperation.ROUTE_SWITCH: "second_brain.route_switch_atomic.v1",
    ProtectedOperation.RETENTION_CLOSE: "second_brain.close_retention.v1",
    ProtectedOperation.DECOMMISSION: "second_brain.decommission.v1",
}



@dataclass(frozen=True, slots=True)
class ProtectedAuthorityError(Exception):
    field: str
    detail: str

    def __str__(self) -> str:
        return f"{self.field}: {self.detail}"


@dataclass(frozen=True, slots=True)
class InstalledArtifactIdentity:
    host_artifact_sha256: str
    executor_artifact_sha256: str
    lockfile_sha256: str


class TrustedClock(Protocol):
    def now(self) -> str: ...


class TrustedGateRegistry(Protocol):
    def public_key(self, signer_ref: str, key_id: str) -> bytes: ...


class TrustedRoleRegistry(Protocol):
    def role_public_key(self, role: str, signer_ref: str, key_id: str) -> bytes: ...


class TrustedImmutableInputRegistry(Protocol):
    def resolve(self, ref: str) -> bytes: ...
    def resolve_digest(self, digest: str) -> bytes: ...


class TrustedReceiptRegistry(Protocol):
    def resolve(self, ref: str) -> bytes: ...


class TrustedOutputRegistry(Protocol):
    def resolve(self, ref: str, digest: str, registry_version: str) -> OutputCapabilityV1: ...
    def resolve_for_recovery(self, grant: PreparedExecutionGrantV1, output_capability_sha256: str, registry_version: str) -> OutputCapabilityV1: ...


class HostGrantSigner:
    """Process-local grant signer. Never serialized onto envelope, argv, receipt, or disk."""

    __slots__ = ("_key", "key_id")

    def __init__(self, key: Ed25519PrivateKey, key_id: str) -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, message: bytes) -> str:
        return self._key.sign(message).hex()

    def verify(self, signature: str, message: bytes) -> None:
        try: self._key.public_key().verify(bytes.fromhex(signature), message)
        except (InvalidSignature, ValueError) as exc: raise ProtectedAuthorityError("signature", "host grant signature failed") from exc


class _Mint:
    __slots__ = ()


_MINT = _Mint()


class OperationSpecificOpaqueAuthority:
    """Non-serializable minted authority. Public argv and mappings cannot construct this."""

    __slots__ = ("_operation", "_workspace_ref", "_request_digest", "_bundle_sha256")

    def __init__(self, mint: _Mint, operation: str, workspace_ref: str, request_digest: str, bundle_sha256: str) -> None:
        if mint is not _MINT: raise ProtectedAuthorityError("authority", "must be minted")
        self._operation, self._workspace_ref, self._request_digest, self._bundle_sha256 = operation, workspace_ref, request_digest, bundle_sha256

    @property
    def operation(self) -> str: return self._operation
    @property
    def workspace_ref(self) -> str: return self._workspace_ref
    @property
    def request_digest(self) -> str: return self._request_digest
    @property
    def bundle_sha256(self) -> str: return self._bundle_sha256


class OperationSpecificRecoveryAuthority(OperationSpecificOpaqueAuthority):
    __slots__ = ("_journal_id", "_grant_sha256")

    def __init__(self, mint: _Mint, operation: str, workspace_ref: str, request_digest: str, bundle_sha256: str, journal_id: str, grant_sha256: str) -> None:
        super().__init__(mint, operation, workspace_ref, request_digest, bundle_sha256)
        self._journal_id, self._grant_sha256 = journal_id, grant_sha256

    @property
    def journal_id(self) -> str: return self._journal_id
    @property
    def grant_sha256(self) -> str: return self._grant_sha256


@dataclass(frozen=True, slots=True)
class JournalRecordV1:
    journal_id: str
    operation: str
    workspace_ref: str
    request_digest: str
    executor_bundle_sha256: str
    protected_input_manifest_sha256: str
    output_capability_sha256: str
    target_manifest_sha256: str
    gate_envelope_sha256: str
    role_approval_set_sha256: str
    state: str
    grant_bytes: bytes
    grant_sha256: str
    observed_effect: str
    receipt_digest: str = ""

    def advance(self, state: str, observed_effect: str, receipt_digest: str = "") -> JournalRecordV1:
        return replace(self, state=state, observed_effect=observed_effect, receipt_digest=receipt_digest or self.receipt_digest)


def _verify(public_key: bytes, signature: str, message: bytes, field: str) -> None:
    try: Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(signature), message)
    except (InvalidSignature, ValueError) as exc: raise ProtectedAuthorityError(field, "verification failed") from exc


def _window(issued_at: str, expires_at: str, now: str, field: str) -> None:
    if not (issued_at <= now < expires_at): raise ProtectedAuthorityError(field, "not inside the authorized time window")


@dataclass(frozen=True, slots=True)
class ProtectedAuthorityFactory:
    gates: TrustedGateRegistry
    roles: TrustedRoleRegistry
    inputs: TrustedImmutableInputRegistry
    receipts: TrustedReceiptRegistry
    outputs: TrustedOutputRegistry
    clock: TrustedClock
    artifacts: InstalledArtifactIdentity
    host_signer: HostGrantSigner

    def verify_and_mint(self, envelope_bytes: bytes, expected_operation: str, expected_bundle_sha256: str, expected_request_digest: str) -> OperationSpecificOpaqueAuthority:
        envelope = GateEnvelopeV1.from_bytes(envelope_bytes)
        if envelope.operation.value != expected_operation: raise ProtectedAuthorityError("operation", "envelope operation mismatch")
        if envelope.executor_bundle_sha256 != expected_bundle_sha256: raise ProtectedAuthorityError("bundle", "executor bundle mismatch")
        if envelope.request_digest != expected_request_digest: raise ProtectedAuthorityError("request", "request digest mismatch")
        _window(envelope.issued_at, envelope.expires_at, self.clock.now(), "time")
        _verify(self.gates.public_key(envelope.signer_ref, envelope.key_id), envelope.signature, signing_message(GATE_ENVELOPE_VERSION, envelope.to_mapping()), "signature")
        bundle = self._bundle(envelope)
        manifest = self._manifest(envelope)
        self._roles(envelope)
        self._inputs(manifest)
        self._output(envelope)
        if envelope.operation is ProtectedOperation.DECOMMISSION: self._destructive(envelope)
        return OperationSpecificOpaqueAuthority(_MINT, envelope.operation.value, envelope.workspace_ref, envelope.request_digest, bundle.bundle_sha256)

    def issue_prepared_grant(self, envelope_bytes: bytes, journal_id: str, request_digest: str) -> bytes:
        envelope = GateEnvelopeV1.from_bytes(envelope_bytes)
        body: dict[str, str | bool] = {
            "version": PREPARED_GRANT_VERSION, "journal_id": journal_id, "gate_envelope_sha256": sha256(envelope_bytes).hexdigest(),
            "role_approval_set_sha256": digest_fields({"role_approval_refs": list(envelope.role_approval_refs)}),
            "protected_input_manifest_sha256": envelope.protected_input_manifest_sha256, "output_capability_sha256": envelope.output_capability_sha256,
            "request_digest": request_digest, "executor_bundle_sha256": envelope.executor_bundle_sha256, "workspace_ref": envelope.workspace_ref,
            "target_manifest_sha256": self._target_digest(envelope), "prepared_at": self.clock.now(), "recovery_authorized": True, "host_key_id": self.host_signer.key_id,
        }
        signed = {**body, "grant_sha256": digest_fields(body)}
        return canonical_bytes({**signed, "host_signature": self.host_signer.sign(signing_message(PREPARED_GRANT_VERSION, signed, exclude=("host_signature",)))})

    def record_from_grant(self, grant_bytes: bytes, state: str, observed_effect: str) -> JournalRecordV1:
        grant = PreparedExecutionGrantV1.from_bytes(grant_bytes)
        return JournalRecordV1(grant.journal_id, "", grant.workspace_ref, grant.request_digest, grant.executor_bundle_sha256, grant.protected_input_manifest_sha256, grant.output_capability_sha256, grant.target_manifest_sha256, grant.gate_envelope_sha256, grant.role_approval_set_sha256, state, grant_bytes, grant.grant_sha256, observed_effect)

    def resume_from_grant(self, grant_bytes: bytes, journal_record: JournalRecordV1) -> OperationSpecificRecoveryAuthority:
        try: grant = PreparedExecutionGrantV1.from_bytes(grant_bytes)
        except (InvalidSignature, ValueError, KeyError) as exc: raise ProtectedAuthorityError("grant", "grant bytes are not an exact prepared grant") from exc
        if grant.grant_sha256 != digest_fields(grant.signing_payload(), exclude=("grant_sha256",)): raise ProtectedAuthorityError("grant", "grant digest mismatch")
        if grant.host_key_id != self.host_signer.key_id: raise ProtectedAuthorityError("grant", "host key mismatch")
        self.host_signer.verify(grant.host_signature, signing_message(PREPARED_GRANT_VERSION, grant.signing_payload(), exclude=("host_signature",)))
        if not grant.recovery_authorized: raise ProtectedAuthorityError("grant", "recovery is not authorized")
        if grant.journal_id != journal_record.journal_id or grant.request_digest != journal_record.request_digest: raise ProtectedAuthorityError("journal", "journal binding mismatch")
        if grant.executor_bundle_sha256 != journal_record.executor_bundle_sha256 or grant.protected_input_manifest_sha256 != journal_record.protected_input_manifest_sha256: raise ProtectedAuthorityError("journal", "bundle or input binding mismatch")
        if grant.output_capability_sha256 != journal_record.output_capability_sha256 or grant.workspace_ref != journal_record.workspace_ref: raise ProtectedAuthorityError("journal", "output or workspace binding mismatch")
        if grant.target_manifest_sha256 != journal_record.target_manifest_sha256 or grant.grant_sha256 != journal_record.grant_sha256: raise ProtectedAuthorityError("journal", "target or grant binding mismatch")
        if journal_record.state not in {"PREPARED", "EFFECT_APPLIED", "RECEIPT_PUBLISHED"}: raise ProtectedAuthorityError("journal", "journal is not resumable")
        return OperationSpecificRecoveryAuthority(_MINT, journal_record.operation or ProtectedOperation.CERTIFIED_IMPORT.value, grant.workspace_ref, grant.request_digest, grant.executor_bundle_sha256, grant.journal_id, grant.grant_sha256)

    def _bundle(self, envelope: GateEnvelopeV1) -> ProtectedExecutorBundleV1:
        try: bundle = ProtectedExecutorBundleV1.from_bytes(self.inputs.resolve_digest(envelope.executor_bundle_sha256))
        except KeyError as exc: raise ProtectedAuthorityError("bundle", "executor bundle is not in the input registry") from exc
        if bundle.bundle_sha256 != envelope.executor_bundle_sha256 or bundle.operation is not envelope.operation or bundle.callable_id != _CALLABLE[envelope.operation]: raise ProtectedAuthorityError("bundle", "bundle does not match the envelope")
        if (bundle.host_artifact_sha256, bundle.executor_artifact_sha256, bundle.lockfile_sha256) != (self.artifacts.host_artifact_sha256, self.artifacts.executor_artifact_sha256, self.artifacts.lockfile_sha256):
            raise ProtectedAuthorityError("artifact", "installed artifact identity mismatch")
        return bundle

    def _manifest(self, envelope: GateEnvelopeV1) -> ProtectedInputManifestV1:
        try: manifest = ProtectedInputManifestV1.from_bytes(self.inputs.resolve_digest(envelope.protected_input_manifest_sha256))
        except KeyError as exc: raise ProtectedAuthorityError("input", "input manifest is not in the input registry") from exc
        if manifest.manifest_sha256 != envelope.protected_input_manifest_sha256 or manifest.operation is not envelope.operation or manifest.workspace_ref != envelope.workspace_ref:
            raise ProtectedAuthorityError("workspace" if manifest.workspace_ref != envelope.workspace_ref else "input", "input manifest binding mismatch")
        return manifest

    def _inputs(self, manifest: ProtectedInputManifestV1) -> None:
        for entry in manifest.entries:
            try: raw = self.inputs.resolve(entry.ref)
            except KeyError as exc: raise ProtectedAuthorityError("input", "input entry is missing") from exc
            if sha256(raw).hexdigest() != entry.sha256 or str(len(raw)) != entry.size: raise ProtectedAuthorityError("target" if "target" in entry.ref else "input", "input entry digest mismatch")
            if entry.kind == "receipt":
                try:
                    if self.receipts.resolve(entry.ref) != raw: raise ProtectedAuthorityError("input", "receipt registry mismatch")
                except KeyError as exc: raise ProtectedAuthorityError("input", "prior receipt is missing") from exc

    def _roles(self, envelope: GateEnvelopeV1) -> None:
        seen: set[str] = set()
        for ref in envelope.role_approval_refs:
            try: approval = RoleApprovalEnvelopeV1.from_bytes(self.inputs.resolve(ref))
            except KeyError as exc: raise ProtectedAuthorityError("role", "role approval is missing") from exc
            if approval.role.value in seen: raise ProtectedAuthorityError("role", "duplicate role")
            seen.add(approval.role.value)
            if (approval.gate_id, approval.authority_digest, approval.operation, approval.workspace_ref, approval.executor_bundle_sha256, approval.protected_input_manifest_sha256, approval.request_digest) != (envelope.gate_id, envelope.authority_digest, envelope.operation, envelope.workspace_ref, envelope.executor_bundle_sha256, envelope.protected_input_manifest_sha256, envelope.request_digest):
                raise ProtectedAuthorityError("role", "role approval binding mismatch")
            _window(approval.issued_at, approval.expires_at, self.clock.now(), "time")
            payload = {"version": approval.version, "gate_id": approval.gate_id, "authority_digest": approval.authority_digest, "role": approval.role.value, "operation": approval.operation.value, "workspace_ref": approval.workspace_ref, "executor_bundle_sha256": approval.executor_bundle_sha256, "protected_input_manifest_sha256": approval.protected_input_manifest_sha256, "request_digest": approval.request_digest, "issued_at": approval.issued_at, "expires_at": approval.expires_at, "signer_ref": approval.signer_ref, "key_id": approval.key_id}
            _verify(self.roles.role_public_key(approval.role.value, approval.signer_ref, approval.key_id), approval.signature, signing_message(ROLE_APPROVAL_VERSION, payload), "role")

    def _output(self, envelope: GateEnvelopeV1) -> OutputCapabilityV1:
        try: capability = self.outputs.resolve(envelope.output_capability_ref, envelope.output_capability_sha256, envelope.output_registry_version)
        except (KeyError, ProtectedAuthorityError) as exc: raise ProtectedAuthorityError("output", "output capability mismatch") from exc
        if capability.capability_sha256 != envelope.output_capability_sha256 or capability.operation is not envelope.operation or capability.workspace_ref != envelope.workspace_ref:
            raise ProtectedAuthorityError("output", "output capability binding mismatch")
        return capability

    def _target_digest(self, envelope: GateEnvelopeV1) -> str:
        manifest = ProtectedInputManifestV1.from_bytes(self.inputs.resolve_digest(envelope.protected_input_manifest_sha256))
        return digest_fields({"version": "second-brain-protected-target-manifest/v1", "operation": envelope.operation.value, "workspace_ref": envelope.workspace_ref, "targets": [entry.to_mapping() for entry in manifest.entries]})

    def _destructive(self, envelope: GateEnvelopeV1) -> None:
        values = require_fields(load_object(self.inputs.resolve_digest(envelope.authority_digest)), DESTRUCTIVE_APPROVAL_FIELDS)
        if values["version"] != DESTRUCTIVE_APPROVAL_VERSION or require_text(values["workspace_ref"], "workspace_ref") != envelope.workspace_ref:
            raise ProtectedAuthorityError("role", "destructive approval mismatch")
        _ = require_digest(values["target_manifest_sha256"], "target_manifest_sha256")
