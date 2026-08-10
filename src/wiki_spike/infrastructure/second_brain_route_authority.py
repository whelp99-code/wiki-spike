"""Deployment-injected, one-transaction Second Brain route authority.

The adapter owns a single signed state file.  It never resolves a legacy
endpoint, queries a fallback source, or performs a dual write.  A deployment
must inject a fresh signed head anchor before the adapter will read or mutate
the file; this is deliberately stronger than a process-local monotonic counter
and prevents a restarted process from accepting a rolled-back state snapshot.
"""
from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import (
    ROUTE_AUTHORITY_STATE_VERSION,
    RouteAuthorityStateV1,
    RouteSwitchReceiptV1,
)
from wiki_spike.memory_core.second_brain_cutover import MigrationCohortManifestV1


ROUTE_AUTHORITY_ANCHOR_VERSION = "second-brain-route-authority-anchor-v1"
ROUTE_AUTHORITY_FILE_SCHEMA = "second-brain-route-authority-file-v1"
_ANCHOR_DOMAIN = b"wiki-spike.second-brain.route-authority-anchor.v1\x00"
_STATE_DOMAIN = b"wiki-spike.second-brain.route-authority-state.v1\x00"
_HEX64 = frozenset("0123456789abcdef")


class RouteAuthorityError(RuntimeError):
    """A trusted route authority precondition or durable transaction failed."""


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in _HEX64 for char in value):
        raise RouteAuthorityError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _text(value: Any, label: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise RouteAuthorityError(f"{label} must be a bounded opaque string")
    return value


def _epoch(value: Any, label: str, *, zero_allowed: bool = False) -> str:
    if not isinstance(value, str) or (value == "0" and zero_allowed):
        if value == "0" and zero_allowed:
            return value
        raise RouteAuthorityError(f"{label} must be a canonical decimal string")
    if value.startswith("0") or not value.isdecimal():
        raise RouteAuthorityError(f"{label} must be a canonical decimal string")
    return value


def _fingerprint(key: Ed25519PublicKey) -> str:
    return sha256(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()


def _head_for_empty(authority: str) -> str:
    return sha256(canonical_bytes({"route_authority": authority, "route_state": None})).hexdigest()


def _strict(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping) or any(not isinstance(key, str) for key in value):
        raise RouteAuthorityError(f"{label} must be an object with string keys")
    unknown, missing = set(value) - fields, fields - set(value)
    if unknown or missing:
        raise RouteAuthorityError(f"{label} fields are wrong; missing={sorted(missing)} unknown={sorted(unknown)}")
    return dict(value)


@dataclass(frozen=True, slots=True)
class RouteAuthorityDeploymentAnchorV1:
    """An out-of-band signed deployment head and exact route runbook pins."""

    anchor_version: str
    route_authority: str
    runbook_digest: str
    cutover_decision_digest: str
    cohort_manifest_digest: str
    target: str
    resolved_scope_digest: str
    contract_digest: str
    source_manifest_digest: str
    capability_manifest_digest: str
    benchmark_manifest_digest: str
    generation_digest: str
    checkpoint_digest: str
    route_version: str
    capability_epoch: str
    visibility: str
    pre_mutation_rollback_receipt_digest: str
    state_revision: str
    state_digest: str
    signer_fingerprint: str
    signature: str

    FIELDS = {
        "anchor_version", "route_authority", "runbook_digest", "cutover_decision_digest",
        "cohort_manifest_digest", "target", "resolved_scope_digest", "contract_digest",
        "source_manifest_digest", "capability_manifest_digest", "benchmark_manifest_digest",
        "generation_digest", "checkpoint_digest", "route_version", "capability_epoch",
        "visibility", "pre_mutation_rollback_receipt_digest", "state_revision", "state_digest",
        "signer_fingerprint", "signature",
    }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "RouteAuthorityDeploymentAnchorV1":
        values = _strict(data, cls.FIELDS, "route authority anchor")
        if values["anchor_version"] != ROUTE_AUTHORITY_ANCHOR_VERSION:
            raise RouteAuthorityError("unsupported route authority anchor version")
        signature = values["signature"]
        if not isinstance(signature, str) or len(signature) != 128:
            raise RouteAuthorityError("route authority anchor signature is invalid")
        try:
            bytes.fromhex(signature)
        except ValueError as exc:
            raise RouteAuthorityError("route authority anchor signature is invalid") from exc
        return cls(
            ROUTE_AUTHORITY_ANCHOR_VERSION,
            _text(values["route_authority"], "route_authority"),
            _digest(values["runbook_digest"], "runbook_digest"),
            _digest(values["cutover_decision_digest"], "cutover_decision_digest"),
            _digest(values["cohort_manifest_digest"], "cohort_manifest_digest"),
            _text(values["target"], "target"),
            _digest(values["resolved_scope_digest"], "resolved_scope_digest"),
            _digest(values["contract_digest"], "contract_digest"),
            _digest(values["source_manifest_digest"], "source_manifest_digest"),
            _digest(values["capability_manifest_digest"], "capability_manifest_digest"),
            _digest(values["benchmark_manifest_digest"], "benchmark_manifest_digest"),
            _digest(values["generation_digest"], "generation_digest"),
            _digest(values["checkpoint_digest"], "checkpoint_digest"),
            _text(values["route_version"], "route_version", maximum=64),
            _epoch(values["capability_epoch"], "capability_epoch"),
            _text(values["visibility"], "visibility", maximum=64),
            _digest(values["pre_mutation_rollback_receipt_digest"], "pre_mutation_rollback_receipt_digest"),
            _epoch(values["state_revision"], "state_revision", zero_allowed=True),
            _digest(values["state_digest"], "state_digest"),
            _digest(values["signer_fingerprint"], "signer_fingerprint"),
            signature,
        )

    def signing_body(self) -> dict[str, str]:
        return {
            "anchor_version": self.anchor_version,
            "route_authority": self.route_authority,
            "runbook_digest": self.runbook_digest,
            "cutover_decision_digest": self.cutover_decision_digest,
            "cohort_manifest_digest": self.cohort_manifest_digest,
            "target": self.target,
            "resolved_scope_digest": self.resolved_scope_digest,
            "contract_digest": self.contract_digest,
            "source_manifest_digest": self.source_manifest_digest,
            "capability_manifest_digest": self.capability_manifest_digest,
            "benchmark_manifest_digest": self.benchmark_manifest_digest,
            "generation_digest": self.generation_digest,
            "checkpoint_digest": self.checkpoint_digest,
            "route_version": self.route_version,
            "capability_epoch": self.capability_epoch,
            "visibility": self.visibility,
            "pre_mutation_rollback_receipt_digest": self.pre_mutation_rollback_receipt_digest,
            "state_revision": self.state_revision,
            "state_digest": self.state_digest,
            "signer_fingerprint": self.signer_fingerprint,
        }

    def to_mapping(self) -> dict[str, str]:
        return self.signing_body() | {"signature": self.signature}


class DeploymentRouteSwitchAuthority:
    """A closed local transaction adapter, activated only by a trusted anchor."""

    def __init__(self, *, state_path: str | Path, route_authority: str, signing_key: Ed25519PrivateKey) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise RouteAuthorityError("route authority signing key is invalid")
        path = Path(state_path)
        if not path.is_absolute() or path.name in {"", ".", ".."}:
            raise RouteAuthorityError("route authority state path must be absolute and concrete")
        self._reject_alias(path, "route authority state")
        self._state_path = path.resolve(strict=False)
        self._authority = _text(route_authority, "route_authority")
        self._key = signing_key
        self._fingerprint = _fingerprint(signing_key.public_key())
        self._trusted_anchor: RouteAuthorityDeploymentAnchorV1 | None = None
        self._trusted_head: tuple[str, str] | None = None
        self._switch_output_bound = False

    @staticmethod
    def _reject_alias(path: Path, label: str) -> None:
        if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
            raise RouteAuthorityError(f"{label} alias is forbidden")

    @property
    def route_authority(self) -> str:
        return self._authority

    @property
    def canonical_switch_output_path(self) -> Path:
        """Deployment-configured path for the single state-and-receipt bundle."""
        return self._state_path

    @property
    def _lock_path(self) -> Path:
        return self._state_path.with_suffix(self._state_path.suffix + ".lock")

    def _locked(self):
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        for parent in (self._state_path.parent, *self._state_path.parent.parents):
            if parent.exists() and parent.is_symlink():
                raise RouteAuthorityError("route authority parent alias is forbidden")
        descriptor = os.open(self._lock_path, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)

        class _Lock:
            def __enter__(_self):
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                return _self

            def __exit__(_self, *unused: object) -> None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

        return _Lock()

    def _validate_output_path(self, raw: str | Path) -> Path:
        """Require the caller's spelling to be the one deployed state namespace."""
        if isinstance(raw, Path):
            raw_text = str(raw)
        elif isinstance(raw, str):
            raw_text = raw
        else:
            raise RouteAuthorityError("route output path is invalid")
        if (
            not os.path.isabs(raw_text)
            or raw_text.startswith("//")
            or raw_text != os.path.normpath(raw_text)
            or any(component in {"", ".", ".."} for component in raw_text.split(os.sep)[1:])
        ):
            raise RouteAuthorityError("route output path must be canonical and absolute")
        candidate = Path(raw_text)
        self._reject_alias(candidate, "route output")
        resolved = candidate.resolve(strict=False)
        if resolved != self._state_path:
            raise RouteAuthorityError("route output path is not the deployment-configured canonical state path")
        try:
            parent = candidate.parent.lstat()
        except OSError as exc:
            raise RouteAuthorityError("route output parent cannot be inspected") from exc
        if stat.S_ISLNK(parent.st_mode) or not stat.S_ISDIR(parent.st_mode):
            raise RouteAuthorityError("route output parent is invalid")
        return resolved

    def _verify_anchor_signature(self, anchor: RouteAuthorityDeploymentAnchorV1) -> None:
        if anchor.route_authority != self._authority or anchor.signer_fingerprint != self._fingerprint:
            raise RouteAuthorityError("route authority anchor identity is untrusted")
        try:
            self._key.public_key().verify(
                bytes.fromhex(anchor.signature),
                _ANCHOR_DOMAIN + canonical_bytes(anchor.signing_body()),
            )
        except (InvalidSignature, ValueError) as exc:
            raise RouteAuthorityError("route authority anchor signature is invalid") from exc

    def verify_trusted_anchor(self, data: Mapping[str, Any] | RouteAuthorityDeploymentAnchorV1) -> None:
        """Accept a deployment-provided head only after signature and exact-state proof."""
        anchor = data if isinstance(data, RouteAuthorityDeploymentAnchorV1) else RouteAuthorityDeploymentAnchorV1.from_mapping(data)
        self._verify_anchor_signature(anchor)
        with self._locked():
            state, _ = self._read_state()
            actual = (
                "0" if state is None else state.authority_revision,
                _head_for_empty(self._authority) if state is None else state.state_digest,
            )
            if actual != (anchor.state_revision, anchor.state_digest):
                raise RouteAuthorityError("trusted route authority head does not match retained state")
            self._trusted_anchor = anchor
            self._trusted_head = actual

    def _read_state(self) -> tuple[RouteAuthorityStateV1 | None, RouteSwitchReceiptV1 | None]:
        try:
            descriptor = os.open(self._state_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except FileNotFoundError:
            return None, None
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RouteAuthorityError("route authority state is not a private regular file")
            chunks: list[bytes] = []
            while chunk := os.read(descriptor, 65536):
                chunks.append(chunk)
            raw = b"".join(chunks)
        except OSError as exc:
            raise RouteAuthorityError("route authority state cannot be read") from exc
        finally:
            os.close(descriptor)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=self._reject_duplicates)
        except (UnicodeDecodeError, ValueError) as exc:
            raise RouteAuthorityError("route authority state is unreadable") from exc
        if canonical_bytes(value) != raw:
            raise RouteAuthorityError("route authority state is noncanonical")
        values = _strict(
            value,
            {"state_schema", "route_state", "receipt", "signer_fingerprint", "signature"},
            "route authority state",
        )
        if values["state_schema"] != ROUTE_AUTHORITY_FILE_SCHEMA or values["signer_fingerprint"] != self._fingerprint:
            raise RouteAuthorityError("route authority state identity is invalid")
        if not isinstance(values["route_state"], Mapping) or not isinstance(values["receipt"], Mapping):
            raise RouteAuthorityError("route authority state payload is invalid")
        signature = values["signature"]
        if not isinstance(signature, str):
            raise RouteAuthorityError("route authority state signature is invalid")
        signing_body = {key: values[key] for key in values if key != "signature"}
        try:
            self._key.public_key().verify(bytes.fromhex(signature), _STATE_DOMAIN + canonical_bytes(signing_body))
        except (InvalidSignature, ValueError) as exc:
            raise RouteAuthorityError("route authority state signature is invalid") from exc
        try:
            state = RouteAuthorityStateV1.from_mapping(values["route_state"])
            receipt = RouteSwitchReceiptV1.from_mapping(values["receipt"])
        except Exception as exc:
            raise RouteAuthorityError("route authority state DTO is invalid") from exc
        if (
            state.route_authority != self._authority
            or receipt.operation != "SWITCH_ATOMIC"
            or receipt.route_state_digest != state.state_digest
            or receipt.authority_revision != state.authority_revision
            or receipt.state != state.state
        ):
            raise RouteAuthorityError("route authority state and receipt do not bind")
        return state, receipt

    @staticmethod
    def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise RouteAuthorityError("route authority state contains duplicate JSON keys")
            output[key] = value
        return output

    def _write_state(self, state: RouteAuthorityStateV1, receipt: RouteSwitchReceiptV1) -> None:
        """Create one signed state-and-receipt bundle at the bound output path.

        ``link`` is used instead of replace: a racing output collision can never
        overwrite an operator's file, and the first visible path is already the
        complete canonical state plus its canonical switch receipt.
        """
        body = {
            "state_schema": ROUTE_AUTHORITY_FILE_SCHEMA,
            "route_state": state.to_mapping(),
            "receipt": receipt.to_mapping(),
            "signer_fingerprint": self._fingerprint,
        }
        value = body | {"signature": self._key.sign(_STATE_DOMAIN + canonical_bytes(body)).hex()}
        payload = canonical_bytes(value)
        descriptor = -1
        temporary: str | None = None
        published = False
        try:
            descriptor, temporary = tempfile.mkstemp(prefix=f".{self._state_path.name}.", suffix=".tmp", dir=self._state_path.parent)
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short route authority state write")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            if self._state_path.exists() and self._state_path.is_symlink():
                raise RouteAuthorityError("route authority state alias is forbidden")
            os.link(temporary, self._state_path)
            published = True
            directory = os.open(self._state_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as exc:
            # A directory fsync can fail after create-only publication.  The
            # visible file is already a complete signed bundle; prove it can be
            # recovered rather than returning a false rc2-after-mutation result.
            if published:
                try:
                    # Drop the temporary hardlink before the strict state read:
                    # the canonical bundle itself must be a private nlink==1 file.
                    if temporary is not None:
                        os.unlink(temporary)
                        temporary = None
                    recovered_state, recovered_receipt = self._read_state()
                    if recovered_state == state and recovered_receipt == receipt:
                        return
                except RouteAuthorityError:
                    pass
            raise RouteAuthorityError("route authority transaction cannot be committed") from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    def _require_trusted_head(self, state: RouteAuthorityStateV1 | None) -> RouteAuthorityDeploymentAnchorV1:
        anchor = self._trusted_anchor
        if anchor is None or self._trusted_head is None:
            raise RouteAuthorityError("fresh deployment route authority anchor is required")
        actual = (
            "0" if state is None else state.authority_revision,
            _head_for_empty(self._authority) if state is None else state.state_digest,
        )
        if actual != self._trusted_head:
            raise RouteAuthorityError("route authority head changed after trusted anchor verification")
        return anchor

    def validate_preflight(
        self,
        *,
        runbook_digest: str,
        cutover_decision_digest: str,
        cohort_manifest_digest: str,
        target: str,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt_digest: str,
    ) -> None:
        """Validate every signed runbook/decision pin before any state mutation.

        ``switch_atomic`` has a compatibility-fixed Core signature and therefore
        cannot receive the runbook or decision digest.  This preflight is the
        deployment seam that binds them to the trusted anchor before that
        atomic call; it has no write path.
        """
        with self._locked():
            state, _ = self._read_state()
            anchor = self._require_trusted_head(state)
            supplied = {
                "runbook_digest": _digest(runbook_digest, "runbook_digest"),
                "cutover_decision_digest": _digest(cutover_decision_digest, "cutover_decision_digest"),
                "cohort_manifest_digest": _digest(cohort_manifest_digest, "cohort_manifest_digest"),
                "target": _text(target, "target"),
                "resolved_scope_digest": _digest(resolved_scope_digest, "resolved_scope_digest"),
                "contract_digest": _digest(contract_digest, "contract_digest"),
                "source_manifest_digest": _digest(source_manifest_digest, "source_manifest_digest"),
                "capability_manifest_digest": _digest(capability_manifest_digest, "capability_manifest_digest"),
                "benchmark_manifest_digest": _digest(benchmark_manifest_digest, "benchmark_manifest_digest"),
                "generation_digest": _digest(generation_digest, "generation_digest"),
                "checkpoint_digest": _digest(checkpoint_digest, "checkpoint_digest"),
                "route_version": _text(route_version, "route_version", maximum=64),
                "capability_epoch": _epoch(capability_epoch, "capability_epoch"),
                "visibility": _text(visibility, "visibility", maximum=64),
                "pre_mutation_rollback_receipt_digest": _digest(
                    pre_mutation_rollback_receipt_digest,
                    "pre_mutation_rollback_receipt_digest",
                ),
            }
            if any(supplied[key] != getattr(anchor, key) for key in supplied):
                raise RouteAuthorityError("route preflight does not match the trusted authority anchor")

    def bind_switch_output(
        self,
        *,
        output_path: str | Path,
        runbook_digest: str,
        cutover_decision_digest: str,
        cohort_manifest_digest: str,
        target: str,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt_digest: str,
    ) -> RouteSwitchReceiptV1 | None:
        """Bind the one permitted switch output before mutation.

        The adapter's configured state path *is* the requested switch receipt
        path.  A recovered matching bundle is returned for a crash/retry; a
        foreign collision never becomes a route mutation.
        """
        output = self._validate_output_path(output_path)
        self.validate_preflight(
            runbook_digest=runbook_digest,
            cutover_decision_digest=cutover_decision_digest,
            cohort_manifest_digest=cohort_manifest_digest,
            target=target,
            resolved_scope_digest=resolved_scope_digest,
            contract_digest=contract_digest,
            source_manifest_digest=source_manifest_digest,
            capability_manifest_digest=capability_manifest_digest,
            benchmark_manifest_digest=benchmark_manifest_digest,
            generation_digest=generation_digest,
            checkpoint_digest=checkpoint_digest,
            route_version=route_version,
            capability_epoch=capability_epoch,
            visibility=visibility,
            pre_mutation_rollback_receipt_digest=pre_mutation_rollback_receipt_digest,
        )
        with self._locked():
            state, receipt = self._read_state()
            anchor = self._require_trusted_head(state)
            if state is not None and receipt is not None:
                if (
                    receipt.cohort_manifest_digest == cohort_manifest_digest
                    and receipt.cutover_decision_digest == cutover_decision_digest
                    and receipt.target == target
                    and receipt.resolved_scope_digest == resolved_scope_digest
                    and receipt.contract_digest == contract_digest
                    and receipt.source_manifest_digest == source_manifest_digest
                    and receipt.capability_manifest_digest == capability_manifest_digest
                    and receipt.benchmark_manifest_digest == benchmark_manifest_digest
                    and receipt.generation_digest == generation_digest
                    and receipt.checkpoint_digest == checkpoint_digest
                    and receipt.route_version == route_version
                    and receipt.capability_epoch == capability_epoch
                    and receipt.visibility == visibility
                    and receipt.pre_mutation_rollback_receipt_digest == pre_mutation_rollback_receipt_digest
                    and anchor.runbook_digest == runbook_digest
                ):
                    return receipt
                raise RouteAuthorityError("route output collision contains a different canonical transaction")
            try:
                output.lstat()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise RouteAuthorityError("route output cannot be inspected") from exc
            else:
                raise RouteAuthorityError("route output already exists; refuse collision")
            if self._switch_output_bound:
                raise RouteAuthorityError("route output was already bound for this authority instance")
            self._switch_output_bound = True
            return None

    def load_canonical_switch_receipt(self, *, receipt_path: str | Path) -> RouteSwitchReceiptV1:
        """Read the signed canonical bundle at the configured switch receipt path."""
        self._validate_output_path(receipt_path)
        with self._locked():
            state, receipt = self._read_state()
            self._require_trusted_head(state)
            if state is None or receipt is None:
                raise RouteAuthorityError("canonical switch receipt is missing")
            return receipt

    def switch_atomic(
        self,
        *,
        cohort_manifest: MigrationCohortManifestV1,
        resolved_scope_digest: str,
        contract_digest: str,
        source_manifest_digest: str,
        capability_manifest_digest: str,
        benchmark_manifest_digest: str,
        generation_digest: str,
        checkpoint_digest: str,
        route_version: str,
        capability_epoch: str,
        visibility: str,
        pre_mutation_rollback_receipt: str,
    ) -> RouteSwitchReceiptV1:
        """Commit every active route pin and its receipt in exactly one state write."""
        if not isinstance(cohort_manifest, MigrationCohortManifestV1):
            raise RouteAuthorityError("typed cohort manifest is required")
        with self._locked():
            state, _ = self._read_state()
            anchor = self._require_trusted_head(state)
            if not self._switch_output_bound:
                raise RouteAuthorityError("switch output must be bound before canonical mutation")
            if state is not None:
                raise RouteAuthorityError("canonical route state already exists; rollback is closed")
            if cohort_manifest.cohort_state != "CUTOVER_READY":
                raise RouteAuthorityError("cohort must be CUTOVER_READY before canonical mutation")
            values = {
                "resolved_scope_digest": _digest(resolved_scope_digest, "resolved_scope_digest"),
                "contract_digest": _digest(contract_digest, "contract_digest"),
                "source_manifest_digest": _digest(source_manifest_digest, "source_manifest_digest"),
                "capability_manifest_digest": _digest(capability_manifest_digest, "capability_manifest_digest"),
                "benchmark_manifest_digest": _digest(benchmark_manifest_digest, "benchmark_manifest_digest"),
                "generation_digest": _digest(generation_digest, "generation_digest"),
                "checkpoint_digest": _digest(checkpoint_digest, "checkpoint_digest"),
                "route_version": _text(route_version, "route_version", maximum=64),
                "capability_epoch": _epoch(capability_epoch, "capability_epoch"),
                "visibility": _text(visibility, "visibility", maximum=64),
                "pre_mutation_rollback_receipt": _digest(pre_mutation_rollback_receipt, "pre_mutation_rollback_receipt"),
            }
            if (
                cohort_manifest.manifest_digest != anchor.cohort_manifest_digest
                or values["resolved_scope_digest"] != anchor.resolved_scope_digest
                or values["contract_digest"] != anchor.contract_digest
                or values["source_manifest_digest"] != anchor.source_manifest_digest
                or values["capability_manifest_digest"] != anchor.capability_manifest_digest
                or values["benchmark_manifest_digest"] != anchor.benchmark_manifest_digest
                or values["generation_digest"] != anchor.generation_digest
                or values["checkpoint_digest"] != anchor.checkpoint_digest
                or values["route_version"] != anchor.route_version
                or values["capability_epoch"] != anchor.capability_epoch
                or values["visibility"] != anchor.visibility
                or values["pre_mutation_rollback_receipt"] != anchor.pre_mutation_rollback_receipt_digest
            ):
                raise RouteAuthorityError("route transaction does not match the trusted authority anchor")
            raw_state = {
                "state_version": ROUTE_AUTHORITY_STATE_VERSION,
                "route_authority": self._authority,
                "cohort_manifest_digest": cohort_manifest.manifest_digest,
                "cutover_decision_digest": anchor.cutover_decision_digest,
                "target": anchor.target,
                "resolved_scope_digest": values["resolved_scope_digest"],
                "contract_digest": values["contract_digest"],
                "source_manifest_digest": values["source_manifest_digest"],
                "capability_manifest_digest": values["capability_manifest_digest"],
                "benchmark_manifest_digest": values["benchmark_manifest_digest"],
                "generation_digest": values["generation_digest"],
                "checkpoint_digest": values["checkpoint_digest"],
                "route_version": values["route_version"],
                "capability_epoch": values["capability_epoch"],
                "visibility": values["visibility"],
                "pre_mutation_rollback_receipt_digest": values["pre_mutation_rollback_receipt"],
                "state": "CANONICAL_MUTATED",
                "authority_revision": "1",
                "prior_state_digest": None,
            }
            raw_state["state_digest"] = sha256(canonical_bytes({
                "domain": ROUTE_AUTHORITY_STATE_VERSION,
                "body": raw_state,
            })).hexdigest()
            state = RouteAuthorityStateV1.from_mapping(raw_state)
            receipt = RouteSwitchReceiptV1.create(
                operation="SWITCH_ATOMIC", state="CANONICAL_MUTATED",
                route_authority=self._authority, cohort_manifest_digest=state.cohort_manifest_digest,
                cutover_decision_digest=state.cutover_decision_digest, target=state.target,
                resolved_scope_digest=state.resolved_scope_digest, contract_digest=state.contract_digest,
                source_manifest_digest=state.source_manifest_digest,
                capability_manifest_digest=state.capability_manifest_digest,
                benchmark_manifest_digest=state.benchmark_manifest_digest,
                generation_digest=state.generation_digest, checkpoint_digest=state.checkpoint_digest,
                route_version=state.route_version, capability_epoch=state.capability_epoch,
                visibility=state.visibility,
                pre_mutation_rollback_receipt_digest=state.pre_mutation_rollback_receipt_digest,
                route_state_digest=state.state_digest, authority_revision=state.authority_revision,
            )
            self._write_state(state, receipt)
            self._trusted_head = (state.authority_revision, state.state_digest)
            return receipt

    def verify_atomic(self, *, receipt: RouteSwitchReceiptV1) -> RouteSwitchReceiptV1:
        """Independently re-read the signed canonical state and switch receipt."""
        if not isinstance(receipt, RouteSwitchReceiptV1) or receipt.operation != "SWITCH_ATOMIC":
            raise RouteAuthorityError("canonical switch receipt is required for postcheck")
        with self._locked():
            state, stored = self._read_state()
            anchor = self._require_trusted_head(state)
            if state is None or stored is None or stored.to_mapping() != receipt.to_mapping():
                raise RouteAuthorityError("canonical route state or switch receipt mismatch")
            if (
                state.cohort_manifest_digest != receipt.cohort_manifest_digest
                or state.cutover_decision_digest != anchor.cutover_decision_digest
                or state.target != anchor.target
                or state.state_digest != receipt.route_state_digest
                or state.cohort_manifest_digest != anchor.cohort_manifest_digest
                or state.resolved_scope_digest != anchor.resolved_scope_digest
                or state.contract_digest != anchor.contract_digest
                or state.source_manifest_digest != anchor.source_manifest_digest
                or state.capability_manifest_digest != anchor.capability_manifest_digest
                or state.benchmark_manifest_digest != anchor.benchmark_manifest_digest
                or state.generation_digest != anchor.generation_digest
                or state.checkpoint_digest != anchor.checkpoint_digest
                or state.route_version != anchor.route_version
                or state.capability_epoch != anchor.capability_epoch
                or state.visibility != anchor.visibility
                or state.pre_mutation_rollback_receipt_digest != anchor.pre_mutation_rollback_receipt_digest
            ):
                raise RouteAuthorityError("canonical route state binding mismatch")
            return RouteSwitchReceiptV1.create(
                operation="VERIFY", state="CANONICAL_MUTATED",
                route_authority=receipt.route_authority,
                cohort_manifest_digest=receipt.cohort_manifest_digest,
                cutover_decision_digest=receipt.cutover_decision_digest,
                target=receipt.target, resolved_scope_digest=receipt.resolved_scope_digest,
                contract_digest=receipt.contract_digest,
                source_manifest_digest=receipt.source_manifest_digest,
                capability_manifest_digest=receipt.capability_manifest_digest,
                benchmark_manifest_digest=receipt.benchmark_manifest_digest,
                generation_digest=receipt.generation_digest,
                checkpoint_digest=receipt.checkpoint_digest,
                route_version=receipt.route_version, capability_epoch=receipt.capability_epoch,
                visibility=receipt.visibility,
                pre_mutation_rollback_receipt_digest=receipt.pre_mutation_rollback_receipt_digest,
                route_state_digest=receipt.route_state_digest,
                authority_revision=receipt.authority_revision,
            )

    def external_rollback(self) -> None:
        """There is intentionally no post-mutation rollback operation."""
        with self._locked():
            state, _ = self._read_state()
            self._require_trusted_head(state)
            if state is not None:
                raise RouteAuthorityError("external rollback is closed after canonical mutation")
            raise RouteAuthorityError("external rollback is not implemented by route authority")


def mint_route_authority_anchor(
    *,
    route_authority: str,
    runbook_digest: str,
    cutover_decision_digest: str,
    cohort_manifest_digest: str,
    target: str,
    resolved_scope_digest: str,
    contract_digest: str,
    source_manifest_digest: str,
    capability_manifest_digest: str,
    benchmark_manifest_digest: str,
    generation_digest: str,
    checkpoint_digest: str,
    route_version: str,
    capability_epoch: str,
    visibility: str,
    pre_mutation_rollback_receipt_digest: str,
    state_revision: str,
    state_digest: str,
    signing_key: Ed25519PrivateKey,
) -> RouteAuthorityDeploymentAnchorV1:
    """Deployment/test helper; production injection controls this signing key."""
    if not isinstance(signing_key, Ed25519PrivateKey):
        raise RouteAuthorityError("route authority signing key is invalid")
    unsigned = {
        "anchor_version": ROUTE_AUTHORITY_ANCHOR_VERSION,
        "route_authority": route_authority,
        "runbook_digest": runbook_digest,
        "cutover_decision_digest": cutover_decision_digest,
        "cohort_manifest_digest": cohort_manifest_digest,
        "target": target,
        "resolved_scope_digest": resolved_scope_digest,
        "contract_digest": contract_digest,
        "source_manifest_digest": source_manifest_digest,
        "capability_manifest_digest": capability_manifest_digest,
        "benchmark_manifest_digest": benchmark_manifest_digest,
        "generation_digest": generation_digest,
        "checkpoint_digest": checkpoint_digest,
        "route_version": route_version,
        "capability_epoch": capability_epoch,
        "visibility": visibility,
        "pre_mutation_rollback_receipt_digest": pre_mutation_rollback_receipt_digest,
        "state_revision": state_revision,
        "state_digest": state_digest,
        "signer_fingerprint": _fingerprint(signing_key.public_key()),
    }
    parsed = RouteAuthorityDeploymentAnchorV1.from_mapping(
        unsigned | {"signature": signing_key.sign(_ANCHOR_DOMAIN + canonical_bytes(unsigned)).hex()}
    )
    return parsed


__all__ = [
    "DeploymentRouteSwitchAuthority",
    "RouteAuthorityDeploymentAnchorV1",
    "RouteAuthorityError",
    "ROUTE_AUTHORITY_ANCHOR_VERSION",
    "ROUTE_AUTHORITY_FILE_SCHEMA",
    "mint_route_authority_anchor",
]
