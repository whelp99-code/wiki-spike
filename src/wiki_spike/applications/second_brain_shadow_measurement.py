"""Non-serving, authenticated native shadow-measurement evidence collector.

The local journal is a replay cache, never rollback authority.  An independently
operated monotonic authority is required for every cohort; its identity is bound
into the signed cohort root.  The collector only reads local journal frames
during recovery and never truncates or repairs them in place.
"""
from __future__ import annotations

import fcntl
import json
import math
import os
from dataclasses import dataclass
from secrets import token_hex
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, Protocol
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wiki_spike.memory_core.second_brain_contracts import ResolvedScopeV1
from wiki_spike.memory_core.second_brain_evaluation_contracts import (
    BenchmarkManifestV1, HoldoutManifestV1, NATIVE_SHADOW_OUTCOMES,
    NATIVE_SHADOW_SAMPLE_V1, NATIVE_SHADOW_SOURCES, RecallSloV1,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_bytes

DOMAIN = "second-brain-native-shadow-sample-v1"
_COHORT_DOMAIN = "second-brain-native-shadow-cohort-v1"
_CHAIN_DOMAIN = "second-brain-native-shadow-chain-v1"
_STORAGE_VERSION = "second-brain-native-shadow-journal-v4"
_AUTHORITY_DOMAIN = "second-brain-native-shadow-authority-v1"
_MAX_INTERVAL_SECONDS = 3600


class ShadowMeasurementError(RuntimeError):
    """Evidence is untrusted, discontinuous, or insufficient."""
@dataclass(frozen=True, slots=True)
class AuthoritySnapshot:
    """Cryptographically authenticated, retained authority receipt.

    ``signature`` authenticates every other field using ``_AUTHORITY_DOMAIN``.
    ``root`` is the SHA-256 digest of the canonical retained event sequence.
    """
    identity: str
    endpoint: str
    policy_id: str
    public_key_fingerprint: str
    revision: int
    root: str
    request_nonce: str
    issued_at: str
    expires_at: str
    events: tuple[Mapping[str, Any], ...]
    signature: str

    def payload(self) -> dict[str, Any]:
        return {"identity": self.identity, "endpoint": self.endpoint,
                "policy_id": self.policy_id, "public_key_fingerprint": self.public_key_fingerprint,
                "revision": self.revision, "root": self.root,
                "request_nonce": self.request_nonce, "issued_at": self.issued_at,
                "expires_at": self.expires_at, "events": [dict(event) for event in self.events]}


class MonotonicAppendAuthority(Protocol):
    """Operator-bound external authority; local cache is never authoritative."""
    @property
    def identity(self) -> str: ...
    @property
    def endpoint(self) -> str: ...
    @property
    def policy_id(self) -> str: ...
    @property
    def public_key(self) -> Ed25519PublicKey: ...
    def snapshot(self, *, request_nonce: str) -> AuthoritySnapshot: ...
    def compare_and_advance(self, *, expected_revision: int, event: Mapping[str, Any], request_nonce: str) -> AuthoritySnapshot: ...


@dataclass(frozen=True, slots=True)
class ShadowMeasurementReport:
    outcome: str
    cohort_digest: str
    sample_count: int
    continuous_seconds: int
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _HistoryMetrics:
    """Pure, non-authoritative measurements used by the test matrix."""

    cohort_digest: str
    sample_count: int
    continuous_seconds: int
    reasons: tuple[str, ...]

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _instant(value: datetime | str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ShadowMeasurementError("timestamp is invalid") from exc
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ShadowMeasurementError("timestamp must be an aware datetime")
    return value.astimezone(timezone.utc)


def _stamp(value: datetime) -> str:
    return _instant(value).isoformat().replace("+00:00", "Z")


def _hex(value: Any, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ShadowMeasurementError(f"{field} must be a sha256 digest")
    return value


def _scope_digest(scope: ResolvedScopeV1) -> str:
    return sha256(canonical_ledger_bytes("resolved-scope-v1", scope.to_mapping())).hexdigest()


def _wilson_lower(successes: int, total: int) -> float:
    if total <= 0:
        return 0.0
    z = 1.6448536269514722
    p = successes / total
    denominator = 1 + z * z / total
    return (p + z * z / (2 * total) - z * math.sqrt((p * (1 - p) + z * z / (4 * total)) / total)) / denominator


def _evaluate_history_metrics(*, root: Mapping[str, Any],
                              entries: list[Mapping[str, Any]],
                              slo: RecallSloV1, evaluated_at: datetime) -> _HistoryMetrics:
    """Calculate metrics/reasons only; this seam never creates an outcome."""
    samples = [entry["sample"] for entry in entries]
    reasons: list[str] = []
    duration = 0 if len(entries) < 2 else int((_instant(entries[-1]["recorded_at"]) - _instant(entries[0]["recorded_at"])).total_seconds())
    if evaluated_at < _instant(root["started_at"]) or int((evaluated_at - _instant(root["started_at"])).total_seconds()) < slo.min_shadow_days * 86400:
        reasons.append("system wall-clock cohort age is below the required duration")
    if duration < slo.min_shadow_days * 86400:
        reasons.append("continuous measurement is below the required duration")
    if len(samples) < slo.min_cohort_e2e_queries:
        reasons.append("cohort E2E denominator is below its floor")
    if sum(sample["safety_violation"] for sample in samples) > slo.max_safety_violations:
        reasons.append("safety violations exceed zero")
    valid = lambda sample: sample["outcome"] == "valid"
    for source in NATIVE_SHADOW_SOURCES:
        source_samples = [sample for sample in samples if sample["source_profile"] == source]
        if len(source_samples) < slo.min_parity_cases_per_source:
            reasons.append(f"{source} parity denominator is below its floor")
        elif _wilson_lower(sum(valid(s) and s["parity"] for s in source_samples), len(source_samples)) * 10000 < slo.parity_min_bps:
            reasons.append(f"{source} parity lower bound failed")
    for name, threshold, predicate in (("citation", slo.citation_min_bps, lambda s: s["citation"]), ("completeness", slo.completeness_min_bps, lambda s: s["completeness"]), ("availability", slo.availability_min_bps, lambda s: True)):
        if _wilson_lower(sum(valid(s) and predicate(s) for s in samples), len(samples)) * 10000 < threshold:
            reasons.append(f"{name} lower bound failed")
    cohort = sha256(canonical_ledger_bytes(_COHORT_DOMAIN, root)).hexdigest()
    return _HistoryMetrics(cohort, len(samples), duration, tuple(reasons))


class NativeShadowMeasurementCollector:
    """A non-serving journal backed by a separately retained append authority."""

    def __init__(self, *, path: str | Path, authority: MonotonicAppendAuthority,
                 scope: ResolvedScopeV1, benchmark: BenchmarkManifestV1,
                 holdout: HoldoutManifestV1, slo: RecallSloV1,
                 measurement_public_key: Ed25519PublicKey, measurement_key_id: str) -> None:
        if tuple(sorted(scope.enabled_source_profiles)) != tuple(sorted(NATIVE_SHADOW_SOURCES)) or len(scope.enabled_source_profiles) != 4:
            raise ShadowMeasurementError("native measurement requires the exact four-source roster")
        if scope.enabled_migration_sources or scope.enabled_external_model_routes or scope.egress_destinations:
            raise ShadowMeasurementError("migration, external routes, and egress are forbidden")
        if not measurement_key_id:
            raise ShadowMeasurementError("measurement identity is required")
        try:
            authority_identity = authority.identity
            authority_endpoint = authority.endpoint
            authority_policy_id = authority.policy_id
            authority_key_bytes = authority.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        except (AttributeError, TypeError, ValueError) as exc:
            raise ShadowMeasurementError("external authority pins are invalid") from exc
        if not all(isinstance(value, str) and value for value in (
            authority_identity, authority_endpoint, authority_policy_id,
        )):
            raise ShadowMeasurementError("external authority pins are invalid")
        try:
            authority_public_key = Ed25519PublicKey.from_public_bytes(authority_key_bytes)
        except (TypeError, ValueError) as exc:
            raise ShadowMeasurementError("external authority public key is invalid") from exc
        self.path, self.authority = Path(path), authority
        self.scope, self.benchmark, self.holdout, self.slo = scope, benchmark, holdout, slo
        self.public_key, self.key_id = measurement_public_key, measurement_key_id
        self._authority_identity = authority_identity
        self._authority_endpoint = authority_endpoint
        self._authority_policy_id = authority_policy_id
        self._authority_public_key = authority_public_key
        self._authority_public_key_fingerprint = sha256(authority_key_bytes).hexdigest()
        self._base_root = {"scope_digest": _scope_digest(scope), "benchmark_manifest_digest": benchmark.manifest_digest,
            "holdout_manifest_digest": holdout.manifest_digest, "slo_digest": slo.slo_digest,
            "source_manifest_digest": scope.source_manifest_digest, "capability_manifest_digest": scope.capability_manifest_digest,
            "sources": list(NATIVE_SHADOW_SOURCES), "measurement_key_id": measurement_key_id,
            "measurement_public_key": measurement_public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
            "authority_identity": self._authority_identity, "authority_endpoint": self._authority_endpoint,
            "authority_policy_id": self._authority_policy_id,
            "authority_public_key_fingerprint": self._authority_public_key_fingerprint}
        self._state: dict[str, Any] | None = None
        snapshot = self._snapshot()
        if snapshot.events:
            with self._locked():
                self._state = self._load_verified(recover=True)
        elif self._segments_path.exists() and any(self._segments_path.iterdir()):
            raise ShadowMeasurementError("measurement journal exists without retained authority")

    @property
    def cohort_digest(self) -> str:
        return sha256(canonical_ledger_bytes(_COHORT_DOMAIN, self._require_state()["root"])).hexdigest()


    @property
    def _lock_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".lock")

    def _locked(self):
        created = not self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if created:
            self._fsync_directory(self.path.parent.parent)
        handle = self._lock_path.open("a+")
        class Lock:
            def __enter__(_self): fcntl.flock(handle.fileno(), fcntl.LOCK_EX); return _self
            def __exit__(_self, *args): fcntl.flock(handle.fileno(), fcntl.LOCK_UN); handle.close()
        return Lock()

    def checkpoint_payload(self, *, cohort_id: str, started_at: datetime | str, anchor_root: str) -> dict[str, Any]:
        try: UUID(cohort_id)
        except (ValueError, TypeError, AttributeError) as exc: raise ShadowMeasurementError("cohort_id must be a UUID") from exc
        start = _instant(started_at)
        if start > _now(): raise ShadowMeasurementError("cohort start cannot be in the future")
        return self._base_root | {"cohort_id": cohort_id, "started_at": _stamp(start), "anchor_root": _hex(anchor_root, "anchor_root")}

    def establish_checkpoint(self, *, cohort_id: str, started_at: datetime | str, anchor_root: str, root_signature: str) -> None:
        root = self.checkpoint_payload(cohort_id=cohort_id, started_at=started_at, anchor_root=anchor_root)
        try: self.public_key.verify(bytes.fromhex(root_signature), canonical_ledger_bytes(_COHORT_DOMAIN, root))
        except (InvalidSignature, ValueError, TypeError) as exc: raise ShadowMeasurementError("cohort checkpoint signature is invalid") from exc
        with self._locked():
            if self._snapshot().events:
                raise ShadowMeasurementError("cohort checkpoint already exists")
            event = {"kind": "checkpoint", "storage_version": _STORAGE_VERSION, "root": root, "root_signature": root_signature}
            self._commit(event)
            self._state = self._state_from_events([event])

    def _require_state(self) -> dict[str, Any]:
        if self._state is None: raise ShadowMeasurementError("measurement cohort requires an authenticated checkpoint")
        return self._state

    @staticmethod
    def _line(event: Mapping[str, Any]) -> bytes:
        payload = json.dumps(event, sort_keys=True, separators=(",", ":")).encode()
        return f"{len(payload):08x}:".encode("ascii") + payload + b"\n"

    def _read_events(self, path: Path, *, recover_tail: bool) -> list[dict[str, Any]]:
        try: raw = path.read_bytes()
        except OSError as exc: raise ShadowMeasurementError("measurement journal is unreadable") from exc
        events: list[dict[str, Any]] = []
        offset = 0
        while offset < len(raw):
            frame_start = offset
            if len(raw) - offset < 9:
                if recover_tail:
                    self._quarantine_tail(path, raw[frame_start:])
                    break
                raise ShadowMeasurementError("measurement journal has an incomplete frame")
            header = raw[offset:offset + 9]
            try:
                size = int(header[:8], 16)
            except ValueError as exc:
                raise ShadowMeasurementError("measurement journal frame header is malformed") from exc
            if header[8:9] != b":" or size < 2 or len(raw) - offset < 10 + size:
                if recover_tail and len(raw) - offset < 10 + size:
                    self._quarantine_tail(path, raw[frame_start:])
                    break
                raise ShadowMeasurementError("measurement journal frame is malformed")
            payload = raw[offset + 9:offset + 9 + size]
            if raw[offset + 9 + size:offset + 10 + size] != b"\n":
                raise ShadowMeasurementError("measurement journal frame terminator is malformed")
            try: event = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc: raise ShadowMeasurementError("measurement journal is malformed") from exc
            if not isinstance(event, dict): raise ShadowMeasurementError("measurement journal event is malformed")
            events.append(event)
            offset += 10 + size
        return events

    def _append_durable(self, path: Path, event: Mapping[str, Any]) -> None:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            payload = self._line(event); offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0: raise OSError("short journal write")
                offset += written
            os.fsync(descriptor)
        finally: os.close(descriptor)
    def _assert_authority_pins(self) -> None:
        """Reject a live adapter whose construction-time trust pins have rotated."""
        try:
            live_key = self.authority.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            live_pins = (
                self.authority.identity, self.authority.endpoint, self.authority.policy_id,
                sha256(live_key).hexdigest(),
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise ShadowMeasurementError("external authority pins are unreadable") from exc
        if live_pins != (
            self._authority_identity, self._authority_endpoint, self._authority_policy_id,
            self._authority_public_key_fingerprint,
        ):
            raise ShadowMeasurementError("external authority pins changed")


    def _verify_authority_receipt(self, receipt: Any, *, nonce: str,
                                  previous: AuthoritySnapshot | None = None,
                                  expected_event: Mapping[str, Any] | None = None) -> AuthoritySnapshot:
        """Authenticate a pinned authority receipt before it enters the local cache."""
        try:
            if not isinstance(receipt, AuthoritySnapshot) or receipt.request_nonce != nonce:
                raise ShadowMeasurementError("authority receipt nonce is invalid or replayed")
            if (receipt.identity != self._authority_identity
                    or receipt.endpoint != self._authority_endpoint
                    or receipt.policy_id != self._authority_policy_id
                    or receipt.public_key_fingerprint != self._authority_public_key_fingerprint):
                raise ShadowMeasurementError("authority receipt identity, endpoint, policy, or key mismatch")
            if type(receipt.revision) is not int or receipt.revision < 0 or len(receipt.events) != receipt.revision:
                raise ShadowMeasurementError("authority receipt revision is invalid")
            root = sha256(canonical_ledger_bytes(
                _AUTHORITY_DOMAIN, {"events": [dict(event) for event in receipt.events]}
            )).hexdigest()
            if receipt.root != root:
                raise ShadowMeasurementError("authority receipt root is invalid")
            issued, expires, now = _instant(receipt.issued_at), _instant(receipt.expires_at), _now()
            if expires <= issued or now < issued or now >= expires:
                raise ShadowMeasurementError("authority receipt is stale")
            self._authority_public_key.verify(bytes.fromhex(receipt.signature), canonical_ledger_bytes(_AUTHORITY_DOMAIN, receipt.payload()))
            if previous is not None:
                if receipt.revision < previous.revision or (receipt.revision == previous.revision and receipt.root != previous.root):
                    raise ShadowMeasurementError("authority receipt rollback detected")
                if expected_event is not None:
                    if (receipt.revision != previous.revision + 1
                            or tuple(receipt.events[:-1]) != tuple(previous.events)
                            or dict(receipt.events[-1]) != dict(expected_event)):
                        raise ShadowMeasurementError("external authority failed atomic monotonic advance")
            return receipt
        except (InvalidSignature, ValueError, TypeError, AttributeError, IndexError) as exc:
            if isinstance(exc, ShadowMeasurementError):
                raise
            raise ShadowMeasurementError("authority receipt authentication is invalid") from exc

    def _snapshot(self) -> AuthoritySnapshot:
        self._assert_authority_pins()
        nonce = token_hex(32)
        snapshot = self.authority.snapshot(request_nonce=nonce)
        self._assert_authority_pins()
        verified = self._verify_authority_receipt(
            snapshot, nonce=nonce, previous=getattr(self, "_authority_receipt", None)
        )
        self._authority_receipt = verified
        return verified

    def _commit(self, event: Mapping[str, Any]) -> None:
        before = self._snapshot()
        self._assert_authority_pins()
        nonce = token_hex(32)
        advanced = self.authority.compare_and_advance(expected_revision=before.revision, event=event, request_nonce=nonce)
        self._assert_authority_pins()
        verified = self._verify_authority_receipt(
            advanced, nonce=nonce, previous=before, expected_event=event
        )
        self._authority_receipt = verified
        self._append_segment(verified.revision, event)


    @property
    def _segments_path(self) -> Path:
        return self.path.with_suffix(self.path.suffix + ".segments")

    def _append_segment(self, revision: int, event: Mapping[str, Any]) -> None:
        created = not self._segments_path.exists()
        self._segments_path.mkdir(parents=True, exist_ok=True)
        if created:
            self._fsync_parent_directory()
        target = self._segments_path / f"{revision:020d}.frame"
        payload = self._line(event)
        try:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            if target.read_bytes() != payload:
                raise ShadowMeasurementError("immutable journal segment conflicts with authority")
            return
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("short journal write")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_segments_directory()

    def _quarantine_tail(self, path: Path, tail: bytes) -> None:
        """Seal a torn segment outside the reachable segment namespace."""
        quarantine = path.with_suffix(path.suffix + ".incomplete")
        if quarantine.exists():
            quarantine = path.with_suffix(path.suffix + f".{token_hex(8)}.incomplete")
        try:
            os.replace(path, quarantine)
        except OSError as exc:
            raise ShadowMeasurementError("incomplete journal segment cannot be quarantined") from exc
        self._fsync_segments_directory()

    def _load_verified(self, *, recover: bool) -> dict[str, Any]:
        snapshot = self._snapshot()
        authority = [dict(event) for event in snapshot.events]
        if not authority:
            raise ShadowMeasurementError("measurement authority is empty")
        journal: list[dict[str, Any]] = []
        if self._segments_path.exists():
            for index, segment in enumerate(sorted(self._segments_path.glob("*.frame")), 1):
                expected = self._segments_path / f"{index:020d}.frame"
                if segment != expected:
                    raise ShadowMeasurementError("journal segments are not contiguous")
                events = self._read_events(segment, recover_tail=recover)
                if len(events) != 1:
                    raise ShadowMeasurementError("journal segment must contain exactly one frame")
                journal.extend(events)
        if journal != authority[:len(journal)]:
            raise ShadowMeasurementError("measurement journal disagrees with retained authority")
        for revision, event in enumerate(authority[len(journal):], len(journal) + 1):
            self._append_segment(revision, event)
        state = self._state_from_events(authority)
        self._verify_state(state)
        return state

    def _state_from_events(self, events: list[Mapping[str, Any]]) -> dict[str, Any]:
        first = events[0] if events else None
        if not isinstance(first, Mapping) or set(first) != {"kind", "storage_version", "root", "root_signature"} or first["kind"] != "checkpoint" or first["storage_version"] != _STORAGE_VERSION:
            raise ShadowMeasurementError("measurement journal checkpoint is invalid")
        samples = []
        for event in events[1:]:
            if not isinstance(event, Mapping) or set(event) != {"kind", "entry"} or event["kind"] != "append": raise ShadowMeasurementError("measurement journal event schema is invalid")
            samples.append(event["entry"])
        return {"storage_version": _STORAGE_VERSION, "root": first["root"], "root_signature": first["root_signature"], "samples": samples, "chain_head": samples[-1]["digest"] if samples else None, "sample_count": len(samples)}

    def _verify_state(self, state: Any) -> None:
        fields = {"storage_version", "root", "root_signature", "samples", "chain_head", "sample_count"}
        if not isinstance(state, Mapping) or set(state) != fields or state["storage_version"] != _STORAGE_VERSION: raise ShadowMeasurementError("measurement state schema is invalid")
        root = state["root"]
        if not isinstance(root, Mapping) or set(root) != set(self._base_root) | {"cohort_id", "started_at", "anchor_root"}: raise ShadowMeasurementError("measurement root schema is invalid")
        if {k: root.get(k) for k in self._base_root} != self._base_root: raise ShadowMeasurementError("measurement state roots, contract, or identity do not match")
        try:
            UUID(root["cohort_id"]); start = _instant(root["started_at"]); _hex(root["anchor_root"], "anchor_root")
            self.public_key.verify(bytes.fromhex(state["root_signature"]), canonical_ledger_bytes(_COHORT_DOMAIN, dict(root)))
        except (InvalidSignature, ValueError, TypeError, KeyError) as exc: raise ShadowMeasurementError("measurement root authentication is invalid") from exc
        if start > _now(): raise ShadowMeasurementError("measurement root start is in the future")
        if not isinstance(state["samples"], list) or type(state["sample_count"]) is not int or state["sample_count"] != len(state["samples"]): raise ShadowMeasurementError("measurement sample list is invalid")
        self._verify_chain(state)

    def _verify_chain(self, state: Mapping[str, Any]) -> None:
        previous, last_recorded = None, None; cohort = sha256(canonical_ledger_bytes(_COHORT_DOMAIN, state["root"])).hexdigest()
        for sequence, entry in enumerate(state["samples"]):
            if not isinstance(entry, Mapping) or set(entry) != {"sample", "recorded_at", "previous", "digest"} or entry["previous"] != previous: raise ShadowMeasurementError("measurement chain is broken")
            if not isinstance(entry["sample"], Mapping): raise ShadowMeasurementError("measurement sample entry is invalid")
            self._validate_sample(entry["sample"], cohort=cohort, previous=previous, sequence=sequence)
            recorded = _instant(entry["recorded_at"])
            if last_recorded is not None and not 0 < (recorded-last_recorded).total_seconds() <= _MAX_INTERVAL_SECONDS: raise ShadowMeasurementError("measurement interval gap or clock rollback")
            digest = sha256(canonical_ledger_bytes(_CHAIN_DOMAIN, {"sample": dict(entry["sample"]), "recorded_at": _stamp(recorded), "previous": previous})).hexdigest()
            if entry["digest"] != digest: raise ShadowMeasurementError("measurement chain digest is invalid")
            previous, last_recorded = digest, recorded
        if state["chain_head"] != previous: raise ShadowMeasurementError("measurement chain head does not match")

    def _validate_sample(self, sample: Mapping[str, Any], *, cohort: str, previous: str | None, sequence: int) -> None:
        required = {"sample_version", "sample_id", "source_profile", "outcome", "citation", "completeness", "parity", "safety_violation", "cohort_digest", "previous", "sequence", "signature"}
        if not isinstance(sample, Mapping) or set(sample) != required or sample.get("sample_version") != NATIVE_SHADOW_SAMPLE_V1: raise ShadowMeasurementError("raw sample fields are invalid")
        if sample["cohort_digest"] != cohort or sample["previous"] != previous or sample["sequence"] != sequence: raise ShadowMeasurementError("raw sample is not bound to this cohort head")
        if sample["source_profile"] not in NATIVE_SHADOW_SOURCES or sample["outcome"] not in NATIVE_SHADOW_OUTCOMES: raise ShadowMeasurementError("raw sample source or outcome is unsupported")
        if not isinstance(sample["sample_id"], str) or not sample["sample_id"] or type(sample["sequence"]) is not int: raise ShadowMeasurementError("raw sample identity is invalid")
        if any(type(sample[field]) is not bool for field in ("citation", "completeness", "parity", "safety_violation")) or not isinstance(sample["signature"], str): raise ShadowMeasurementError("raw sample measures or signature are invalid")
        payload = {key: sample[key] for key in required - {"signature"}}
        try: self.public_key.verify(bytes.fromhex(sample["signature"]), canonical_ledger_bytes(DOMAIN, payload))
        except (InvalidSignature, ValueError) as exc: raise ShadowMeasurementError("raw sample signature is invalid") from exc

    def _fsync_parent_directory(self) -> None:
        self._fsync_directory(self.path.parent)

    def _fsync_segments_directory(self) -> None:
        self._fsync_directory(self._segments_path)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def append(self, sample: Mapping[str, Any]) -> None:
        with self._locked():
            state = self._load_verified(recover=True)
            previous, sequence = state["chain_head"], state["sample_count"]
            self._validate_sample(sample, cohort=sha256(canonical_ledger_bytes(_COHORT_DOMAIN, state["root"])).hexdigest(), previous=previous, sequence=sequence)
            if any(entry["sample"]["sample_id"] == sample["sample_id"] for entry in state["samples"]): raise ShadowMeasurementError("raw sample replay is forbidden")
            recorded = _now()
            if state["samples"] and not 0 < (recorded - _instant(state["samples"][-1]["recorded_at"])).total_seconds() <= _MAX_INTERVAL_SECONDS: raise ShadowMeasurementError("measurement interval gap or clock rollback; reset cohort")
            entry = {"sample": dict(sample), "recorded_at": _stamp(recorded), "previous": previous}
            entry["digest"] = sha256(canonical_ledger_bytes(_CHAIN_DOMAIN, entry)).hexdigest()
            self._commit({"kind": "append", "entry": entry})
            self._state = self._load_verified(recover=True)

    def report(self) -> ShadowMeasurementReport:
        with self._locked():
            state = self._load_verified(recover=True)
            self._state = state
            # Only the verified collector reads production wall-clock time and mints outcomes.
            metrics = _evaluate_history_metrics(
                root=state["root"], entries=state["samples"], slo=self.slo,
                evaluated_at=_now(),
            )
            return ShadowMeasurementReport(
                "EVIDENCE_COMPLETE_NON_SERVING" if not metrics.reasons else "NOT_READY",
                metrics.cohort_digest, metrics.sample_count,
                metrics.continuous_seconds, metrics.reasons,
            )


__all__ = ["AuthoritySnapshot", "MonotonicAppendAuthority", "NativeShadowMeasurementCollector", "ShadowMeasurementError", "ShadowMeasurementReport", "DOMAIN"]
