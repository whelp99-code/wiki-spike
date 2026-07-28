"""Fixture-only credential broker with fail-closed, opaque leases."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from wiki_spike.memory_core.second_brain_capabilities import ConsumptionReceipt


class CredentialDenied(PermissionError):
    """Credential use was denied before a resolver or consumer was invoked."""


@dataclass(frozen=True)
class OpaqueCredentialLease:
    credential_ref: str
    lease_id: str
    expires_at: str


class FixtureCredentialResolver:
    """Test-only one-shot mutable secret buffers, zeroized immediately after use."""
    def __init__(self, fixtures: Mapping[str, bytes | bytearray]) -> None:
        self._fixtures = {ref: bytearray(value) for ref, value in fixtures.items()}

    def consume(self, credential_ref: str, consumer: Callable[[memoryview], None]) -> None:
        secret = self._fixtures.pop(credential_ref, None)
        if secret is None: raise CredentialDenied("credential fixture is unavailable")
        try:
            consumer(memoryview(secret))
        finally:
            secret[:] = b"\0" * len(secret)


class _CredentialConsumer(Protocol):
    def __call__(self, lease: OpaqueCredentialLease, secret: memoryview) -> None: ...


class LocalCredentialBroker:
    """Redeems only store-minted capability consumption receipts exactly once."""
    def __init__(self, policy: Mapping[str, Any] | str | Path, *, capability_store: object, resolver: FixtureCredentialResolver | None = None, consumer: _CredentialConsumer | None = None, now: Callable[[], datetime] | None = None) -> None:
        self._policy, self._disabled_credentials = self._load_policy(policy)
        self._capability_store, self._resolver, self._consumer = capability_store, resolver, consumer
        self._now = now or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _load_policy(policy: Mapping[str, Any] | str | Path) -> tuple[dict[str, dict[str, str]], frozenset[str]]:
        raw: Any = json.loads(Path(policy).read_text(encoding="utf-8")) if isinstance(policy, (str, Path)) else dict(policy)
        if raw.get("version") != "credential-policy-v1" or set(raw) != {"version", "credentials", "disabled_credential_refs"}: raise CredentialDenied("credential policy is invalid")
        credentials, disabled = raw["credentials"], raw["disabled_credential_refs"]
        if not isinstance(credentials, list) or not isinstance(disabled, list) or any(not isinstance(ref, str) or not ref for ref in disabled): raise CredentialDenied("credential policy is invalid")
        required = {"credential_ref", "source_ref", "route_ref", "credential_class", "action", "device_key_ref", "expires_at"}; parsed: dict[str, dict[str, str]] = {}
        for entry in credentials:
            if not isinstance(entry, Mapping) or set(entry) != required or not all(isinstance(entry[key], str) and entry[key] for key in required): raise CredentialDenied("credential policy is invalid")
            if entry["credential_ref"] in parsed: raise CredentialDenied("credential policy has duplicate credential refs")
            parsed[entry["credential_ref"]] = dict(entry)
        return parsed, frozenset(disabled)

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try: return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (TypeError, ValueError) as error: raise CredentialDenied("credential binding expiry is invalid") from error

    def lease(self, receipt: ConsumptionReceipt) -> OpaqueCredentialLease:
        """Redeem an exact one-time receipt before exposing a fixture secret."""
        if not isinstance(receipt, ConsumptionReceipt): raise CredentialDenied("a store-minted ConsumptionReceipt is required")
        evidence = self._capability_store.redeem_consumption_receipt(receipt)
        if evidence is None: raise CredentialDenied("consumption receipt is invalid, cross-store, or replayed")
        current = self._now().astimezone(timezone.utc)
        if self._timestamp(evidence.expires_at) <= current: raise CredentialDenied("capability is expired")
        policy = self._policy.get(evidence.credential_ref)
        if policy is None or evidence.credential_ref in self._disabled_credentials: raise CredentialDenied("credential scope is unresolved or disabled")
        if self._timestamp(policy["expires_at"]) <= current: raise CredentialDenied("credential policy is expired")
        if evidence.action != policy["action"] or evidence.device_key_ref != policy["device_key_ref"]: raise CredentialDenied("capability binding does not match credential policy")
        if self._resolver is None or self._consumer is None: raise CredentialDenied("platform credential backend is unavailable")
        lease = OpaqueCredentialLease(evidence.credential_ref, uuid4().hex, min(evidence.expires_at, policy["expires_at"]))
        self._resolver.consume(evidence.credential_ref, lambda secret: self._consumer(lease, secret))
        return lease
