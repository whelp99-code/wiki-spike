"""Fixture-only credential broker with fail-closed, opaque leases.

This module deliberately has no platform credential-store, network, or source-client
integration.  A fixture resolver is injected by tests; production callers receive a
denial unless they provide an explicit backend.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4


class CredentialDenied(PermissionError):
    """Credential use was denied before a resolver or consumer was invoked."""


@dataclass(frozen=True)
class OpaqueCredentialLease:
    """Non-secret evidence that a fixture credential was used by its consumer."""

    credential_ref: str
    lease_id: str
    expires_at: str


@dataclass(frozen=True)
class ConsumedCredentialCapability:
    """One-time capability evidence supplied after the capability service consumed it."""

    capability_ref: str
    credential_ref: str
    source_ref: str
    route_ref: str
    credential_class: str
    action: str
    device_key_ref: str
    expires_at: str
    consumed: bool = True


class FixtureCredentialResolver:
    """Test-only resolver that exposes a mutable secret buffer only during consumption."""

    def __init__(self, fixtures: Mapping[str, bytes | bytearray]) -> None:
        self._fixtures = {ref: bytes(value) for ref, value in fixtures.items()}

    def consume(self, credential_ref: str, consumer: Callable[[memoryview], None]) -> None:
        secret = self._fixtures.get(credential_ref)
        if secret is None:
            raise CredentialDenied("credential fixture is unavailable")
        buffer = bytearray(secret)
        try:
            consumer(memoryview(buffer))
        finally:
            buffer[:] = b"\0" * len(buffer)


class _CredentialConsumer(Protocol):
    def __call__(self, lease: OpaqueCredentialLease, secret: memoryview) -> None: ...


class LocalCredentialBroker:
    """Binds a consumed capability to a fixture credential and a low-level consumer."""

    _CAPABILITY_FIELDS = frozenset(ConsumedCredentialCapability.__dataclass_fields__)
    _SECRET_FIELD_MARKERS = ("secret", "password", "token", "api_key", "apikey", "credential_value")

    def __init__(
        self,
        policy: Mapping[str, Any] | str | Path,
        *,
        resolver: FixtureCredentialResolver | None = None,
        consumer: _CredentialConsumer | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy, self._disabled_credentials = self._load_policy(policy)
        self._resolver = resolver
        self._consumer = consumer
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._used_capabilities: set[str] = set()

    @staticmethod
    def _load_policy(policy: Mapping[str, Any] | str | Path) -> tuple[dict[str, dict[str, str]], frozenset[str]]:
        raw: Any
        if isinstance(policy, (str, Path)):
            raw = json.loads(Path(policy).read_text(encoding="utf-8"))
        else:
            raw = dict(policy)
        if raw.get("version") != "credential-policy-v1" or set(raw) != {"version", "credentials", "disabled_credential_refs"}:
            raise CredentialDenied("credential policy is invalid")
        credentials, disabled = raw["credentials"], raw["disabled_credential_refs"]
        if not isinstance(credentials, list) or not isinstance(disabled, list) or any(not isinstance(ref, str) or not ref for ref in disabled):
            raise CredentialDenied("credential policy is invalid")
        required = {"credential_ref", "source_ref", "route_ref", "credential_class", "action", "device_key_ref", "expires_at"}
        parsed: dict[str, dict[str, str]] = {}
        for entry in credentials:
            if not isinstance(entry, Mapping) or set(entry) != required or not all(isinstance(entry[key], str) and entry[key] for key in required):
                raise CredentialDenied("credential policy is invalid")
            credential_ref = entry["credential_ref"]
            if credential_ref in parsed:
                raise CredentialDenied("credential policy has duplicate credential refs")
            parsed[credential_ref] = dict(entry)
        return parsed, frozenset(disabled)

    @staticmethod
    def _timestamp(value: str) -> datetime:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
        except (TypeError, ValueError) as error:
            raise CredentialDenied("credential binding expiry is invalid") from error

    def _capability(self, capability: ConsumedCredentialCapability | Mapping[str, Any]) -> ConsumedCredentialCapability:
        if isinstance(capability, ConsumedCredentialCapability):
            return capability
        if not isinstance(capability, Mapping):
            raise CredentialDenied("consumed capability is required")
        if any(marker in str(key).lower() for key in capability for marker in self._SECRET_FIELD_MARKERS):
            raise CredentialDenied("raw credential fields are forbidden")
        if set(capability) != self._CAPABILITY_FIELDS:
            raise CredentialDenied("consumed capability fields are invalid")
        try:
            return ConsumedCredentialCapability(**dict(capability))
        except TypeError as error:
            raise CredentialDenied("consumed capability fields are invalid") from error

    def lease(self, capability: ConsumedCredentialCapability | Mapping[str, Any]) -> OpaqueCredentialLease:
        """Consume a pre-consumed capability exactly once, then call only the injected consumer."""
        evidence = self._capability(capability)
        if not evidence.consumed or not all(isinstance(getattr(evidence, field), str) and getattr(evidence, field) for field in self._CAPABILITY_FIELDS - {"consumed"}):
            raise CredentialDenied("capability was not already consumed")
        current = self._now().astimezone(timezone.utc)
        if self._timestamp(evidence.expires_at) <= current:
            raise CredentialDenied("capability is expired")
        if evidence.capability_ref in self._used_capabilities:
            raise CredentialDenied("capability replay is denied")
        policy = self._policy.get(evidence.credential_ref)
        if policy is None or evidence.credential_ref in self._disabled_credentials:
            raise CredentialDenied("credential scope is unresolved or disabled")
        if self._timestamp(policy["expires_at"]) <= current:
            raise CredentialDenied("credential policy is expired")
        for field in ("credential_ref", "source_ref", "route_ref", "credential_class", "action", "device_key_ref"):
            if getattr(evidence, field) != policy[field]:
                raise CredentialDenied("capability binding does not match credential policy")
        if self._resolver is None or self._consumer is None:
            raise CredentialDenied("platform credential backend is unavailable")
        lease = OpaqueCredentialLease(evidence.credential_ref, uuid4().hex, min(evidence.expires_at, policy["expires_at"]))
        self._used_capabilities.add(evidence.capability_ref)
        self._resolver.consume(evidence.credential_ref, lambda secret: self._consumer(lease, secret))
        return lease
