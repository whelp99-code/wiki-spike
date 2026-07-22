"""MemoryCommandGateway orchestration without storage publication coupling."""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Protocol

from .contracts import CONTRACT_VERSION, CommandEnvelope, CoreResult
from .policy import CapabilityToken, PolicyEngine, PolicyRequest, Sensitivity


class GenerationReader(Protocol):
    def current_generation_id(self, workspace_id: str) -> str | None: ...


class CapabilityResolver(Protocol):
    def resolve(self, workspace_id: str, actor_id: str) -> CapabilityToken | None: ...


class CommandHandler(Protocol):
    def handle(self, command: CommandEnvelope) -> CoreResult: ...


@dataclass(frozen=True)
class IdempotencyRecord:
    request_digest: str
    result: CoreResult


class InMemoryIdempotencyStore:
    """Reference store for contract tests; persistent implementation is a later adapter."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], IdempotencyRecord] = {}

    def get(self, workspace_id: str, key: str) -> IdempotencyRecord | None:
        return self._records.get((workspace_id, key))

    def put(self, workspace_id: str, key: str, record: IdempotencyRecord) -> None:
        self._records[(workspace_id, key)] = record


class MemoryCommandGateway:
    def __init__(
        self,
        generation_reader: GenerationReader,
        capability_resolver: CapabilityResolver,
        handler: CommandHandler,
        *,
        policy: PolicyEngine | None = None,
        idempotency: InMemoryIdempotencyStore | None = None,
        now: str,
    ) -> None:
        self.generation_reader = generation_reader
        self.capability_resolver = capability_resolver
        self.handler = handler
        self.policy = policy or PolicyEngine()
        self.idempotency = idempotency or InMemoryIdempotencyStore()
        self.now = now
        self._lock = RLock()

    def execute(self, command: CommandEnvelope) -> CoreResult:
        with self._lock:
            digest = sha256(command.canonical_bytes()).hexdigest()
            existing = self.idempotency.get(command.workspace_id, command.idempotency_key)
            if existing is not None:
                if existing.request_digest != digest:
                    return self._result(command.command_id, "rejected", None, "idempotency_payload_mismatch")
                return existing.result

            current = self.generation_reader.current_generation_id(command.workspace_id)
            if command.expected_generation_id != current:
                return self._result(command.command_id, "retry_later", current, "stale_generation")

            token = self.capability_resolver.resolve(command.workspace_id, command.actor_id)
            if token is None:
                return self._result(command.command_id, "rejected", current, "capability_missing")

            try:
                sensitivity = Sensitivity(str(command.payload.get("sensitivity", "public")))
            except ValueError:
                return self._result(command.command_id, "rejected", current, "invalid_sensitivity")

            decision = self.policy.authorize(
                token,
                PolicyRequest(
                    workspace_id=command.workspace_id,
                    actor_id=command.actor_id,
                    action=command.command_type,
                    now=self.now,
                    object_sensitivity=sensitivity,
                ),
            )
            if not decision.allowed:
                return self._result(command.command_id, "rejected", current, decision.reason.value)

            try:
                result = self.handler.handle(command)
            except Exception:
                return self._result(command.command_id, "retry_later", current, "handler_unavailable")

            if result.status != "retry_later":
                self.idempotency.put(
                    command.workspace_id,
                    command.idempotency_key,
                    IdempotencyRecord(digest, result),
                )
            return result

    @staticmethod
    def _result(request_id: str, status: str, generation_id: str | None, error_code: str) -> CoreResult:
        return CoreResult(
            contract_version=CONTRACT_VERSION,
            request_id=request_id,
            status=status,
            generation_id=generation_id,
            result={},
            error_code=error_code,
        )
