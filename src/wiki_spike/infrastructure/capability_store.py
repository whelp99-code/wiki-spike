"""In-memory opaque Stage-1 capability persistence."""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from uuid import uuid4

from wiki_spike.memory_core.second_brain_ports import CapabilityStatePort
from wiki_spike.memory_core.second_brain_capabilities import (
    CapabilityGrantV1,
    ConsumptionReceipt,
    ConsumptionReceiptEvidence,
    mint_consumption_receipt,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    CapabilityReceiptV1,
    CapabilityRequestV1,
    DelegatedReviewGrantV1,
    DeviceEnrollmentV1,
    TrustRootV1,
)


@dataclass(frozen=True)
class _ReceiptState:
    evidence: ConsumptionReceiptEvidence
    redeemed: bool = False


class CapabilityStore(CapabilityStatePort):
    """A locked store of only canonical wire values, keyed references, and digests."""

    def __init__(self) -> None:
        self._lock = RLock()
        self._roots: dict[str, TrustRootV1] = {}
        self._devices: dict[str, DeviceEnrollmentV1] = {}
        self._grants: dict[str, DelegatedReviewGrantV1] = {}
        self._requests: dict[str, CapabilityRequestV1] = {}
        self._receipts: dict[str, CapabilityReceiptV1] = {}
        self._capabilities: dict[str, CapabilityGrantV1] = {}
        self._consumed: set[str] = set()
        self._receipt_states: dict[str, _ReceiptState] = {}
        self._revocation_epochs: dict[str, int] = {}

    def record_trust_root(self, trust_root: TrustRootV1) -> None:
        with self._lock:
            current = self._roots.get(trust_root.trust_root_ref)
            if current is not None and int(trust_root.root_revision) <= int(current.root_revision):
                raise ValueError("trust root revision must increase")
            self._roots[trust_root.trust_root_ref] = trust_root
            self._revocation_epochs.setdefault(trust_root.trust_root_ref, 0)

    def record_device_enrollment(self, enrollment: DeviceEnrollmentV1) -> None:
        with self._lock:
            if enrollment.trust_root_ref not in self._roots:
                raise ValueError("unknown trust root")
            self._devices[enrollment.device_key_ref] = enrollment

    def record_delegated_review_grant(self, grant: DelegatedReviewGrantV1) -> None:
        with self._lock:
            self._grants[grant.grant_ref] = grant

    def record_capability_request(self, request: CapabilityRequestV1) -> None:
        with self._lock:
            self._requests[request.request_ref] = request

    def record_capability_receipt(self, receipt: CapabilityReceiptV1) -> None:
        with self._lock:
            if receipt.request_ref not in self._requests:
                raise ValueError("unknown capability request")
            self._receipts[receipt.receipt_ref] = receipt

    def trust_root(self, trust_root_ref: str) -> TrustRootV1 | None:
        with self._lock:
            return self._roots.get(trust_root_ref)

    def device(self, device_key_ref: str) -> DeviceEnrollmentV1 | None:
        with self._lock:
            return self._devices.get(device_key_ref)

    def grants_for(self, reviewer_key_ref: str) -> tuple[DelegatedReviewGrantV1, ...]:
        with self._lock:
            return tuple(grant for grant in self._grants.values() if grant.reviewer_key_ref == reviewer_key_ref)

    def revoke_device(self, trust_root_ref: str, device_key_ref: str) -> str:
        with self._lock:
            device = self._devices.get(device_key_ref)
            if device is None or device.trust_root_ref != trust_root_ref:
                raise ValueError("unknown device")
            del self._devices[device_key_ref]
            self._revocation_epochs[trust_root_ref] = self._revocation_epochs.get(trust_root_ref, 0) + 1
            return str(self._revocation_epochs[trust_root_ref])

    def revocation_epoch(self, trust_root_ref: str) -> str:
        with self._lock:
            return str(self._revocation_epochs.get(trust_root_ref, 0))

    def save_capability(self, capability: CapabilityGrantV1) -> None:
        with self._lock:
            if capability.capability_ref in self._capabilities:
                raise ValueError("capability already exists")
            self._capabilities[capability.capability_ref] = capability

    def capability(self, capability_ref: str) -> CapabilityGrantV1 | None:
        with self._lock:
            return self._capabilities.get(capability_ref)

    def compare_consume(
        self,
        capability_ref: str,
        request_digest: str,
        nonce_digest: str,
        credential_ref: str,
        action: str,
    ) -> ConsumptionReceipt | None:
        """Atomically validate persisted scope and mint only an opaque receipt token."""
        with self._lock:
            capability = self._capabilities.get(capability_ref)
            if (capability is None or capability_ref in self._consumed
                    or capability.request_digest != request_digest
                    or capability.nonce_digest != nonce_digest
                    or credential_ref not in capability.credential_refs
                    or action not in capability.credential_actions):
                return None
            self._consumed.add(capability_ref)
            token = uuid4().hex
            self._receipt_states[token] = _ReceiptState(
                ConsumptionReceiptEvidence(credential_ref, action, capability.device_key_ref, capability.expires_at)
            )
            return mint_consumption_receipt(token)

    def redeem_consumption_receipt(self, token: ConsumptionReceipt) -> ConsumptionReceiptEvidence | None:
        """Atomically redeem an opaque token owned by this concrete store."""
        if not isinstance(token, ConsumptionReceipt):
            return None
        with self._lock:
            receipt_token = token._token_for_store()
            state = self._receipt_states.get(receipt_token)
            if state is None or state.redeemed:
                return None
            self._receipt_states[receipt_token] = _ReceiptState(state.evidence, redeemed=True)
            return state.evidence
