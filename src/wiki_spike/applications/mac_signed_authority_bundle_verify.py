"""Verify a Mac signed-authority bundle against injected pinned public keys."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.mac_signed_authority_bundle import (
    SignedAuthorityBundleV1,
    parse_mac_signed_authority_bundle,
)
from wiki_spike.memory_core.mac_signed_authority_parse import EVIDENCE_SIGNING_DOMAIN
from wiki_spike.memory_core.mac_signed_authority_receipt import records_directory_digest
from wiki_spike.memory_core.second_brain_contracts import (
    DECISION_SIGNING_DOMAIN,
    SecondBrainContractDigestV1,
    TrustedDecisionKeyBindingsV1,
)


def _require_aware(now: datetime) -> datetime:
    if now.tzinfo is None or now.utcoffset() is None:
        raise InvalidContractValue("trusted now must include a timezone")
    return now.astimezone(UTC)


def _verify_decisions(
    bundle: SignedAuthorityBundleV1,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    now: datetime,
) -> None:
    for binding in bundle.decision_records:
        record = binding.record
        if not all(
            trusted_keys.matches_decision(record, signature)
            and signature.verify(DECISION_SIGNING_DOMAIN, record.signing_payload())
            for signature in record.signatures
        ):
            raise InvalidContractValue(
                f"untrusted or invalid signature for {record.decision_id}"
            )
        _ = record.from_mapping(record.to_mapping(), now=now)


def _verify_aggregate(
    bundle: SignedAuthorityBundleV1,
    trusted_keys: TrustedDecisionKeyBindingsV1,
) -> None:
    if not bundle.aggregate.verify(trusted_keys):
        raise InvalidContractValue("untrusted or invalid aggregate envelope")
    records = tuple(item.record for item in bundle.decision_records)
    expected = SecondBrainContractDigestV1.create(
        records,
        bundle.aggregate.contract.resolved_scope,
        bundle.aggregate.contract.expected_scope_manifest,
    )
    if bundle.aggregate.contract != expected:
        raise InvalidContractValue("aggregate does not match decision records")


def _verify_evidence(
    bundle: SignedAuthorityBundleV1,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    now: datetime,
) -> None:
    envelope = bundle.evidence_manifest
    if not all(
        trusted_keys.matches_aggregate(signature)
        and signature.verify(EVIDENCE_SIGNING_DOMAIN, envelope.signing_payload())
        for signature in envelope.signatures
    ):
        raise InvalidContractValue("evidence manifest has an untrusted or invalid signature")
    identities = {
        (record.decision_id, record.scope_kind, record.scope_name): record.evidence_digest
        for record in (item.record for item in bundle.decision_records)
    }
    if envelope.body.evidence != identities:
        raise InvalidContractValue(
            "evidence manifest must exactly match the supplied decision evidence"
        )
    observed = envelope.body.observed_at
    expires = envelope.body.expires_at
    current = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if current < observed:
        raise InvalidContractValue("evidence manifest is from the future")
    if current >= expires:
        raise InvalidContractValue("evidence manifest is stale")


def _verify_receipt(bundle: SignedAuthorityBundleV1) -> None:
    records = tuple((item.name, item.record) for item in bundle.decision_records)
    actual = records_directory_digest(records)
    receipt = bundle.resolution_receipt
    if actual != receipt.input_sha256.records_dir:
        raise InvalidContractValue("records-directory digest does not match resolution receipt")
    aggregate_digest = sha256(canonical_bytes(bundle.aggregate.to_mapping())).hexdigest()
    if aggregate_digest != receipt.input_sha256.aggregate:
        raise InvalidContractValue("aggregate digest does not match resolution receipt")
    evidence_digest = sha256(canonical_bytes(bundle.evidence_manifest.to_mapping())).hexdigest()
    if evidence_digest != receipt.input_sha256.evidence_manifest:
        raise InvalidContractValue("evidence digest does not match resolution receipt")


def verify_mac_signed_authority_bundle(
    raw: bytes,
    trusted_keys: TrustedDecisionKeyBindingsV1,
    *,
    now: datetime,
) -> SignedAuthorityBundleV1:
    bundle = parse_mac_signed_authority_bundle(raw)
    current = _require_aware(now)
    _verify_decisions(bundle, trusted_keys, current)
    _verify_aggregate(bundle, trusted_keys)
    _verify_evidence(bundle, trusted_keys, current)
    _verify_receipt(bundle)
    return bundle
