"""Gate 8 conformance / review machinery for the Encrypted Single-Memory
Lifecycle.

Implements the four review-process artifacts the Gate 8 join requires, all
deterministic and independently verifiable:

* **Verdict-free pre-review manifest** -- lists the three imported immutable
  bundles (gate1, conformance, canary) bound to one implementation commit, with
  NO verdict field. It is the input the reviewers sign; it can never itself
  claim pass/fail.
* **Two independent attestations** -- ARCHITECT and CRITIC each independently
  sign the manifest digest under their own Ed25519 key (domain-separated per
  R10-2). Neither attestation depends on the other.
* **Separate receipt** -- records the reviewed manifest digest plus the two
  attestations; it is a distinct artifact from the attestations and is only
  valid when both required roles are present, distinct, and verify.
* **Three-import evidence join** -- preserves the three independent bundle
  import receipts under one digest bound to the implementation commit.

Architecture-boundary contract: infrastructure layer; may import
``wiki_spike.memory_core`` and intra-infrastructure (``crypto``) only.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Mapping

from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes

# ---------------------------------------------------------------------------
# Domains / schemas / closed enums
# ---------------------------------------------------------------------------

PRE_REVIEW_MANIFEST_DOMAIN = "wiki.gate8.pre-review-manifest.v1"
REVIEW_ATTESTATION_DOMAIN = "wiki.gate8.review-attestation.v1"
REVIEW_RECEIPT_DOMAIN = "wiki.gate8.review-receipt.v1"
EVIDENCE_JOIN_DOMAIN = "wiki.gate8.evidence-join.v1"

PRE_REVIEW_MANIFEST_SCHEMA = "wiki-gate8-pre-review-manifest-v1"
REVIEW_ATTESTATION_SCHEMA = "wiki-gate8-review-attestation-v1"
REVIEW_RECEIPT_SCHEMA = "wiki-gate8-review-receipt-v1"
EVIDENCE_JOIN_SCHEMA = "wiki-gate8-evidence-join-v1"

ARCHITECT = "ARCHITECT"
CRITIC = "CRITIC"
REQUIRED_ROLES: tuple[str, ...] = (ARCHITECT, CRITIC)

GATE1 = "gate1"
CONFORMANCE = "conformance"
CANARY = "canary"
REQUIRED_LANES: tuple[str, ...] = (GATE1, CONFORMANCE, CANARY)


class ConformanceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _domain_digest(domain: str, body: Mapping) -> str:
    return hashlib.sha256(crypto.signature_input(domain, body)).hexdigest()


# ---------------------------------------------------------------------------
# Verdict-free pre-review manifest
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BundleRef:
    """One imported immutable bundle lane (digest-only references)."""

    lane: str
    artifact_name: str
    artifact_kind: str
    bundle_sha256: str
    platform: str


@dataclass(frozen=True)
class PreReviewManifest:
    """Verdict-free enumeration of the three imported bundles bound to one
    implementation commit. Deliberately carries NO verdict/pass/fail field."""

    schema: str
    workspace_id: str
    implementation_commit: str
    bundles: tuple[BundleRef, ...]
    manifest_digest: str


def _manifest_body(workspace_id: str, implementation_commit: str, bundles: tuple[BundleRef, ...]) -> dict:
    return {
        "workspace_id": workspace_id,
        "implementation_commit": implementation_commit,
        "bundles": [
            {
                "lane": b.lane,
                "artifact_name": b.artifact_name,
                "artifact_kind": b.artifact_kind,
                "bundle_sha256": b.bundle_sha256,
                "platform": b.platform,
            }
            for b in bundles
        ],
    }


def build_pre_review_manifest(
    *,
    workspace_id: str,
    implementation_commit: str,
    bundles: Mapping[str, Mapping],
) -> PreReviewManifest:
    """Build the verdict-free pre-review manifest from exactly the three
    required lanes. Each ``bundles[lane]`` must provide ``artifact_name``,
    ``artifact_kind``, ``bundle_sha256``, and ``platform``. Fails closed on a
    missing/extra lane or a missing field."""
    missing = [lane for lane in REQUIRED_LANES if lane not in bundles]
    if missing:
        raise ConformanceError("manifest_missing_lanes", f"missing bundle lane(s): {sorted(missing)}")
    extra = [lane for lane in bundles if lane not in REQUIRED_LANES]
    if extra:
        raise ConformanceError("manifest_extra_lanes", f"unexpected bundle lane(s): {sorted(extra)}")

    refs: list[BundleRef] = []
    for lane in REQUIRED_LANES:
        entry = bundles[lane]
        for field in ("artifact_name", "artifact_kind", "bundle_sha256", "platform"):
            if not entry.get(field):
                raise ConformanceError(
                    "manifest_lane_field_missing",
                    f"lane {lane!r} missing required field {field!r}",
                )
        refs.append(
            BundleRef(
                lane=lane,
                artifact_name=entry["artifact_name"],
                artifact_kind=entry["artifact_kind"],
                bundle_sha256=entry["bundle_sha256"],
                platform=entry["platform"],
            )
        )

    ordered = tuple(refs)
    body = _manifest_body(workspace_id, implementation_commit, ordered)
    manifest_digest = _domain_digest(PRE_REVIEW_MANIFEST_DOMAIN, body)
    return PreReviewManifest(
        schema=PRE_REVIEW_MANIFEST_SCHEMA,
        workspace_id=workspace_id,
        implementation_commit=implementation_commit,
        bundles=ordered,
        manifest_digest=manifest_digest,
    )


# ---------------------------------------------------------------------------
# Independent review attestations (ARCHITECT / CRITIC)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewAttestation:
    """One reviewer's independent Ed25519 signature over the manifest digest."""

    schema: str
    role: str
    key_id: str
    manifest_digest: str
    signature_hex: str


def _attestation_payload(role: str, key_id: str, manifest_digest: str) -> dict:
    return {
        "schema": REVIEW_ATTESTATION_SCHEMA,
        "role": role,
        "key_id": key_id,
        "manifest_digest": manifest_digest,
    }


def attest_manifest(*, role: str, key_id: str, private_key, manifest_digest: str) -> ReviewAttestation:
    """Produce one independent attestation. ``role`` must be ARCHITECT or
    CRITIC. The signature is domain-separated (R10-2) so it is valid only for
    this exact role/key/manifest digest."""
    if role not in REQUIRED_ROLES:
        raise ConformanceError("attestation_invalid_role", f"role must be one of {REQUIRED_ROLES}, got {role!r}")
    if not key_id:
        raise ConformanceError("attestation_missing_key_id", "key_id is required")
    signature_hex = crypto.sign(private_key, REVIEW_ATTESTATION_DOMAIN, _attestation_payload(role, key_id, manifest_digest))
    return ReviewAttestation(
        schema=REVIEW_ATTESTATION_SCHEMA,
        role=role,
        key_id=key_id,
        manifest_digest=manifest_digest,
        signature_hex=signature_hex,
    )


def verify_attestation(attestation: ReviewAttestation, public_key, manifest_digest: str) -> None:
    """Verify one attestation binds to ``manifest_digest`` and verifies under
    ``public_key``. Raises ``ConformanceError`` (or InvalidSignature) on any
    mismatch."""
    if attestation.schema != REVIEW_ATTESTATION_SCHEMA:
        raise ConformanceError("attestation_schema_mismatch", f"expected {REVIEW_ATTESTATION_SCHEMA!r}")
    if attestation.role not in REQUIRED_ROLES:
        raise ConformanceError("attestation_invalid_role", f"role must be one of {REQUIRED_ROLES}")
    if attestation.manifest_digest != manifest_digest:
        raise ConformanceError(
            "attestation_manifest_mismatch",
            f"attestation binds {attestation.manifest_digest!r}, expected {manifest_digest!r}",
        )
    try:
        crypto.verify(
            public_key,
            REVIEW_ATTESTATION_DOMAIN,
            _attestation_payload(attestation.role, attestation.key_id, attestation.manifest_digest),
            attestation.signature_hex,
        )
    except Exception as exc:  # cryptography.exceptions.InvalidSignature et al.
        raise ConformanceError("attestation_signature_invalid", f"{attestation.role} attestation failed: {exc}") from exc


# ---------------------------------------------------------------------------
# Separate review receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewReceipt:
    """Separate receipt recording the reviewed manifest digest plus the two
    independent attestations. Distinct from the attestations themselves."""

    schema: str
    workspace_id: str
    manifest_digest: str
    attestations: tuple[ReviewAttestation, ...]
    receipt_digest: str


def _receipt_body(workspace_id: str, manifest_digest: str, attestations: tuple[ReviewAttestation, ...]) -> dict:
    return {
        "workspace_id": workspace_id,
        "manifest_digest": manifest_digest,
        "attestations": [
            {
                "schema": a.schema,
                "role": a.role,
                "key_id": a.key_id,
                "manifest_digest": a.manifest_digest,
                "signature_hex": a.signature_hex,
            }
            for a in attestations
        ],
    }


def _validate_attestation_set(attestations: tuple[ReviewAttestation, ...], manifest_digest: str) -> None:
    if len(attestations) != len(REQUIRED_ROLES):
        raise ConformanceError(
            "receipt_attestation_count",
            f"exactly {len(REQUIRED_ROLES)} attestations required, got {len(attestations)}",
        )
    roles = [a.role for a in attestations]
    if len(set(roles)) != len(roles):
        raise ConformanceError("receipt_duplicate_role", f"attestation roles must be distinct, got {roles}")
    if set(roles) != set(REQUIRED_ROLES):
        raise ConformanceError("receipt_missing_role", f"attestations must cover {REQUIRED_ROLES}, got {sorted(roles)}")
    for a in attestations:
        if a.manifest_digest != manifest_digest:
            raise ConformanceError(
                "receipt_attestation_manifest_mismatch",
                f"{a.role} attestation binds a different manifest digest",
            )


def build_review_receipt(
    *,
    workspace_id: str,
    manifest_digest: str,
    attestations: tuple[ReviewAttestation, ...],
) -> ReviewReceipt:
    """Build the separate review receipt. Requires exactly the two distinct
    required roles, both bound to ``manifest_digest``."""
    _validate_attestation_set(attestations, manifest_digest)
    body = _receipt_body(workspace_id, manifest_digest, attestations)
    receipt_digest = _domain_digest(REVIEW_RECEIPT_DOMAIN, body)
    return ReviewReceipt(
        schema=REVIEW_RECEIPT_SCHEMA,
        workspace_id=workspace_id,
        manifest_digest=manifest_digest,
        attestations=attestations,
        receipt_digest=receipt_digest,
    )


def verify_review_receipt(
    receipt: ReviewReceipt,
    public_keys: Mapping[str, object],
    manifest_digest: str,
) -> None:
    """Verify the receipt: correct schema, both required roles present/distinct,
    every attestation verifies under its role's public key and binds the
    manifest digest, and the receipt digest recomputes."""
    if receipt.schema != REVIEW_RECEIPT_SCHEMA:
        raise ConformanceError("receipt_schema_mismatch", f"expected {REVIEW_RECEIPT_SCHEMA!r}")
    if receipt.manifest_digest != manifest_digest:
        raise ConformanceError(
            "receipt_manifest_mismatch",
            f"receipt binds {receipt.manifest_digest!r}, expected {manifest_digest!r}",
        )
    _validate_attestation_set(receipt.attestations, manifest_digest)
    for a in receipt.attestations:
        if a.role not in public_keys:
            raise ConformanceError("receipt_missing_public_key", f"no public key supplied for role {a.role!r}")
        verify_attestation(a, public_keys[a.role], manifest_digest)
    expected = _domain_digest(REVIEW_RECEIPT_DOMAIN, _receipt_body(receipt.workspace_id, manifest_digest, receipt.attestations))
    if expected != receipt.receipt_digest:
        raise ConformanceError("receipt_digest_mismatch", "receipt_digest does not recompute")


# ---------------------------------------------------------------------------
# Three-import evidence join
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EvidenceJoin:
    """Joins the three independent bundle import receipts under one digest
    bound to the implementation commit, preserving each receipt verbatim."""

    schema: str
    workspace_id: str
    implementation_commit: str
    import_receipts: tuple[tuple[str, dict], ...]  # (lane, receipt) pairs
    manifest_digest: str
    join_digest: str


def _join_body(
    workspace_id: str,
    implementation_commit: str,
    import_receipts: tuple[tuple[str, dict], ...],
    manifest_digest: str,
) -> dict:
    return {
        "workspace_id": workspace_id,
        "implementation_commit": implementation_commit,
        "import_receipts": [{"lane": lane, "receipt": receipt} for lane, receipt in import_receipts],
        "manifest_digest": manifest_digest,
    }


def build_evidence_join(
    *,
    workspace_id: str,
    implementation_commit: str,
    import_receipts: Mapping[str, Mapping],
    manifest_digest: str,
) -> EvidenceJoin:
    """Join exactly the three independent import receipts (gate1, conformance,
    canary). Each receipt is preserved verbatim so the join never becomes the
    sole oracle for any single lane."""
    missing = [lane for lane in REQUIRED_LANES if lane not in import_receipts]
    if missing:
        raise ConformanceError("join_missing_lanes", f"missing import receipt lane(s): {sorted(missing)}")
    extra = [lane for lane in import_receipts if lane not in REQUIRED_LANES]
    if extra:
        raise ConformanceError("join_extra_lanes", f"unexpected import receipt lane(s): {sorted(extra)}")

    ordered = tuple((lane, dict(import_receipts[lane])) for lane in REQUIRED_LANES)
    body = _join_body(workspace_id, implementation_commit, ordered, manifest_digest)
    join_digest = _domain_digest(EVIDENCE_JOIN_DOMAIN, body)
    return EvidenceJoin(
        schema=EVIDENCE_JOIN_SCHEMA,
        workspace_id=workspace_id,
        implementation_commit=implementation_commit,
        import_receipts=ordered,
        manifest_digest=manifest_digest,
        join_digest=join_digest,
    )


def verify_evidence_join(join: EvidenceJoin, manifest_digest: str) -> None:
    """Verify the join: correct schema, all three lanes present, bound to the
    manifest digest, and the join digest recomputes."""
    if join.schema != EVIDENCE_JOIN_SCHEMA:
        raise ConformanceError("join_schema_mismatch", f"expected {EVIDENCE_JOIN_SCHEMA!r}")
    lanes = [lane for lane, _ in join.import_receipts]
    if sorted(lanes) != sorted(REQUIRED_LANES):
        raise ConformanceError("join_lanes_mismatch", f"expected lanes {sorted(REQUIRED_LANES)}, got {sorted(lanes)}")
    if join.manifest_digest != manifest_digest:
        raise ConformanceError(
            "join_manifest_mismatch",
            f"join binds {join.manifest_digest!r}, expected {manifest_digest!r}",
        )
    expected = _domain_digest(
        EVIDENCE_JOIN_DOMAIN,
        _join_body(join.workspace_id, join.implementation_commit, join.import_receipts, manifest_digest),
    )
    if expected != join.join_digest:
        raise ConformanceError("join_digest_mismatch", "join_digest does not recompute")
