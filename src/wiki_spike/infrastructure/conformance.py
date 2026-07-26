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
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping
from pathlib import PurePosixPath

from wiki_spike.infrastructure import crypto
from wiki_spike.memory_core.contracts import canonical_bytes

# ---------------------------------------------------------------------------
# Domains / schemas / closed enums
# ---------------------------------------------------------------------------

PRE_REVIEW_MANIFEST_DOMAIN = "wiki.gate8.pre-review-manifest.v1"
REVIEW_ATTESTATION_DOMAIN = "wiki.gate8.reviewer-attestation.v1"
EVIDENCE_JOIN_DOMAIN = "wiki.gate8.evidence-join.v1"

PRE_REVIEW_MANIFEST_SCHEMA = "wiki-gate8-pre-review-manifest-v1"
REVIEW_ATTESTATION_SCHEMA = "wiki-gate8-reviewer-attestation-v1"
FINAL_REVIEW_RECEIPT_SCHEMA = "wiki-gate8-final-review-receipt-v1"
EVIDENCE_JOIN_SCHEMA = "wiki-gate8-evidence-join-v1"

ARCHITECT = "ARCHITECT"
CRITIC = "CRITIC"
REQUIRED_ROLES: tuple[str, ...] = (ARCHITECT, CRITIC)

GATE1 = "gate1"
CONFORMANCE = "conformance"
CANARY = "canary"
REQUIRED_LANES: tuple[str, ...] = (GATE1, CONFORMANCE, CANARY)
LANE_ARTIFACT_KINDS: dict[str, str] = {
    GATE1: "GATE1_DECISION",
    CONFORMANCE: "CONFORMANCE_PRE_CANARY",
    CANARY: "CANARY_24H",
}
STRICT_IMPORT_RECEIPT_FIELDS = frozenset((
    "repository", "artifact_kind", "platform", "producer_commit",
    "contract_digest", "toolchain_lock_digest", "workflow_file_digest",
    "workflow_run_id", "workflow_run_attempt", "artifact_name",
    "bundle_sha256", "payload_paths", "payload_sha256", "source_run_url",
    "verified",
))
ATTESTATION_FIELDS = frozenset((
    "schema", "reviewer_role", "verdict", "workspace_id",
    "implementation_commit", "manifest_digest", "reviewer_key_id",
    "issued_at", "expires_at", "signature",
))
FINAL_REVIEW_RECEIPT_FIELDS = frozenset((
    "schema", "workspace_id", "implementation_commit", "manifest_digest",
    "artifact_inventory", "attestations",
))
APPROVE = "APPROVE"
MAX_ATTESTATION_LIFETIME_SECONDS = 3600
_ATTESTATION_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


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
    """One lane's complete, strictly verified import receipt."""

    lane: str
    receipt: dict


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
        "bundles": [{"lane": b.lane, "receipt": b.receipt} for b in bundles],
    }


def build_pre_review_manifest(
    *,
    workspace_id: str,
    implementation_commit: str,
    bundles: Mapping[str, Mapping],
) -> PreReviewManifest:
    """Build the verdict-free pre-review manifest from exactly the three
    required lanes. Each lane supplies one complete, strictly verified import
    receipt, preserved verbatim and covered by ``manifest_digest``."""
    missing = [lane for lane in REQUIRED_LANES if lane not in bundles]
    if missing:
        raise ConformanceError("manifest_missing_lanes", f"missing bundle lane(s): {sorted(missing)}")
    extra = [lane for lane in bundles if lane not in REQUIRED_LANES]
    if extra:
        raise ConformanceError("manifest_extra_lanes", f"unexpected bundle lane(s): {sorted(extra)}")

    refs: list[BundleRef] = []
    receipt_keys = STRICT_IMPORT_RECEIPT_FIELDS
    seen_receipts: set[bytes] = set()
    for lane in REQUIRED_LANES:
        receipt = bundles[lane]
        if set(receipt) != receipt_keys:
            raise ConformanceError(
                "manifest_receipt_keys_invalid",
                f"lane {lane!r} receipt must use the closed strict-import receipt wire",
            )
        if receipt["verified"] is not True:
            raise ConformanceError("manifest_receipt_unverified", f"lane {lane!r} receipt is not verified")
        if receipt["artifact_kind"] != LANE_ARTIFACT_KINDS[lane]:
            raise ConformanceError("manifest_receipt_lane_mismatch", f"lane {lane!r} receipt has the wrong artifact kind")
        if lane in (CONFORMANCE, CANARY) and receipt["producer_commit"] != implementation_commit:
            raise ConformanceError("manifest_receipt_commit_mismatch", f"lane {lane!r} must use implementation_commit")
        scalar_fields = receipt_keys - {"payload_paths", "payload_sha256", "verified"}
        if not all(isinstance(receipt[field], str) and receipt[field] for field in scalar_fields):
            raise ConformanceError("manifest_receipt_invalid", f"lane {lane!r} receipt has an invalid scalar field")
        if not isinstance(receipt["payload_paths"], list) or not isinstance(receipt["payload_sha256"], list):
            raise ConformanceError("manifest_receipt_invalid", f"lane {lane!r} receipt payload fields are invalid")
        if not receipt["source_run_url"]:
            raise ConformanceError("manifest_receipt_source_missing", f"lane {lane!r} source_run_url is required")
        try:
            receipt_bytes = canonical_bytes(receipt)
        except Exception as exc:
            raise ConformanceError("manifest_receipt_invalid", f"lane {lane!r} receipt is not canonicalizable") from exc
        if receipt_bytes in seen_receipts:
            raise ConformanceError("manifest_receipt_reused", "each lane must have a distinct import receipt")
        seen_receipts.add(receipt_bytes)
        refs.append(BundleRef(lane=lane, receipt=dict(receipt)))

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
# Independent review attestations and final receipt
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReviewAttestation:
    """Closed reviewer attestation wire, signed independently by one reviewer."""

    schema: str
    reviewer_role: str
    verdict: str
    workspace_id: str
    implementation_commit: str
    manifest_digest: str
    reviewer_key_id: str
    issued_at: str
    expires_at: str
    signature: str

    def to_mapping(self) -> dict[str, str]:
        return {
            "schema": self.schema,
            "reviewer_role": self.reviewer_role,
            "verdict": self.verdict,
            "workspace_id": self.workspace_id,
            "implementation_commit": self.implementation_commit,
            "manifest_digest": self.manifest_digest,
            "reviewer_key_id": self.reviewer_key_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "signature": self.signature,
        }


def _parse_attestation_time(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise ConformanceError("attestation_time_invalid", f"{field} must be a UTC timestamp")
    try:
        return datetime.strptime(value, _ATTESTATION_TIME_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ConformanceError(
            "attestation_time_invalid",
            f"{field} must use canonical UTC second precision",
        ) from exc


def _attestation_payload(
    *,
    reviewer_role: str,
    workspace_id: str,
    implementation_commit: str,
    manifest_digest: str,
    reviewer_key_id: str,
    issued_at: str,
    expires_at: str,
) -> dict[str, str]:
    return {
        "schema": REVIEW_ATTESTATION_SCHEMA,
        "reviewer_role": reviewer_role,
        "verdict": APPROVE,
        "workspace_id": workspace_id,
        "implementation_commit": implementation_commit,
        "manifest_digest": manifest_digest,
        "reviewer_key_id": reviewer_key_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
    }


def attest_manifest(
    *,
    reviewer_role: str,
    reviewer_key_id: str,
    private_key,
    workspace_id: str,
    implementation_commit: str,
    manifest_digest: str,
    issued_at: str,
    expires_at: str,
) -> ReviewAttestation:
    """Issue a complete, closed APPROVE attestation over one exact manifest."""
    payload = _attestation_payload(
        reviewer_role=reviewer_role,
        workspace_id=workspace_id,
        implementation_commit=implementation_commit,
        manifest_digest=manifest_digest,
        reviewer_key_id=reviewer_key_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    _validate_attestation_mapping(payload)
    return ReviewAttestation(
        **payload,
        signature=crypto.sign(private_key, REVIEW_ATTESTATION_DOMAIN, payload),
    )


def _validate_attestation_mapping(value: Mapping) -> None:
    if not isinstance(value, Mapping):
        raise ConformanceError("attestation_fields_invalid", "attestation must be an object")
    if set(value) != ATTESTATION_FIELDS - {"signature"} and set(value) != ATTESTATION_FIELDS:
        raise ConformanceError("attestation_fields_invalid", "attestation must use the closed wire fields")
    if value.get("schema") != REVIEW_ATTESTATION_SCHEMA:
        raise ConformanceError("attestation_schema_mismatch", f"expected {REVIEW_ATTESTATION_SCHEMA!r}")
    if value.get("reviewer_role") not in REQUIRED_ROLES:
        raise ConformanceError("attestation_invalid_role", f"reviewer_role must be one of {REQUIRED_ROLES}")
    if value.get("verdict") != APPROVE:
        raise ConformanceError("attestation_invalid_verdict", "reviewer verdict must be APPROVE")
    for field in ATTESTATION_FIELDS - {"signature"}:
        if not isinstance(value.get(field), str) or not value[field]:
            raise ConformanceError("attestation_invalid_field", f"{field} must be a non-empty string")
    if "signature" in value and (not isinstance(value["signature"], str) or not value["signature"]):
        raise ConformanceError("attestation_invalid_field", "signature must be a non-empty string")


def _attestation_from_mapping(value: Mapping) -> ReviewAttestation:
    _validate_attestation_mapping(value)
    if set(value) != ATTESTATION_FIELDS:
        raise ConformanceError("attestation_fields_invalid", "attestation signature is required")
    return ReviewAttestation(**dict(value))


def verify_attestation(
    attestation: ReviewAttestation,
    trusted_reviewers: Mapping[str, tuple[str, object]],
    *,
    workspace_id: str,
    implementation_commit: str,
    manifest_digest: str,
    now: str,
) -> None:
    """Fail closed on wire, trust, binding, clock, or signature mismatch."""
    wire = attestation.to_mapping()
    _validate_attestation_mapping(wire)
    if (
        attestation.workspace_id != workspace_id
        or attestation.implementation_commit != implementation_commit
        or attestation.manifest_digest != manifest_digest
    ):
        raise ConformanceError("attestation_binding_mismatch", "attestation does not bind the expected review target")
    try:
        expected_key_id, public_key = trusted_reviewers[attestation.reviewer_role]
    except KeyError as exc:
        raise ConformanceError("attestation_untrusted_role", "reviewer role is not trusted") from exc
    if attestation.reviewer_key_id != expected_key_id:
        raise ConformanceError("attestation_untrusted_key", "reviewer key is not authorized for its role")

    issued = _parse_attestation_time(attestation.issued_at, "issued_at")
    expires = _parse_attestation_time(attestation.expires_at, "expires_at")
    trusted_now = _parse_attestation_time(now, "now")
    if expires <= issued:
        raise ConformanceError("attestation_lifetime_invalid", "expires_at must be after issued_at")
    if (expires - issued).total_seconds() > MAX_ATTESTATION_LIFETIME_SECONDS:
        raise ConformanceError("attestation_lifetime_invalid", "attestation lifetime exceeds the allowed bound")
    if issued > trusted_now:
        raise ConformanceError("attestation_not_yet_valid", "attestation is issued in the future")
    if expires <= trusted_now:
        raise ConformanceError("attestation_expired", "attestation is expired")
    try:
        crypto.verify(
            public_key,
            REVIEW_ATTESTATION_DOMAIN,
            _attestation_payload(
                reviewer_role=attestation.reviewer_role,
                workspace_id=attestation.workspace_id,
                implementation_commit=attestation.implementation_commit,
                manifest_digest=attestation.manifest_digest,
                reviewer_key_id=attestation.reviewer_key_id,
                issued_at=attestation.issued_at,
                expires_at=attestation.expires_at,
            ),
            attestation.signature,
        )
    except Exception as exc:
        raise ConformanceError("attestation_signature_invalid", "reviewer attestation signature failed") from exc


def _validate_attestation_set(
    attestations: tuple[ReviewAttestation, ...],
    trusted_reviewers: Mapping[str, tuple[str, object]],
    *,
    workspace_id: str,
    implementation_commit: str,
    manifest_digest: str,
    now: str,
) -> None:
    if len(attestations) != len(REQUIRED_ROLES):
        raise ConformanceError("receipt_attestation_count", f"exactly {len(REQUIRED_ROLES)} attestations are required")
    roles = [attestation.reviewer_role for attestation in attestations]
    keys = [attestation.reviewer_key_id for attestation in attestations]
    if len(set(roles)) != len(roles):
        raise ConformanceError("receipt_duplicate_role", "reviewer roles must be distinct")
    if len(set(keys)) != len(keys):
        raise ConformanceError("receipt_duplicate_key", "reviewer keys must be distinct")
    from cryptography.hazmat.primitives import serialization

    public_key_fingerprints = {
        hashlib.sha256(
            public_key.public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).hexdigest()
        for _, public_key in trusted_reviewers.values()
    }
    if len(public_key_fingerprints) != len(REQUIRED_ROLES):
        raise ConformanceError(
            "receipt_duplicate_public_key",
            "reviewer public-key material must be independently held",
        )
    if tuple(roles) != REQUIRED_ROLES:
        raise ConformanceError("receipt_attestation_order_invalid", f"attestations must use canonical role order {REQUIRED_ROLES}")
    for attestation in attestations:
        verify_attestation(
            attestation,
            trusted_reviewers,
            workspace_id=workspace_id,
            implementation_commit=implementation_commit,
            manifest_digest=manifest_digest,
            now=now,
        )


def write_final_review_receipt(
    *,
    workspace_id: str,
    implementation_commit: str,
    manifest: PreReviewManifest,
    evidence_join: "EvidenceJoin",
    attestations: tuple[ReviewAttestation, ...],
    trusted_reviewers: Mapping[str, tuple[str, object]],
    now: str,
) -> bytes:
    """Write the sole canonical final-review receipt representation."""
    manifest_digest = manifest.manifest_digest
    if (
        manifest.workspace_id != workspace_id
        or manifest.implementation_commit != implementation_commit
    ):
        raise ConformanceError("receipt_manifest_binding_mismatch", "manifest does not bind the receipt target")
    inventory = _reviewed_artifact_inventory(manifest, evidence_join)
    for field, value in {
        "workspace_id": workspace_id,
        "implementation_commit": implementation_commit,
        "manifest_digest": manifest_digest,
    }.items():
        if not isinstance(value, str) or not value:
            raise ConformanceError("receipt_invalid_field", f"{field} must be a non-empty string")
    _validate_attestation_set(
        attestations, trusted_reviewers, workspace_id=workspace_id,
        implementation_commit=implementation_commit, manifest_digest=manifest_digest, now=now,
    )
    receipt = {
        "schema": FINAL_REVIEW_RECEIPT_SCHEMA,
        "workspace_id": workspace_id,
        "implementation_commit": implementation_commit,
        "manifest_digest": manifest_digest,
        "artifact_inventory": inventory,
        "attestations": [attestation.to_mapping() for attestation in attestations],
    }
    return canonical_bytes(receipt)


def import_final_review_receipt(
    receipt_bytes: bytes,
    *,
    trusted_reviewers: Mapping[str, tuple[str, object]],
    workspace_id: str,
    implementation_commit: str,
    manifest: PreReviewManifest,
    evidence_join: "EvidenceJoin",
    now: str,
) -> tuple[ReviewAttestation, ...]:
    """Strictly import and verify a canonical final-review receipt."""
    try:
        receipt = json.loads(receipt_bytes)
    except (TypeError, ValueError, UnicodeDecodeError) as exc:
        raise ConformanceError("receipt_decode_invalid", "receipt must be UTF-8 JSON") from exc
    if not isinstance(receipt, dict) or set(receipt) != FINAL_REVIEW_RECEIPT_FIELDS:
        raise ConformanceError("receipt_fields_invalid", "receipt must use the closed final-review wire")
    try:
        if canonical_bytes(receipt) != receipt_bytes:
            raise ConformanceError("receipt_noncanonical", "receipt bytes are not canonical")
    except ConformanceError:
        raise
    except Exception as exc:
        raise ConformanceError("receipt_noncanonical", "receipt is not canonicalizable") from exc
    manifest_digest = manifest.manifest_digest
    if (
        manifest.workspace_id != workspace_id
        or manifest.implementation_commit != implementation_commit
    ):
        raise ConformanceError("receipt_manifest_binding_mismatch", "manifest does not bind the receipt target")
    for field in ("workspace_id", "implementation_commit", "manifest_digest"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise ConformanceError("receipt_invalid_field", f"{field} must be a non-empty string")
    if receipt["schema"] != FINAL_REVIEW_RECEIPT_SCHEMA:
        raise ConformanceError("receipt_schema_mismatch", f"expected {FINAL_REVIEW_RECEIPT_SCHEMA!r}")
    if (
        receipt["workspace_id"] != workspace_id
        or receipt["implementation_commit"] != implementation_commit
        or receipt["manifest_digest"] != manifest_digest
    ):
        raise ConformanceError("receipt_binding_mismatch", "receipt does not bind the expected review target")
    if receipt["artifact_inventory"] != _reviewed_artifact_inventory(manifest, evidence_join):
        raise ConformanceError("receipt_inventory_mismatch", "receipt inventory does not exactly match both reviewed manifests")
    if not isinstance(receipt["attestations"], list):
        raise ConformanceError("receipt_attestations_invalid", "attestations must be an array")
    attestations = tuple(_attestation_from_mapping(value) for value in receipt["attestations"])
    _validate_attestation_set(
        attestations, trusted_reviewers, workspace_id=workspace_id,
        implementation_commit=implementation_commit, manifest_digest=manifest_digest, now=now,
    )
    return attestations

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

    seen_receipts: set[bytes] = set()
    ordered_items: list[tuple[str, dict]] = []
    for lane in REQUIRED_LANES:
        receipt = import_receipts[lane]
        if set(receipt) != STRICT_IMPORT_RECEIPT_FIELDS or receipt.get("verified") is not True:
            raise ConformanceError("join_receipt_invalid", f"lane {lane!r} is not a closed verified import receipt")
        if receipt.get("artifact_kind") != LANE_ARTIFACT_KINDS[lane] or not receipt.get("source_run_url"):
            raise ConformanceError("join_receipt_lane_mismatch", f"lane {lane!r} receipt does not bind its expected provenance")
        if lane in (CONFORMANCE, CANARY) and receipt.get("producer_commit") != implementation_commit:
            raise ConformanceError("join_receipt_commit_mismatch", f"lane {lane!r} must use implementation_commit")
        receipt_bytes = canonical_bytes(receipt)
        if receipt_bytes in seen_receipts:
            raise ConformanceError("join_receipt_reused", "each lane must have a distinct import receipt")
        seen_receipts.add(receipt_bytes)
        ordered_items.append((lane, dict(receipt)))
    ordered = tuple(ordered_items)
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
    seen_receipts: set[bytes] = set()
    for lane, receipt in join.import_receipts:
        if set(receipt) != STRICT_IMPORT_RECEIPT_FIELDS or receipt.get("verified") is not True:
            raise ConformanceError("join_receipt_invalid", f"lane {lane!r} is not a closed verified import receipt")
        if receipt.get("artifact_kind") != LANE_ARTIFACT_KINDS[lane] or not receipt.get("source_run_url"):
            raise ConformanceError("join_receipt_lane_mismatch", f"lane {lane!r} receipt does not bind its expected provenance")
        if lane in (CONFORMANCE, CANARY) and receipt.get("producer_commit") != join.implementation_commit:
            raise ConformanceError("join_receipt_commit_mismatch", f"lane {lane!r} must use implementation_commit")
        receipt_bytes = canonical_bytes(receipt)
        if receipt_bytes in seen_receipts:
            raise ConformanceError("join_receipt_reused", "each lane must have a distinct import receipt")
        seen_receipts.add(receipt_bytes)
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
def _reviewed_artifact_inventory(
    manifest: PreReviewManifest, evidence_join: EvidenceJoin,
) -> dict[str, str]:
    """Return the frozen, path-sorted payload inventory shared by both manifests."""
    verify_evidence_join(evidence_join, manifest.manifest_digest)
    if (
        evidence_join.workspace_id != manifest.workspace_id
        or evidence_join.implementation_commit != manifest.implementation_commit
    ):
        raise ConformanceError("receipt_evidence_binding_mismatch", "evidence join does not bind the manifest target")

    manifest_receipts = {bundle.lane: bundle.receipt for bundle in manifest.bundles}
    join_receipts = dict(evidence_join.import_receipts)
    if tuple(bundle.lane for bundle in manifest.bundles) != REQUIRED_LANES:
        raise ConformanceError("receipt_manifest_lanes_invalid", "manifest must contain each lane in canonical order")
    inventory: dict[str, str] = {}
    seen_paths: set[str] = set()
    for lane in REQUIRED_LANES:
        receipt = manifest_receipts.get(lane)
        if receipt is None or lane not in join_receipts:
            raise ConformanceError("receipt_inventory_lane_missing", f"missing reviewed lane {lane!r}")
        if canonical_bytes(receipt) != canonical_bytes(join_receipts[lane]):
            raise ConformanceError("receipt_manifest_receipt_mismatch", f"lane {lane!r} differs between reviewed manifests")
        paths, digests = receipt["payload_paths"], receipt["payload_sha256"]
        if len(paths) != len(digests) or not paths:
            raise ConformanceError("receipt_inventory_invalid", f"lane {lane!r} has invalid payload inventory")
        for path, digest in zip(paths, digests):
            normalized = PurePosixPath(path).as_posix() if isinstance(path, str) else ""
            if (
                not isinstance(path, str)
                or not path
                or path != normalized
                or path.startswith("/")
                or any(part in (".", "..") for part in PurePosixPath(path).parts)
            ):
                raise ConformanceError("receipt_inventory_path_invalid", "payload paths must be canonical relative paths")
            if path in seen_paths:
                raise ConformanceError("receipt_inventory_duplicate_path", f"duplicate or aliased payload path {path!r}")
            if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ConformanceError("receipt_inventory_digest_invalid", f"payload {path!r} has an invalid SHA-256 digest")
            seen_paths.add(path)
            inventory[path] = digest
    return dict(sorted(inventory.items()))
