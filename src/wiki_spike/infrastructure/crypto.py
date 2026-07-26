"""Product identity/crypto module for the Encrypted Single-Memory Lifecycle.

Implements ADR-0026 (docs/adr/ADR-0026-encrypted-lifecycle-authority-identity.md)
exactly: HKDF-SHA-256 key derivation, the five HMAC identity message
families, AES-256-GCM envelope seal/open, Ed25519 domain-separated
signing/verification under the single signature-input rule (R10-2), the
RFC 6962 append-only Merkle history tree, the 256-level sparse Merkle
current map, and the acyclic bundle digest self-field projection.

This module reuses the frozen Core canonicalizer
(``wiki_spike.memory_core.contracts.canonical_bytes``) — there is no
parallel encoder here. All production key material (root IKM for HKDF,
AES-256 DEKs, Ed25519 private key seeds) is injected by callers; nothing
secret is hardcoded in this module. The HKDF salt/info domain-separation
strings below are part of the frozen wire protocol (ADR-0026 §3), not
secret material, and are reused verbatim so derived keys are byte-for-byte
reproducible by any independent verifier given the same root IKM — this is
what lets ``tests/encrypted_lifecycle/test_crypto_conformance.py`` prove
this module reproduces the frozen Gate 1 vectors exactly.

Architecture-boundary contract: this module (part of the ``infrastructure``
layer) may import ``wiki_spike.memory_core`` only; it must never import
``wiki_spike.memory_runtime``, ``wiki_spike.applications``,
``wiki_spike.connectors``, ``wiki_spike.ui``, or the legacy storage modules.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Mapping, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from wiki_spike.memory_core.contracts import canonical_bytes

# ---------------------------------------------------------------------------
# 1. HKDF-SHA-256 key derivation (ADR-0026 §3).
# ---------------------------------------------------------------------------

HKDF_LABELS: tuple[str, ...] = (
    "command_digest_key_v1",
    "manifest_digest_key_v1",
    "artifact_identity_key_v1",
    "subject_identity_key_v1",
    "object_identity_key_v1",
    "revision_identity_key_v1",
    "stable_subject_key_v1",
    "locator_identity_key_v1",
)

# Frozen HKDF domain-separation strings (ADR-0026 §3: "unchanged salt ...
# NUL-delimited info string"). These are wire-protocol constants, not
# secrets; the actual secret is the injected root IKM.
_HKDF_SALT_PREFIX = b"WIKI-SPIKE-TEST-ONLY-HKDF-SALT-V1:"
_HKDF_INFO_VERSION_SUFFIX = b"v1"


def hkdf_salt(label: str) -> bytes:
    if label not in HKDF_LABELS:
        raise ValueError(f"unknown HKDF label: {label!r}")
    return hashlib.sha256(_HKDF_SALT_PREFIX + label.encode("ascii")).digest()


def hkdf_info(label: str) -> bytes:
    if label not in HKDF_LABELS:
        raise ValueError(f"unknown HKDF label: {label!r}")
    return label.encode("ascii") + b"\x00" + _HKDF_INFO_VERSION_SUFFIX


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA-256 extract-and-expand."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    prev = b""
    counter = 1
    while len(okm) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        okm += prev
        counter += 1
    return okm[:length]


def derive_identity_keys(root_ikm: bytes) -> dict[str, bytes]:
    """Derive all eight identity/manifest HKDF keys from an injected root IKM."""
    return {
        label: hkdf_sha256(root_ikm, hkdf_salt(label), hkdf_info(label))
        for label in HKDF_LABELS
    }


# ---------------------------------------------------------------------------
# 2. Canonical identity messages / HMAC framing (ADR-0026 §2).
# ---------------------------------------------------------------------------


def identity_hmac_hex(derived_keys: Mapping[str, bytes], label: str, payload: Mapping) -> str:
    """HMAC-SHA-256 hex digest over canonical_bytes(payload) under the
    derived key for ``label``. This is the single canonicalization path for
    all identity bytes in this system (reuses frozen Core canonical_bytes)."""
    if label not in derived_keys:
        raise ValueError(f"no derived key for label: {label!r}")
    message = canonical_bytes(payload)
    return hmac.new(derived_keys[label], message, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# 3. Single signature-input construction rule (ADR-0026 §4, R10-2, binding).
# ---------------------------------------------------------------------------


def domain_prefix(domain: str) -> bytes:
    """ASCII domain string terminated by exactly one NUL byte."""
    return domain.encode("ascii") + b"\x00"


def signature_input(domain: str, payload: Mapping) -> bytes:
    """signature_input = domain_prefix_bytes + canonical_bytes(payload_object)."""
    return domain_prefix(domain) + canonical_bytes(payload)


def sign(private_key: Ed25519PrivateKey, domain: str, payload: Mapping) -> str:
    return private_key.sign(signature_input(domain, payload)).hex()


def verify(public_key: Ed25519PublicKey, domain: str, payload: Mapping, signature_hex: str) -> None:
    """Raises cryptography.exceptions.InvalidSignature on any mismatch,
    including a signature valid only under a different domain or key."""
    public_key.verify(bytes.fromhex(signature_hex), signature_input(domain, payload))


# ---------------------------------------------------------------------------
# 4. Nonce type split (ADR-0026 §5).
# ---------------------------------------------------------------------------

AES_GCM_NONCE_HEX24_RE = re.compile(r"^[0-9a-f]{24}$")
CHALLENGE_NONCE_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def is_aes_gcm_nonce_hex24(value: str) -> bool:
    return bool(AES_GCM_NONCE_HEX24_RE.fullmatch(value))


def is_challenge_nonce_hex64(value: str) -> bool:
    return bool(CHALLENGE_NONCE_HEX64_RE.fullmatch(value))


# ---------------------------------------------------------------------------
# 5. AES-256-GCM envelope seal/open (ADR-0026 §8).
# ---------------------------------------------------------------------------


def aes_gcm_seal(dek: bytes, nonce_hex: str, plaintext: bytes, aad: bytes = b"") -> tuple[str, str]:
    """Seal ``plaintext`` under a 32-byte DEK and an AesGcmNonceHex24 nonce.

    Returns ``(ciphertext_hex, tag_hex)`` with the GCM authentication tag
    split out as its own 16-byte field (matching the envelope-v1 schema's
    separate ``ciphertext``/``tag`` fields, both hex-encoded).
    """
    if len(dek) != 32:
        raise ValueError("DEK must be exactly 32 bytes for AES-256-GCM")
    if not is_aes_gcm_nonce_hex24(nonce_hex):
        raise ValueError("nonce must match AesGcmNonceHex24 (^[0-9a-f]{24}$)")
    nonce = bytes.fromhex(nonce_hex)
    sealed = AESGCM(dek).encrypt(nonce, plaintext, aad or None)
    ciphertext, tag = sealed[:-16], sealed[-16:]
    return ciphertext.hex(), tag.hex()


def aes_gcm_open(dek: bytes, nonce_hex: str, ciphertext_hex: str, tag_hex: str, aad: bytes = b"") -> bytes:
    """Inverse of :func:`aes_gcm_seal`. Raises
    ``cryptography.exceptions.InvalidTag`` on any tamper."""
    if len(dek) != 32:
        raise ValueError("DEK must be exactly 32 bytes for AES-256-GCM")
    if not is_aes_gcm_nonce_hex24(nonce_hex):
        raise ValueError("nonce must match AesGcmNonceHex24 (^[0-9a-f]{24}$)")
    nonce = bytes.fromhex(nonce_hex)
    sealed = bytes.fromhex(ciphertext_hex) + bytes.fromhex(tag_hex)
    return AESGCM(dek).decrypt(nonce, sealed, aad or None)


# ---------------------------------------------------------------------------
# 6. RFC 6962-style append-only Merkle tree (history root / inclusion /
#    consistency proofs).
# ---------------------------------------------------------------------------


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _merkle_root(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    split = 1
    while split * 2 < n:
        split *= 2
    return node_hash(_merkle_root(leaves[:split]), _merkle_root(leaves[split:]))


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    return _merkle_root(list(leaves))


def merkle_inclusion_proof(leaves: Sequence[bytes], index: int) -> list[bytes]:
    leaves = list(leaves)

    def rec(lo: int, hi: int) -> list[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        split = 1
        while split * 2 < n:
            split *= 2
        if index - lo < split:
            return rec(lo, lo + split) + [_merkle_root(leaves[lo + split:hi])]
        return rec(lo + split, hi) + [_merkle_root(leaves[lo:lo + split])]

    return rec(0, len(leaves))


def merkle_consistency_proof(leaves: Sequence[bytes], old_size: int, new_size: int) -> list[bytes]:
    leaves = list(leaves)

    def subproof(lo: int, hi: int, m: int, complete: bool) -> list[bytes]:
        n = hi - lo
        if m == n:
            if complete:
                return []
            return [_merkle_root(leaves[lo:hi])]
        split = 1
        while split * 2 < n:
            split *= 2
        if m <= split:
            return subproof(lo, lo + split, m, False) + [_merkle_root(leaves[lo + split:hi])]
        right = subproof(lo + split, hi, m - split, complete and m == n)
        return right + [_merkle_root(leaves[lo:lo + split])]

    if old_size == 0 or old_size == new_size:
        return []
    return subproof(0, new_size, old_size, True)


# ---------------------------------------------------------------------------
# 7. 256-level Sparse Merkle Tree (current-map root / membership /
#    non-membership proofs).
# ---------------------------------------------------------------------------

SMT_DEPTH = 256
SMT_DEFAULT: list[bytes] = [hashlib.sha256(b"\x00").digest()]
for _i in range(SMT_DEPTH):
    SMT_DEFAULT.append(hashlib.sha256(b"\x02" + SMT_DEFAULT[-1] + SMT_DEFAULT[-1]).digest())


def smt_bit(key_int: int, depth: int) -> int:
    return (key_int >> (SMT_DEPTH - 1 - depth)) & 1


def smt_leaf(key_int: int, value: bytes) -> bytes:
    """Occupied sparse-Merkle leaf hash = SHA-256(0x01 || key_raw32 || value_raw32).

    Domain-separated (0x01) from internal nodes (0x02) and the empty-leaf
    default (0x00) per the Stage-8 binding current-map wire spec."""
    return hashlib.sha256(b"\x01" + key_int.to_bytes(32, "big") + value).digest()


def smt_node(items: Mapping[int, bytes], depth: int) -> bytes:
    if not items:
        return SMT_DEFAULT[SMT_DEPTH - depth]
    if depth == SMT_DEPTH:
        ((key_int, value),) = items.items()
        return smt_leaf(key_int, value)
    left = {k: v for k, v in items.items() if smt_bit(k, depth) == 0}
    right = {k: v for k, v in items.items() if smt_bit(k, depth) == 1}
    return hashlib.sha256(b"\x02" + smt_node(left, depth + 1) + smt_node(right, depth + 1)).digest()


def smt_root(items: Mapping[int, bytes]) -> bytes:
    return smt_node(items, 0)


def smt_proof(items: Mapping[int, bytes], key_int: int) -> list[bytes]:
    siblings: list[bytes] = []

    def rec(cur_items: Mapping[int, bytes], depth: int) -> None:
        if depth == SMT_DEPTH:
            return
        left = {k: v for k, v in cur_items.items() if smt_bit(k, depth) == 0}
        right = {k: v for k, v in cur_items.items() if smt_bit(k, depth) == 1}
        if smt_bit(key_int, depth) == 0:
            siblings.append(smt_node(right, depth + 1))
            rec(left, depth + 1)
        else:
            siblings.append(smt_node(left, depth + 1))
            rec(right, depth + 1)

    rec(items, 0)
    return siblings


def hexkey_to_int(hex64: str) -> int:
    return int(hex64, 16)


# ---------------------------------------------------------------------------
# 8. Acyclic bundle identity (self-field projection) (ADR-0026 §9).
# ---------------------------------------------------------------------------

BUNDLE_SELF_FIELDS: tuple[str, str] = ("artifact_name", "bundle_sha256")


def project_bundle_envelope(template: Mapping) -> tuple[bytes, str, int]:
    """Replace the two self-fields with fixed JSON empty strings and
    canonicalize once. Returns ``(projected_bytes, projected_sha256_hex,
    projected_size)``."""
    projected = dict(template)
    for field in BUNDLE_SELF_FIELDS:
        projected[field] = ""
    projected_bytes = canonical_bytes(projected)
    return projected_bytes, hashlib.sha256(projected_bytes).hexdigest(), len(projected_bytes)


def build_bundle_manifest(entries: Sequence[Mapping]) -> dict:
    return {"schema": "wiki-artifact-bundle-manifest-v1", "entries": list(entries)}


def compute_bundle_digest(manifest: Mapping) -> tuple[bytes, str]:
    """Returns ``(manifest_canonical_bytes, bundle_sha256_hex)``."""
    manifest_bytes = canonical_bytes(manifest)
    return manifest_bytes, hashlib.sha256(manifest_bytes).hexdigest()


def bundle_artifact_name(lower_kind: str, run: str, attempt: str, bundle_sha256: str) -> str:
    return f"encrypted-lifecycle-{lower_kind}-{run}-{attempt}-{bundle_sha256[:16]}"


# ---------------------------------------------------------------------------
# 9. Envelope content-addressed identity (ADR-0026 §8).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SealedEnvelope:
    nonce_hex: str
    ciphertext_hex: str
    tag_hex: str

    def envelope_bytes(self) -> bytes:
        return bytes.fromhex(self.nonce_hex) + bytes.fromhex(self.ciphertext_hex) + bytes.fromhex(self.tag_hex)

    def blob_id(self) -> str:
        """blob_id = SHA-256(envelope_bytes), computed over the exact
        persisted envelope byte sequence (nonce + ciphertext + tag)."""
        return hashlib.sha256(self.envelope_bytes()).hexdigest()
