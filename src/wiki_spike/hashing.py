"""Hashing primitives (v3.3 §3, §4-4).

- canonical_hash: sha256 over canonical bytes.
- merkle_root: sorted-leaf, domain-separated Merkle root used for
  accepted_claim_set_root. Sorting the leaves makes the root order-independent,
  which is what "set" semantics require.
"""
from __future__ import annotations

import hashlib
from typing import Any

from .canonical import canonical_bytes

_LEAF = b"\x00"  # domain separation to prevent second-preimage across leaf/node
_NODE = b"\x01"
_EMPTY = b"wiki.merkle.empty.v1"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return sha256_hex(canonical_bytes(value))


def merkle_root(leaves: list[bytes]) -> str:
    """Order-independent Merkle root over raw leaf byte-strings."""
    if not leaves:
        return sha256_hex(_EMPTY)
    nodes = sorted(hashlib.sha256(_LEAF + leaf).digest() for leaf in leaves)
    while len(nodes) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]  # promote odd
            nxt.append(hashlib.sha256(_NODE + left + right).digest())
        nodes = nxt
    return nodes[0].hex()
