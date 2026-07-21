"""Signing rules (v3.3 §3).

- Algorithm: Ed25519.
- Domain separator prefixed to signed bytes ("wiki.generation.v1") so signatures
  cannot be replayed across protocols/versions.
- Keyring resolves signer_key_id -> public key. Rotation = keep old key_ids in the
  keyring during an overlap window so past generations still verify.
"""
from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DOMAIN_SEPARATOR = b"wiki.generation.v1"


def _framed(payload: bytes) -> bytes:
    return DOMAIN_SEPARATOR + b"\x00" + payload


class Keyring:
    def __init__(self) -> None:
        self._priv: dict[str, Ed25519PrivateKey] = {}
        self._pub: dict[str, Ed25519PublicKey] = {}

    def generate(self, key_id: str) -> str:
        priv = Ed25519PrivateKey.generate()
        self._priv[key_id] = priv
        self._pub[key_id] = priv.public_key()
        return key_id

    def add_public(self, key_id: str, pub: Ed25519PublicKey) -> None:
        self._pub[key_id] = pub

    def public_bytes(self, key_id: str) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._pub[key_id].public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def sign(self, key_id: str, payload: bytes) -> bytes:
        return self._priv[key_id].sign(_framed(payload))

    def sign_domain(self, key_id: str, domain: str, payload: bytes) -> bytes:
        return self._priv[key_id].sign(domain.encode("utf-8") + b"\x00" + payload)

    def verify_domain(self, key_id: str, domain: str, payload: bytes, signature: bytes) -> bool:
        pub = self._pub.get(key_id)
        if pub is None:
            return False
        try:
            pub.verify(signature, domain.encode("utf-8") + b"\x00" + payload)
            return True
        except InvalidSignature:
            return False

    def verify(self, key_id: str, payload: bytes, signature: bytes) -> bool:
        pub = self._pub.get(key_id)
        if pub is None:
            return False
        try:
            pub.verify(signature, _framed(payload))
            return True
        except InvalidSignature:
            return False

    def load_or_create(self, key_id: str, path) -> str:
        """Persist/load a raw Ed25519 private key so the CLI signs stably across runs."""
        from pathlib import Path

        from cryptography.hazmat.primitives import serialization

        p = Path(path)
        if p.exists():
            priv = Ed25519PrivateKey.from_private_bytes(p.read_bytes())
        else:
            priv = Ed25519PrivateKey.generate()
            p.write_bytes(
                priv.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
            import os

            os.chmod(p, 0o600)
        self._priv[key_id] = priv
        self._pub[key_id] = priv.public_key()
        return key_id
