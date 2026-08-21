"""Packaged Mac production resource bytes."""
from __future__ import annotations

from importlib.resources import files

_SQLCIPHER_FEASIBILITY = "sqlcipher-feasibility-darwin-arm64.json"
_TRUSTED_BINDINGS = "trusted-bindings.json"
_EXPECTED_SCOPES = "expected-scopes.json"


def load_pinned_sqlcipher_artifact_bytes() -> bytes:
    """Return the committed Darwin/arm64 SQLCipher feasibility JSON bytes."""
    return files("wiki_spike.resources").joinpath(_SQLCIPHER_FEASIBILITY).read_bytes()


def load_pinned_trusted_bindings_bytes() -> bytes:
    """Return the committed public trusted-bindings JSON bytes."""
    return files("wiki_spike.resources").joinpath(_TRUSTED_BINDINGS).read_bytes()


def load_pinned_expected_scopes_bytes() -> bytes:
    """Return the committed public expected-scopes JSON bytes."""
    return files("wiki_spike.resources").joinpath(_EXPECTED_SCOPES).read_bytes()
