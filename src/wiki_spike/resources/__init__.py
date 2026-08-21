"""Packaged Mac production resource bytes."""
from __future__ import annotations

from importlib.resources import files

_SQLCIPHER_FEASIBILITY = "sqlcipher-feasibility-darwin-arm64.json"
_TRUSTED_BINDINGS = "trusted-bindings.json"
_EXPECTED_SCOPES = "expected-scopes.json"
_ENVELOPE_SCHEMA = "envelope-v1.schema.json"
_DELETION_STATE_SCHEMA = "deletion-state-v1.schema.json"
_STATE_DELTA_SCHEMA = "state-delta-v1.schema.json"


def load_pinned_sqlcipher_artifact_bytes() -> bytes:
    """Return the committed Darwin/arm64 SQLCipher feasibility JSON bytes."""
    return files("wiki_spike.resources").joinpath(_SQLCIPHER_FEASIBILITY).read_bytes()


def load_pinned_trusted_bindings_bytes() -> bytes:
    """Return the committed public trusted-bindings JSON bytes."""
    return files("wiki_spike.resources").joinpath(_TRUSTED_BINDINGS).read_bytes()


def load_pinned_expected_scopes_bytes() -> bytes:
    """Return the committed public expected-scopes JSON bytes."""
    return files("wiki_spike.resources").joinpath(_EXPECTED_SCOPES).read_bytes()


def load_encrypted_cas_envelope_schema_bytes() -> bytes:
    """Return the committed Encrypted CAS envelope JSON Schema bytes."""
    return files("wiki_spike.resources").joinpath(_ENVELOPE_SCHEMA).read_bytes()


def load_deletion_state_schema_bytes() -> bytes:
    """Return the committed deletion-state JSON Schema bytes."""
    return files("wiki_spike.resources").joinpath(_DELETION_STATE_SCHEMA).read_bytes()


def load_state_delta_schema_bytes() -> bytes:
    """Return the committed StateDelta JSON Schema bytes."""
    return files("wiki_spike.resources").joinpath(_STATE_DELTA_SCHEMA).read_bytes()
