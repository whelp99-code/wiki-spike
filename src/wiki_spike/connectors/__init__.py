"""Fixture-only Stage-2 typed source connectors.

These connectors implement the frozen capture reader port.  They consume only
opaque fixture request references through a frozen low-level port; they neither
open source locations nor resolve credentials.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Mapping, Sequence
from hashlib import sha256
from typing import Any, Final

from wiki_spike.memory_core.second_brain_capture_contracts import (
    CapturedItemV1,
    EncryptedNativeMappingRefV1,
    SourceScopeRefV1,
)
from wiki_spike.memory_core.second_brain_capture_ports import (
    CaptureApiPort,
    ConnectorSourceReaderPort,
    EncryptedNativeMappingSealerPort,
)

_FIXTURE_VERSION: Final = "second-brain-connector-fixture-v1"
_FIELDS: Final = frozenset({
    "fixture_version", "source_profile", "source_domain", "scope_ref", "scope_epoch",
    "scan_epoch", "capture_ref", "encrypted_content_ref", "ciphertext_b64",
    "native_mapping",
})
_REF = re.compile(r"^[a-z][a-z0-9_-]{0,63}:[0-9a-f]{64}$")
_POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
_MAX_FIXTURES: Final = 1024
_MAX_CIPHERTEXT_BYTES: Final = 4 * 1024 * 1024
_MAX_TOTAL_CIPHERTEXT_BYTES: Final = 16 * 1024 * 1024


class FixtureConnectorError(ValueError):
    """A fixture connector input is invalid and must not be captured."""


class FixtureConnectorReader(ConnectorSourceReaderPort):
    """Shared fixture-only reader for one closed source profile.

    Fixture request references are opaque keys understood only by the supplied
    low-level fixture port. Native mappings are canonicalized and immediately
    sealed; this reader retains no native identifiers, paths, or bodies.
    """

    source_profile: Final[str]
    source_domain: Final[str]

    def __init__(
        self,
        fixture_client: CaptureApiPort,
        native_mapping_sealer: EncryptedNativeMappingSealerPort,
        fixture_request_refs: Sequence[str],
    ) -> None:
        refs = tuple(fixture_request_refs)
        if not refs or len(refs) > _MAX_FIXTURES:
            raise FixtureConnectorError("fixture request count is outside the permitted limit")
        if len(set(refs)) != len(refs) or any(not isinstance(ref, str) or _REF.fullmatch(ref) is None for ref in refs):
            raise FixtureConnectorError("fixture request references must be unique keyed opaque references")
        self._fixture_client = fixture_client
        self._native_mapping_sealer = native_mapping_sealer
        self._fixture_request_refs = tuple(sorted(refs))

    def read_fixture_capture_items(self, scope: SourceScopeRefV1, scan_epoch: str) -> tuple[CapturedItemV1, ...]:
        self._validate_scope(scope, scan_epoch)
        parsed = tuple(self._parse_fixture(self._fixture_client.read_fixture_payload(ref), scope, scan_epoch) for ref in self._fixture_request_refs)
        if len({item[0] for item in parsed}) != len(parsed):
            raise FixtureConnectorError("fixture capture references must be unique")
        if sum(len(item[1]) for item in parsed) > _MAX_TOTAL_CIPHERTEXT_BYTES:
            raise FixtureConnectorError("fixture ciphertext total exceeds the permitted limit")
        items: list[CapturedItemV1] = []
        for capture_ref, ciphertext, encrypted_content_ref, native_mapping in sorted(parsed, key=lambda item: (item[0], sha256(item[1]).digest())):
            sealed = self._native_mapping_sealer.seal_native_mapping(scope, capture_ref, native_mapping)
            if not isinstance(sealed, EncryptedNativeMappingRefV1) or sealed.capture_ref != capture_ref:
                raise FixtureConnectorError("native mapping sealer must return the exact capture-bound mapping reference")
            items.append(CapturedItemV1(capture_ref, ciphertext, encrypted_content_ref, sealed.encrypted_native_mapping_ref))
        return tuple(items)

    def _validate_scope(self, scope: SourceScopeRefV1, scan_epoch: str) -> None:
        if not isinstance(scope, SourceScopeRefV1) or scope.source_profile != self.source_profile or scope.source_domain != self.source_domain:
            raise FixtureConnectorError("scope does not match connector source profile and domain")
        if not isinstance(scan_epoch, str) or _POSITIVE_DECIMAL.fullmatch(scan_epoch) is None:
            raise FixtureConnectorError("scan epoch must be a canonical positive epoch")

    def _parse_fixture(self, payload: bytes, scope: SourceScopeRefV1, scan_epoch: str) -> tuple[str, bytes, str, bytes]:
        if not isinstance(payload, bytes):
            raise FixtureConnectorError("fixture payload must be bytes")
        try:
            value: Any = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FixtureConnectorError("fixture payload must be a JSON object") from exc
        if not isinstance(value, Mapping) or set(value) != _FIELDS:
            raise FixtureConnectorError("fixture payload fields are invalid")
        if (value["fixture_version"] != _FIXTURE_VERSION
                or value["source_profile"] != self.source_profile
                or value["source_domain"] != self.source_domain
                or value["scope_ref"] != scope.scope_ref
                or value["scope_epoch"] != scope.scope_epoch
                or value["scan_epoch"] != scan_epoch):
            raise FixtureConnectorError("fixture payload does not bind the requested source scope and epochs")
        capture_ref = value["capture_ref"]
        if not isinstance(capture_ref, str) or not capture_ref.startswith("capture:") or _REF.fullmatch(capture_ref) is None:
            raise FixtureConnectorError("fixture capture reference must be a capture opaque reference")
        ciphertext = self._decode_ciphertext(value["ciphertext_b64"])
        encrypted_content_ref = value["encrypted_content_ref"]
        if (not isinstance(encrypted_content_ref, str)
                or not encrypted_content_ref.startswith("encrypted-content:")
                or _REF.fullmatch(encrypted_content_ref) is None):
            raise FixtureConnectorError("fixture encrypted content reference must be an encrypted-content opaque reference")
        native_mapping = value["native_mapping"]
        if not isinstance(native_mapping, Mapping):
            raise FixtureConnectorError("fixture native mapping must be an object")
        try:
            native_mapping_bytes = json.dumps(native_mapping, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise FixtureConnectorError("fixture native mapping is not JSON-canonicalizable") from exc
        return capture_ref, ciphertext, encrypted_content_ref, native_mapping_bytes

    @staticmethod
    def _decode_ciphertext(value: Any) -> bytes:
        if not isinstance(value, str):
            raise FixtureConnectorError("fixture ciphertext must be base64 text")
        try:
            ciphertext = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise FixtureConnectorError("fixture ciphertext is not valid base64") from exc
        if not ciphertext or len(ciphertext) > _MAX_CIPHERTEXT_BYTES:
            raise FixtureConnectorError("fixture ciphertext size is outside the permitted limit")
        return ciphertext


from .claude_memory_bank import ClaudeMemoryBankFixtureConnector
from .codex import CodexFixtureConnector
from .git import GitFixtureConnector
from .markdown import MarkdownFixtureConnector

__all__ = [
    "ClaudeMemoryBankFixtureConnector",
    "CodexFixtureConnector",
    "FixtureConnectorError",
    "FixtureConnectorReader",
    "GitFixtureConnector",
    "MarkdownFixtureConnector",
]
