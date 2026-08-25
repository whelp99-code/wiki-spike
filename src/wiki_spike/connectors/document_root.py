"""Typed Document root connector. Depends only on Core."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from wiki_spike.memory_core.second_brain_document_parser_ports import (
    DOCUMENT_ROOT_PROFILE,
    DocumentParseErrorCodeV1,
    DocumentParseFailureV1,
    DocumentParseRequestV1,
    DocumentParseResultV1,
    DocumentParserPort,
)
from wiki_spike.memory_core.second_brain_source_profiles import ParserCapabilityNameV2, ParserCapabilityV2


@dataclass(frozen=True, slots=True)
class DocumentParserCompositionError(Exception):
    reason: str

    def __str__(self) -> str:
        return self.reason


class DocumentRootConnector:
    """Routes one Document root payload to an injected Core parser."""

    source_profile: Final = DOCUMENT_ROOT_PROFILE

    def __init__(self, parsers: Mapping[ParserCapabilityNameV2, DocumentParserPort]) -> None:
        roster = MappingProxyType(dict(parsers))
        if not roster:
            raise DocumentParserCompositionError("missing parser capability")
        self._parsers = roster

    def parse(self, request: DocumentParseRequestV1) -> DocumentParseResultV1:
        parser = self._parsers.get(request.capability.name)
        if parser is None:
            return DocumentParseFailureV1(request.capability, DocumentParseErrorCodeV1.FORMAT_UNSUPPORTED)
        if len(request.payload) > request.capability.max_bytes:
            return DocumentParseFailureV1(request.capability, DocumentParseErrorCodeV1.LIMIT_EXCEEDED)
        if request.media_type not in request.capability.media_types:
            return DocumentParseFailureV1(request.capability, DocumentParseErrorCodeV1.FORMAT_UNSUPPORTED)
        return parser.parse(request)


__all__ = (
    "DOCUMENT_ROOT_PROFILE",
    "DocumentParserCompositionError",
    "DocumentRootConnector",
    "ParserCapabilityV2",
)
