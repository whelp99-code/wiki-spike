"""Closed Core document parser port and parse result/error contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

from .errors import InvalidContractValue, UnsupportedContractVersion
from .second_brain_source_profiles import ParserCapabilityV2 as ParserCapabilityV2

DOCUMENT_PARSE_REQUEST_VERSION: Final = "second-brain-document-parse-request/v1"
DOCUMENT_ROOT_PROFILE: Final = "Document root"
LOCATOR_VALUE_MAX: Final = 128


class DocumentParseErrorCodeV1(StrEnum):
    INVALID_INPUT = "INVALID_INPUT"
    FORMAT_UNSUPPORTED = "FORMAT_UNSUPPORTED"
    OCR_REQUIRED = "OCR_REQUIRED"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"


class DocumentLocatorKindV1(StrEnum):
    LINE = "line"
    RECORD = "record"
    PAGE = "page"
    SECTION = "section"
    TABLE = "table"
    SHEET = "sheet"
    CELL = "cell"


@dataclass(frozen=True, slots=True)
class DocumentLocatorV1:
    kind: DocumentLocatorKindV1
    value: str

    def __post_init__(self) -> None:
        encoded = self.value.encode("utf-8")
        if not self.value or "\x00" in self.value or len(encoded) > LOCATOR_VALUE_MAX:
            raise InvalidContractValue("locator value must be a bounded non-empty string")


@dataclass(frozen=True, slots=True)
class DocumentParseRequestV1:
    version: str
    capability: ParserCapabilityV2
    media_type: str
    payload: bytes

    def __post_init__(self) -> None:
        if self.version != DOCUMENT_PARSE_REQUEST_VERSION:
            raise UnsupportedContractVersion("unsupported document parse request version")
        if not self.media_type or "\x00" in self.media_type:
            raise InvalidContractValue("media_type must be a non-empty string")


@dataclass(frozen=True, slots=True)
class DocumentParseRecordV1:
    locator: DocumentLocatorV1
    text: str

    def __post_init__(self) -> None:
        if "\x00" in self.text:
            raise InvalidContractValue("record text must not contain NUL")


@dataclass(frozen=True, slots=True)
class DocumentParseSuccessV1:
    capability: ParserCapabilityV2
    records: tuple[DocumentParseRecordV1, ...]


@dataclass(frozen=True, slots=True)
class DocumentParseFailureV1:
    capability: ParserCapabilityV2
    code: DocumentParseErrorCodeV1


type DocumentParseResultV1 = DocumentParseSuccessV1 | DocumentParseFailureV1


@runtime_checkable
class DocumentParserPort(Protocol):
    """Closed parser implementation boundary. Implementations live outside Core."""

    @property
    def capability(self) -> ParserCapabilityV2: ...

    def parse(self, request: DocumentParseRequestV1) -> DocumentParseResultV1: ...


@runtime_checkable
class DocumentFilesystemPort(Protocol):
    """Opaque document-byte reader. Implementations live outside Core."""

    def read_document(self, document_ref: str) -> bytes: ...


__all__ = (
    "DOCUMENT_PARSE_REQUEST_VERSION",
    "DOCUMENT_ROOT_PROFILE",
    "LOCATOR_VALUE_MAX",
    "DocumentFilesystemPort",
    "DocumentLocatorKindV1",
    "DocumentLocatorV1",
    "DocumentParseErrorCodeV1",
    "DocumentParseFailureV1",
    "DocumentParseRecordV1",
    "DocumentParseRequestV1",
    "DocumentParseResultV1",
    "DocumentParseSuccessV1",
    "DocumentParserPort",
    "ParserCapabilityV2",
)
