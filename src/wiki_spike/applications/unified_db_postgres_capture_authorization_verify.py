"""Verify metadata-capture bytes and issue a process-local grant.

The only public issuance path is ``verify_metadata_capture_authorization``.
No public API accepts a parsed authorization and mints a grant.
"""
from __future__ import annotations

import secrets
from collections.abc import Mapping
from threading import Lock
from typing import ClassVar, Final, NoReturn, final, override

from wiki_spike.applications.unified_db_postgres_capture_authorization_checks import (
    bind_capture_signatures,
    bind_expected_digests,
    bind_trusted_time,
    snapshot_from_canonical_bytes,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    ExpectedMetadataCaptureDigestsV1,
    MetadataCaptureVerifyRequestV1,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue, UnknownContractField
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    MetadataCaptureNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

__all__ = (
    "ExpectedMetadataCaptureDigestsV1",
    "MetadataCaptureVerifyRequestV1",
    "VerifiedUnifiedDbMetadataCaptureAuthorityV1",
    "verify_metadata_capture_authorization",
)

_HANDLE_SIZE: Final = 32
_LOCK = Lock()
_GRANTS: dict[bytes, UnifiedDbMetadataCaptureOnlyAuthorizationV1] = {}


class _ClaimMint:
    """Capability that only claim() holds."""


_CLAIM_MINT = _ClaimMint()


@final
class ClaimedUnifiedDbMetadataCaptureAuthorityV1:
    """Internal claimed grant. Not a public constructible authority."""

    __slots__: ClassVar[tuple[str, ...]] = ("__authorization",)

    def __init__(
        self,
        mint: _ClaimMint,
        authorization: UnifiedDbMetadataCaptureOnlyAuthorizationV1,
    ) -> None:
        if mint is not _CLAIM_MINT:
            raise InvalidContractValue("claimed metadata capture authority must be minted")
        self.__authorization = authorization

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> ClaimedUnifiedDbMetadataCaptureAuthorityV1:
        _ = data
        raise InvalidContractValue(
            "claimed metadata capture authority cannot be constructed from JSON"
        )

    @property
    def authorization(self) -> UnifiedDbMetadataCaptureOnlyAuthorizationV1:
        return self.__authorization

    @property
    def authorization_id(self) -> str:
        return self.__authorization.authorization_id

    @property
    def nonce(self) -> str:
        return self.__authorization.nonce

    @property
    def operation(self) -> str:
        return self.__authorization.operation

    @property
    def source_name(self) -> str:
        return self.__authorization.source_name

    @property
    def query_manifest_digest(self) -> str:
        return self.__authorization.query_manifest_digest

    @property
    def capture_plan_digest(self) -> str:
        return self.__authorization.capture_plan_digest

    @property
    def output_digest(self) -> str:
        return self.__authorization.output_digest

    @property
    def issued_at(self) -> str:
        return self.__authorization.issued_at

    @property
    def not_before(self) -> str:
        return self.__authorization.not_before

    @property
    def expires_at(self) -> str:
        return self.__authorization.expires_at

    @property
    def authorization_digest(self) -> str:
        return self.__authorization.authorization_digest

    @override
    def __getstate__(self) -> NoReturn:
        raise UnifiedDbExportError("claimed metadata capture authority cannot be pickled")

    @override
    def __reduce__(self) -> NoReturn:
        raise UnifiedDbExportError("claimed metadata capture authority cannot be pickled")


@final
class VerifiedUnifiedDbMetadataCaptureAuthorityV1:
    """Opaque handle. ``claim()`` atomically pops the grant once."""

    __slots__: ClassVar[tuple[str, ...]] = ("__handle",)

    def __init__(self, handle: bytes) -> None:
        if len(handle) != _HANDLE_SIZE:
            raise InvalidContractValue("verified metadata capture authority handle is invalid")
        self.__handle = handle

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
        _ = data
        raise InvalidContractValue(
            "verified metadata capture authority cannot be constructed from JSON"
        )

    def claim(self) -> ClaimedUnifiedDbMetadataCaptureAuthorityV1:
        with _LOCK:
            grant = _GRANTS.pop(self.__handle, None)
        if grant is None:
            raise UnifiedDbExportError("verified metadata capture authority was already claimed")
        return ClaimedUnifiedDbMetadataCaptureAuthorityV1(_CLAIM_MINT, grant)

    def __copy__(self) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
        return VerifiedUnifiedDbMetadataCaptureAuthorityV1(self.__handle)

    def __deepcopy__(
        self, memo: dict[int, VerifiedUnifiedDbMetadataCaptureAuthorityV1]
    ) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
        _ = memo
        return VerifiedUnifiedDbMetadataCaptureAuthorityV1(self.__handle)

    @override
    def __getstate__(self) -> NoReturn:
        raise UnifiedDbExportError("verified metadata capture authority cannot be pickled")

    @override
    def __reduce__(self) -> NoReturn:
        raise UnifiedDbExportError("verified metadata capture authority cannot be pickled")


def _issue_capture_grant(
    authorization: UnifiedDbMetadataCaptureOnlyAuthorizationV1,
) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
    handle = secrets.token_bytes(_HANDLE_SIZE)
    with _LOCK:
        _GRANTS[handle] = authorization
    return VerifiedUnifiedDbMetadataCaptureAuthorityV1(handle)


def verify_metadata_capture_authorization(
    request: MetadataCaptureVerifyRequestV1,
    nonces: MetadataCaptureNonceStore,
) -> VerifiedUnifiedDbMetadataCaptureAuthorityV1:
    snapshot = snapshot_from_canonical_bytes(request.body_bytes)
    try:
        authorization = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(snapshot)
    except UnknownContractField as exc:
        raise InvalidContractValue("authorization is not metadata-capture-only") from exc
    nonces.reserve_and_consume(
        authorization_id=authorization.authorization_id,
        nonce=authorization.nonce,
        authorization_digest=authorization.authorization_digest,
        authorization_issued_at=authorization.issued_at,
    )
    bind_expected_digests(authorization, request.expected)
    bind_trusted_time(authorization, request.now)
    bind_capture_signatures(snapshot, request.envelopes, request.trusted)
    return _issue_capture_grant(authorization)
