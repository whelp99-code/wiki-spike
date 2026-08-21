"""Verify LIVE_EXPORT_ONLY bytes and issue a process-local grant.

The only public issuance path is ``verify_export_only_authorization``. It
accepts canonical body bytes, envelopes, trusted bindings, expected digests,
trusted time, and a nonce store. No public API accepts a parsed authorization
and mints a grant. ``_issue_export_grant`` is module-private in this file.
"""
from __future__ import annotations

import secrets
from collections.abc import Mapping
from threading import Lock
from typing import ClassVar, Final, NoReturn, final, override

from wiki_spike.applications.unified_db_export_authorization_checks import (
    bind_expected_digests,
    bind_export_signatures,
    bind_trusted_time,
    snapshot_from_canonical_bytes,
)
from wiki_spike.applications.unified_db_export_authorization_types import (
    ExpectedExportAuthorizationDigestsV1,
    ExportAuthorizationVerifyRequestV1,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization import (
    UnifiedDbExportOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    ExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

__all__ = (
    "ExpectedExportAuthorizationDigestsV1",
    "ExportAuthorizationVerifyRequestV1",
    "VerifiedUnifiedDbExportAuthorityV1",
    "verify_export_only_authorization",
)

_HANDLE_SIZE: Final = 32
_LOCK = Lock()
_GRANTS: dict[bytes, UnifiedDbExportOnlyAuthorizationV1] = {}


class _ClaimMint:
    """Capability that only claim() holds."""


_CLAIM_MINT = _ClaimMint()


@final
class ClaimedUnifiedDbExportAuthorityV1:
    """Internal claimed grant. Not a public constructible authority."""

    __slots__: ClassVar[tuple[str, ...]] = ("__authorization",)

    def __init__(
        self,
        mint: _ClaimMint,
        authorization: UnifiedDbExportOnlyAuthorizationV1,
    ) -> None:
        if mint is not _CLAIM_MINT:
            raise InvalidContractValue("claimed export authority must be minted")
        self.__authorization = authorization

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> ClaimedUnifiedDbExportAuthorityV1:
        _ = data
        raise InvalidContractValue("claimed export authority cannot be constructed from JSON")

    @property
    def authorization(self) -> UnifiedDbExportOnlyAuthorizationV1:
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
    def profile_digest(self) -> str:
        return self.__authorization.profile_digest

    @property
    def plan_digest(self) -> str:
        return self.__authorization.plan_digest

    @property
    def mapping_digest(self) -> str:
        return self.__authorization.mapping_digest

    @property
    def adapter_digest(self) -> str:
        return self.__authorization.adapter_digest

    @property
    def inventory_digest(self) -> str:
        return self.__authorization.inventory_digest

    @property
    def destination_digest(self) -> str:
        return self.__authorization.destination_digest

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
        raise UnifiedDbExportError("claimed export authority cannot be pickled")

    @override
    def __reduce__(self) -> NoReturn:
        raise UnifiedDbExportError("claimed export authority cannot be pickled")


@final
class VerifiedUnifiedDbExportAuthorityV1:
    """Opaque handle. ``claim()`` atomically pops the grant once."""

    __slots__: ClassVar[tuple[str, ...]] = ("__handle",)

    def __init__(self, handle: bytes) -> None:
        if len(handle) != _HANDLE_SIZE:
            raise InvalidContractValue("verified export authority handle is invalid")
        self.__handle = handle

    @classmethod
    def from_mapping(
        cls, data: Mapping[str, JsonValue]
    ) -> VerifiedUnifiedDbExportAuthorityV1:
        _ = data
        raise InvalidContractValue(
            "verified export authority cannot be constructed from JSON"
        )

    def claim(self) -> ClaimedUnifiedDbExportAuthorityV1:
        with _LOCK:
            grant = _GRANTS.pop(self.__handle, None)
        if grant is None:
            raise UnifiedDbExportError("verified export authority was already claimed")
        return ClaimedUnifiedDbExportAuthorityV1(_CLAIM_MINT, grant)

    def __copy__(self) -> VerifiedUnifiedDbExportAuthorityV1:
        return VerifiedUnifiedDbExportAuthorityV1(self.__handle)

    def __deepcopy__(
        self, memo: dict[int, VerifiedUnifiedDbExportAuthorityV1]
    ) -> VerifiedUnifiedDbExportAuthorityV1:
        _ = memo
        return VerifiedUnifiedDbExportAuthorityV1(self.__handle)

    @override
    def __getstate__(self) -> NoReturn:
        raise UnifiedDbExportError("verified export authority cannot be pickled")

    @override
    def __reduce__(self) -> NoReturn:
        raise UnifiedDbExportError("verified export authority cannot be pickled")


def _issue_export_grant(
    authorization: UnifiedDbExportOnlyAuthorizationV1,
) -> VerifiedUnifiedDbExportAuthorityV1:
    handle = secrets.token_bytes(_HANDLE_SIZE)
    with _LOCK:
        _GRANTS[handle] = authorization
    return VerifiedUnifiedDbExportAuthorityV1(handle)


def verify_export_only_authorization(
    request: ExportAuthorizationVerifyRequestV1,
    nonces: ExportAuthorizationNonceStore,
) -> VerifiedUnifiedDbExportAuthorityV1:
    snapshot = snapshot_from_canonical_bytes(request.body_bytes)
    authorization = UnifiedDbExportOnlyAuthorizationV1.from_mapping(snapshot)
    nonces.reserve_and_consume(
        authorization_id=authorization.authorization_id,
        nonce=authorization.nonce,
        authorization_digest=authorization.authorization_digest,
        authorization_issued_at=authorization.issued_at,
    )
    bind_expected_digests(authorization, request.expected)
    bind_trusted_time(authorization, request.now)
    bind_export_signatures(snapshot, request.envelopes, request.trusted)
    return _issue_export_grant(authorization)
