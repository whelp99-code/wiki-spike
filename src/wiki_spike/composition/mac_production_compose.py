"""Existing-only Mac CAS/Keychain admission, bind, and product composition."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from wiki_spike.composition.second_brain_product import (
    ProductCompositionError,
    SecondBrainProductV2,
    compose_second_brain_product_v2,
)
from wiki_spike.infrastructure.encrypted_cas import (
    EncryptedCASError,
    EncryptedContentStore,
)
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase
from wiki_spike.infrastructure.macos_keychain import ProductionCustodyError
from wiki_spike.infrastructure.macos_keychain_existing import (
    MAC_KEYCHAIN_SERVICE,
    SERVING_ARK_HANDLE,
    open_existing_macos_keychain_store,
)
from wiki_spike.infrastructure.persistence_profile import (
    PersistenceProfileAuthorizationError,
    bind_mac_persistence_profile,
)
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    AuthorityProvenanceV2,
    RecallTrustVerifierV2,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    SecurityContextAuthority,
)

PINNED_RECALL_VERIFIER: RecallTrustVerifierV2 | None = None
PINNED_CLOCK: Callable[[], str] | None = None
PINNED_PROVENANCE: Mapping[str, AuthorityProvenanceV2] | None = None
PINNED_SNAPSHOT_SIGNER: Callable[[bytes], str] | None = None
PINNED_SIGNER_REF: str | None = None
PINNED_KEY_ID: str | None = None


class MacProductionComposeError(Exception):
    """Existing-only CAS/Keychain admission, bind, or composition refused."""


def compose_existing_mac_product(
    *,
    v1_dir: Path,
    database: LifecycleDatabase,
    authorization: object,
    workspace_ref: str,
    keychain_directory: Path,
    authority: SecurityContextAuthority,
) -> SecondBrainProductV2:
    """Open existing CAS/Keychain, bind authorization, and compose if pinned."""
    try:
        cas = EncryptedContentStore.open_existing(v1_dir / "cas")
        _ = open_existing_macos_keychain_store(
            index_dir=v1_dir / "keychain",
            service=MAC_KEYCHAIN_SERVICE,
            namespace=workspace_ref,
            ark_handle=SERVING_ARK_HANDLE,
            keychain_directory=keychain_directory,
        )
        profile = bind_mac_persistence_profile(
            authorization,
            database=database,
            cas=cas,
        )
        return compose_second_brain_product_v2(
            authority=authority,
            database=database,
            cas=cas,
            persistence_profile=profile,
            verifier=PINNED_RECALL_VERIFIER,
            clock=PINNED_CLOCK,
            provenance=PINNED_PROVENANCE,
            snapshot_signer=PINNED_SNAPSHOT_SIGNER,
            signer_ref=PINNED_SIGNER_REF,
            key_id=PINNED_KEY_ID,
        )
    except (
        EncryptedCASError,
        ProductionCustodyError,
        PersistenceProfileAuthorizationError,
        ProductCompositionError,
    ) as exc:
        raise MacProductionComposeError(str(exc)) from exc
