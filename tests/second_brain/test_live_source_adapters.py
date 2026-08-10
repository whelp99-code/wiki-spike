from __future__ import annotations

from hashlib import sha256
from base64 import b64encode
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import pytest

from wiki_spike.connectors.claude_memory_bank import ClaudeMemoryBankLiveSourceAdapter
from wiki_spike.connectors.codex import CodexLiveSourceAdapter
from wiki_spike.connectors.git import GitLiveSourceAdapter
from wiki_spike.connectors.markdown import MarkdownLiveSourceAdapter
from wiki_spike.composition.second_brain_capture import (
    CaptureCompositionError,
    compose_non_authorizing_live_source_adapters,
)
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients
from wiki_spike.memory_core.second_brain_contracts import (
    CONTRACT_SIGNING_DOMAIN, CONTRACT_SIGNATURE_VERSION, DECISION_SIGNING_DOMAIN,
    DECISION_SIGNATURE_VERSION, DecisionRecordV1, Ed25519SignatureEnvelopeV1,
    ExpectedScopeManifestV1, ResolvedScopeV1, SecondBrainContractDigestV1,
    SignedSecondBrainContractEnvelopeV1, SourceCheckpointV1, SourceItemDispositionV1,
    SourcePageV1, TrustedAuthorityBindingsV1, TrustedDecisionKeyBindingsV1,
    detached_signing_bytes,
)
from wiki_spike.memory_core.second_brain_security_contracts import mint_security_context_authority


ADAPTERS = (
    (CodexLiveSourceAdapter, "Codex", "api_client"),
    (ClaudeMemoryBankLiveSourceAdapter, "Claude/Memory Bank", "api_client"),
    (GitLiveSourceAdapter, "Git", "filesystem_client"),
    (MarkdownLiveSourceAdapter, "Markdown", "filesystem_client"),
)


def _public(key: Ed25519PrivateKey) -> str:
    return b64encode(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _authority(*, enabled: tuple[str, ...] = ("Codex", "Claude/Memory Bank", "Git", "Markdown"), expires_at: str = "2030-01-01T00:00:00Z", now: datetime | None = None):
    owner, approver = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    authority = TrustedAuthorityBindingsV1("approver", _public(approver), "owner", _public(owner))
    profiles = ("Claude/Memory Bank", "Codex", "Git", "Markdown")
    bindings = {("DB-01", "global", None): authority, ("DB-04", "global", None): authority, ("DB-05", "global", None): authority, ("DB-07", "global", None): authority, ("DB-03", "migration_source", "legacy Mem0/RAG"): authority, ("DB-03", "migration_source", "me-wiki"): authority, ("DB-03", "migration_source", "unified-db"): authority, ("DB-06", "external_model_route", "model-a"): authority, ("DB-08", "export_destination", "archive"): authority}
    bindings.update({("DB-02", "source_profile", profile): authority for profile in profiles})
    trusted = TrustedDecisionKeyBindingsV1(bindings, authority)
    def record(decision_id: str, scope_kind: str, scope_name: str | None, outcome: str = "GO") -> DecisionRecordV1:
        raw = {"decision_version": "second-brain-decision-record-v1", "decision_id": decision_id, "outcome": outcome, "scope_kind": scope_kind, "scope_name": scope_name, "record_revision": "1", "decided_at": "2026-01-01T00:00:00Z", "supersedes": None, "post_interview_reconciliation": {"original_question": "q", "reconciliation": "r"}, "reason": "test", "evidence_refs": ["e"], "evidence_digest": "a" * 64, "expires_at": expires_at}
        raw["signatures"] = [{"signature_version": DECISION_SIGNATURE_VERSION, "role": role, "key_id": name, "public_key_b64": _public(key), "signature_b64": b64encode(key.sign(detached_signing_bytes(DECISION_SIGNING_DOMAIN, raw))).decode()} for role, name, key in (("approver", "approver", approver), ("owner", "owner", owner))]
        return DecisionRecordV1.from_mapping(raw, now=now)
    decisions = [*(record(item, "global", None) for item in ("DB-01", "DB-04", "DB-05", "DB-07")), *(record("DB-02", "source_profile", profile, "GO" if profile in enabled else "NO_GO") for profile in profiles), *(record("DB-03", "migration_source", item) for item in ("legacy Mem0/RAG", "me-wiki", "unified-db")), record("DB-06", "external_model_route", "model-a"), record("DB-08", "export_destination", "archive")]
    scope = ResolvedScopeV1.from_mapping({"scope_version": "second-brain-resolved-scope-v1", "enabled_source_profiles": sorted(enabled), "disabled_source_profiles": {profile: "disabled" for profile in profiles if profile not in enabled}, "enabled_migration_sources": ["legacy Mem0/RAG", "me-wiki", "unified-db"], "disabled_migration_sources": {}, "feature_flags": ["benchmark-governance", "conflict-behavior", "cutover-retention", "identity-auth"], "egress_destinations": ["archive"], "enabled_external_model_routes": ["model-a"], "disabled_external_model_routes": {}, "disabled_export_destinations": {}, "capability_manifest_digest": "a" * 64, "source_manifest_digest": "a" * 64, "mandatory_release_constraints": ["test"]})
    expected = ExpectedScopeManifestV1.from_tuples(tuple(("DB-02", "source_profile", item) for item in profiles) + (("DB-03", "migration_source", "legacy Mem0/RAG"), ("DB-03", "migration_source", "me-wiki"), ("DB-03", "migration_source", "unified-db"), ("DB-06", "external_model_route", "model-a"), ("DB-08", "export_destination", "archive")))
    contract = SecondBrainContractDigestV1.create(decisions, scope, expected)
    payload = {"contract_version": contract.contract_version, "contract_body": contract.body(), "contract_digest": contract.digest}
    aggregate = SignedSecondBrainContractEnvelopeV1(contract, tuple(Ed25519SignatureEnvelopeV1.from_mapping({"signature_version": CONTRACT_SIGNATURE_VERSION, "role": role, "key_id": name, "public_key_b64": _public(key), "signature_b64": b64encode(key.sign(detached_signing_bytes(CONTRACT_SIGNING_DOMAIN, payload))).decode()}, version=CONTRACT_SIGNATURE_VERSION) for role, name, key in (("approver", "approver", approver), ("owner", "owner", owner))))
    return mint_security_context_authority(decisions, scope, expected, aggregate, trusted, now=now)


AUTHORITY = _authority()


def _disposition(*, kind: str = "ACCEPTED", retryable: bool = False) -> SourceItemDispositionV1:
    return SourceItemDispositionV1.from_mapping({
        "disposition_version": "second-brain-source-item-disposition-v1",
        "native_id": "native-1", "revision": "revision-1", "disposition": kind,
        "reason_code": "tested", "retryable": retryable,
    })


def _page(profile: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "page_version": "second-brain-source-page-v1", "source_profile": profile,
        "source_scope": "scope-1", "cursor": None, "watermark": None,
        "next_cursor": "cursor-1", "next_watermark": "watermark-1", "complete_snapshot": True,
        "items": [{
            "item_version": "second-brain-source-item-v1", "native_id": "native-1",
            "revision": "revision-1", "observed_cursor": "cursor-1",
            "observed_watermark": "watermark-1", "tombstone": False,
            "content_digest": sha256(b"content").hexdigest(), "disposition": _disposition().to_mapping(),
        }], "live_operation_authorized": False,
    }
    value.update(overrides)
    return value


class _CredentialProvider:
    def read_only_credential(self, *, source_scope: str) -> object:
        assert source_scope == "scope-1"
        return object()


class _ReadOnlyClient:
    read_only = True

    def __init__(self, value: dict[str, object]) -> None:
        self.value = value
        self.calls: list[dict[str, object]] = []

    def read_page(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return self.value


@pytest.mark.parametrize(("adapter_type", "profile", "client_kw"), ADAPTERS)
def test_each_typed_reader_binds_profile_scope_and_read_only_page(adapter_type, profile, client_kw) -> None:
    client = _ReadOnlyClient(_page(profile))
    adapter = adapter_type(**{client_kw: client, "credential_provider": _CredentialProvider(), "security_authority": AUTHORITY})
    page = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    assert page.source_profile == profile
    assert page.live_operation_authorized is False
    assert client.calls == [{"source_scope": "scope-1", "cursor": None, "watermark": None, "limit": 1, "credential": client.calls[0]["credential"]}]


def test_checkpoint_initial_retry_is_idempotent_and_stale_cas_is_rejected() -> None:
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    page = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    kwargs = dict(source_scope="scope-1", prior_checkpoint=None, next_cursor=page.next_cursor,
                  next_watermark=page.next_watermark, observed_page_digest=page.digest,
                  dispositions=(page.items[0].disposition,), tombstones=())
    checkpoint = adapter.commit(**kwargs)
    assert adapter.commit(**kwargs) == checkpoint
    with pytest.raises(ValueError, match="binding"):
        adapter.commit(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=page.digest,
                       next_cursor="cursor-2", next_watermark="watermark-2", dispositions=(), tombstones=())


@pytest.mark.parametrize("field", ("source_profile", "source_scope", "next_cursor", "next_watermark"))
def test_closed_page_dto_rejects_missing_or_unknown_fields(field: str) -> None:
    value = _page("Codex")
    value.pop(field)
    with pytest.raises(ValueError):
        SourcePageV1.from_mapping(value)
    with pytest.raises(ValueError):
        SourcePageV1.from_mapping({**_page("Codex"), "secret": "forbidden"})


def test_closed_disposition_and_checkpoint_dtos_reject_missing_or_unknown_fields() -> None:
    disposition = _disposition().to_mapping()
    with pytest.raises(ValueError):
        SourceItemDispositionV1.from_mapping({key: value for key, value in disposition.items() if key != "reason_code"})
    with pytest.raises(ValueError):
        SourceItemDispositionV1.from_mapping({**disposition, "raw_content": "forbidden"})
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    page = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    checkpoint = adapter.commit(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=page.digest, next_cursor=page.next_cursor, next_watermark=page.next_watermark, dispositions=(page.items[0].disposition,), tombstones=())
    mapping = checkpoint.to_mapping()
    with pytest.raises(ValueError):
        SourceCheckpointV1.from_mapping({key: value for key, value in mapping.items() if key != "source_profile"})
    with pytest.raises(ValueError):
        SourceCheckpointV1.from_mapping({**mapping, "unknown": True})


def test_live_source_composition_injects_all_four_clients_without_authorization() -> None:
    codex, claude = _ReadOnlyClient(_page("Codex")), _ReadOnlyClient(_page("Claude/Memory Bank"))
    git, markdown = _ReadOnlyClient(_page("Git")), _ReadOnlyClient(_page("Markdown"))
    providers = {profile: _CredentialProvider() for _, profile, _ in ADAPTERS}
    composition = compose_non_authorizing_live_source_adapters(
        security_authority=AUTHORITY,
        codex_api_client=codex, claude_memory_bank_api_client=claude,
        git_filesystem_client=git, markdown_filesystem_client=markdown,
        credential_providers=providers,
    )
    assert tuple(composition.readers) == tuple(profile for _, profile, _ in ADAPTERS)
    assert composition.live_operation_authorized is False
    assert all(reader.live_operation_authorized is False for reader in composition.readers.values())
    assert tuple(reader._client for reader in composition.readers.values()) == (codex, claude, git, markdown)  # type: ignore[attr-defined]
    assert not hasattr(composition, "capture") and not hasattr(composition, "activate") and not hasattr(composition, "serve")


def test_live_source_composition_rejects_fixture_client_and_incomplete_or_misbound_providers() -> None:
    clients = dict(
        codex_api_client=_ReadOnlyClient(_page("Codex")),
        claude_memory_bank_api_client=_ReadOnlyClient(_page("Claude/Memory Bank")),
        git_filesystem_client=_ReadOnlyClient(_page("Git")),
        markdown_filesystem_client=_ReadOnlyClient(_page("Markdown")),
    )
    providers = {profile: _CredentialProvider() for _, profile, _ in ADAPTERS}
    with pytest.raises(CaptureCompositionError, match="credential provider"):
        compose_non_authorizing_live_source_adapters(**clients, security_authority=AUTHORITY, credential_providers={"Codex": _CredentialProvider()})
    with pytest.raises(CaptureCompositionError, match="credential provider"):
        compose_non_authorizing_live_source_adapters(**clients, security_authority=AUTHORITY, credential_providers={**providers, "other": _CredentialProvider()})
    with pytest.raises(ValueError, match="low-level source client"):
        compose_non_authorizing_live_source_adapters(
            **{**clients, "codex_api_client": FixtureCaptureClients()}, security_authority=AUTHORITY, credential_providers=providers,
        )
