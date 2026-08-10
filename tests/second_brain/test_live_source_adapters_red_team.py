from __future__ import annotations

import ast
import threading
from hashlib import sha256
from pathlib import Path

import pytest

from wiki_spike.connectors.codex import CodexLiveSourceAdapter
from wiki_spike.connectors.git import GitLiveSourceAdapter
from wiki_spike.composition.second_brain_capture import CaptureCompositionError, compose_non_authorizing_live_source_adapters
from wiki_spike.infrastructure.fixture_capture_clients import FixtureCaptureClients
from wiki_spike.memory_core.second_brain_contracts import SourceItemDispositionV1
from test_live_source_adapters import AUTHORITY, _authority


class _CredentialProvider:
    def read_only_credential(self, *, source_scope: str) -> object:
        return object()


def _page(profile: str, **overrides: object) -> dict[str, object]:
    disposition = {"disposition_version": "second-brain-source-item-disposition-v1", "native_id": "native-1", "revision": "revision-1", "disposition": "ACCEPTED", "reason_code": "tested", "retryable": False}
    value: dict[str, object] = {"page_version": "second-brain-source-page-v1", "source_profile": profile, "source_scope": "scope-1", "cursor": None, "watermark": None, "next_cursor": "cursor-1", "next_watermark": "watermark-1", "complete_snapshot": True, "items": [{"item_version": "second-brain-source-item-v1", "native_id": "native-1", "revision": "revision-1", "observed_cursor": "cursor-1", "observed_watermark": "watermark-1", "tombstone": False, "content_digest": sha256(b"content").hexdigest(), "disposition": disposition}], "live_operation_authorized": False}
    value.update(overrides)
    return value


class _ReadOnlyClient:
    read_only = True

    def __init__(self, value: dict[str, object]) -> None:
        self.value = value
        self.calls: list[dict[str, object]] = []

    def read_page(self, **kwargs: object) -> dict[str, object]:
        self.calls.append(kwargs)
        return self.value


class _WriteCapableClient(_ReadOnlyClient):
    def write(self) -> None:
        pass


def _transient() -> SourceItemDispositionV1:
    return SourceItemDispositionV1.from_mapping({
        "disposition_version": "second-brain-source-item-disposition-v1",
        "native_id": "native-1", "revision": "revision-1", "disposition": "TRANSIENT_FAILURE",
        "reason_code": "transport-timeout", "retryable": True,
    })


def test_write_capable_and_fixture_clients_cannot_substitute_for_live_client() -> None:
    with pytest.raises(ValueError, match="write-capable"):
        CodexLiveSourceAdapter(api_client=_WriteCapableClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    with pytest.raises(ValueError, match="low-level source client"):
        CodexLiveSourceAdapter(api_client=FixtureCaptureClients(), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    for mutation in ("append", "patch", "unlink", "rename", "request"):
        client = _ReadOnlyClient(_page("Codex"))
        setattr(client, mutation, lambda: None)
        with pytest.raises(ValueError, match="write-capable"):
            CodexLiveSourceAdapter(api_client=client, credential_provider=_CredentialProvider(), security_authority=AUTHORITY)


@pytest.mark.parametrize(("cursor", "watermark"), (("cursor-0", None), (None, "watermark-0")))
def test_unpaired_requested_cursor_watermark_is_rejected_before_client_call(cursor: str | None, watermark: str | None) -> None:
    client = _ReadOnlyClient(_page("Codex"))
    adapter = CodexLiveSourceAdapter(api_client=client, credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    with pytest.raises(ValueError, match="source scope"):
        adapter.read_page(source_scope="scope-1", cursor=cursor, watermark=watermark, limit=1)
    assert client.calls == []


@pytest.mark.parametrize(("cursor", "watermark"), (("cursor-0", None), (None, "watermark-0")))
def test_page_dto_rejects_unpaired_current_cursor_watermark(cursor: str | None, watermark: str | None) -> None:
    with pytest.raises(ValueError, match="current cursor"):
        from wiki_spike.memory_core.second_brain_contracts import SourcePageV1
        SourcePageV1.from_mapping(_page("Codex", cursor=cursor, watermark=watermark))


@pytest.mark.parametrize("mutation", (
    {"source_profile": "Git"}, {"next_cursor": "cursor-2"}, {"next_watermark": "watermark-2"},
))
def test_reader_rejects_profile_or_cursor_watermark_substitution(mutation: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="pin"):
        CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex", **mutation)), credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(
            source_scope="scope-1", cursor=None, watermark=None, limit=1
        )


def test_reader_rejects_unpinned_revision_tombstone_and_pagination_overrun() -> None:
    unpinned = _page("Codex")
    unpinned["items"] = [{**unpinned["items"][0], "observed_cursor": "wrong"}]  # type: ignore[index]
    with pytest.raises(ValueError, match="pin"):
        CodexLiveSourceAdapter(api_client=_ReadOnlyClient(unpinned), credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    revision_substitution = _page("Codex")
    revision_substitution["items"] = [{**revision_substitution["items"][0], "revision": "revision-2"}]  # type: ignore[index]
    with pytest.raises(ValueError, match="disposition"):
        CodexLiveSourceAdapter(api_client=_ReadOnlyClient(revision_substitution), credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    tombstone = _page("Codex", complete_snapshot=False)
    item = dict(tombstone["items"][0])  # type: ignore[index]
    item.update({"tombstone": True, "content_digest": None, "disposition": {**item["disposition"], "disposition": "TOMBSTONE"}})
    tombstone["items"] = [item]
    with pytest.raises(ValueError, match="tombstones"):
        CodexLiveSourceAdapter(api_client=_ReadOnlyClient(tombstone), credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    overrun = _page("Codex")
    overrun["items"] = [overrun["items"][0], {**overrun["items"][0], "native_id": "native-2", "revision": "revision-2", "disposition": {**overrun["items"][0]["disposition"], "native_id": "native-2", "revision": "revision-2"}}]  # type: ignore[index]
    with pytest.raises(ValueError, match="exceeded"):
        CodexLiveSourceAdapter(api_client=_ReadOnlyClient(overrun), credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)


def _observed(adapter, *, cursor=None, watermark=None, next_cursor=None, next_watermark=None, dispositions=()):
    raw = _page("Codex", cursor=cursor, watermark=watermark, next_cursor=next_cursor, next_watermark=next_watermark, items=[])
    if dispositions:
        item = _page("Codex")["items"][0]
        item = {**item, "observed_cursor": next_cursor, "observed_watermark": next_watermark, "disposition": dispositions[0].to_mapping(), "tombstone": False, "content_digest": "a" * 64}
        raw["items"] = [item]
    adapter._client.value = raw
    return adapter.read_page(source_scope="scope-1", cursor=cursor, watermark=watermark, limit=1)


def test_page_bound_transient_and_initial_retry() -> None:
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    initial = _observed(adapter, dispositions=(_transient(),))
    kwargs = dict(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=initial.digest, next_cursor=None, next_watermark=None, dispositions=(_transient(),), tombstones=())
    checkpoint = adapter.commit(**kwargs)
    assert adapter.commit(**kwargs) == checkpoint
    with pytest.raises(ValueError, match="validated observed page"):
        adapter.commit(**{**kwargs, "observed_page_digest": "b" * 64})


def test_commit_rejects_synthesized_page_scope_or_disposition_and_preserves_state() -> None:
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    page = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    base = dict(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=page.digest, next_cursor=page.next_cursor, next_watermark=page.next_watermark, dispositions=(page.items[0].disposition,), tombstones=())
    for replacement in ({"observed_page_digest": "b" * 64}, {"source_scope": "other-scope"}, {"dispositions": ()}):
        with pytest.raises(ValueError):
            adapter.commit(**{**base, **replacement})
        assert adapter.load(source_scope="scope-1") is None


def test_cached_page_digest_binds_exact_revision_and_disposition_not_just_scope_position() -> None:
    client = _ReadOnlyClient(_page("Codex"))
    adapter = CodexLiveSourceAdapter(api_client=client, credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    page_a = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    raw_b = _page("Codex")
    item_b = dict(raw_b["items"][0])  # type: ignore[index]
    item_b["revision"] = "revision-2"
    item_b["disposition"] = {**item_b["disposition"], "revision": "revision-2", "disposition": "DUPLICATE"}
    raw_b["items"] = [item_b]
    client.value = raw_b
    page_b = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    assert (page_a.cursor, page_a.watermark, page_a.next_cursor, page_a.next_watermark) == (page_b.cursor, page_b.watermark, page_b.next_cursor, page_b.next_watermark)
    evidence_a = dict(next_cursor=page_a.next_cursor, next_watermark=page_a.next_watermark, dispositions=(page_a.items[0].disposition,), tombstones=())
    evidence_b = dict(next_cursor=page_b.next_cursor, next_watermark=page_b.next_watermark, dispositions=(page_b.items[0].disposition,), tombstones=())
    for digest, evidence in ((page_a.digest, evidence_b), (page_b.digest, evidence_a)):
        with pytest.raises(ValueError, match="dispositions"):
            adapter.commit(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=digest, **evidence)
        assert adapter.load(source_scope="scope-1") is None


def test_commit_revalidates_expired_corrupted_and_disabled_authority_before_mutation() -> None:
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    page = adapter.read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    kwargs = dict(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=page.digest, next_cursor=page.next_cursor, next_watermark=page.next_watermark, dispositions=(page.items[0].disposition,), tombstones=())
    from datetime import datetime, timezone
    expired = _authority(expires_at="2026-01-02T00:00:00Z", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    for authority in (expired, _authority(enabled=("Git",))):
        adapter._security_authority = authority
        with pytest.raises(ValueError, match="security context"):
            adapter.commit(**kwargs)
        assert adapter.load(source_scope="scope-1") is None
    corrupted = _authority()
    object.__setattr__(corrupted, "_SecurityContextAuthority__trusted_keys", object())
    adapter._security_authority = corrupted
    with pytest.raises(ValueError, match="security context"):
        adapter.commit(**kwargs)
    assert adapter.load(source_scope="scope-1") is None


def test_process_local_lock_allows_exactly_one_competing_successor_without_partial_state() -> None:
    adapter = CodexLiveSourceAdapter(api_client=_ReadOnlyClient(_page("Codex")), credential_provider=_CredentialProvider(), security_authority=AUTHORITY)
    initial = _observed(adapter)
    prior = adapter.commit(source_scope="scope-1", prior_checkpoint=None, observed_page_digest=initial.digest, next_cursor=None, next_watermark=None, dispositions=(), tombstones=())
    next_pages = [
        _observed(adapter, cursor=None, watermark=None, next_cursor="cursor-a", next_watermark="watermark-cursor-a"),
        _observed(adapter, cursor=None, watermark=None, next_cursor="cursor-b", next_watermark="watermark-cursor-b"),
    ]
    barrier = threading.Barrier(2)
    outcomes: list[object] = []
    def attempt(page) -> None:
        barrier.wait()
        try:
            outcomes.append(adapter.commit(source_scope="scope-1", prior_checkpoint=prior, observed_page_digest=page.digest, next_cursor=page.next_cursor, next_watermark=page.next_watermark, dispositions=(), tombstones=()))
        except ValueError as exc:
            outcomes.append(str(exc))
    threads = [threading.Thread(target=attempt, args=(page,)) for page in next_pages]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    successes = [item for item in outcomes if not isinstance(item, str)]
    failures = [item for item in outcomes if isinstance(item, str)]
    assert len(successes) == len(failures) == 1 and failures == ["checkpoint compare-and-swap conflict"]
    assert adapter.load(source_scope="scope-1") == successes[0]


def test_composition_and_read_fail_closed_or_select_only_stage0_enabled_profiles() -> None:
    clients = dict(codex_api_client=_ReadOnlyClient(_page("Codex")), claude_memory_bank_api_client=None, git_filesystem_client=None, markdown_filesystem_client=None)
    with pytest.raises(CaptureCompositionError, match="security authority"):
        compose_non_authorizing_live_source_adapters(**clients, security_authority=None, credential_providers={"Codex": _CredentialProvider()})
    codex_only = _authority(enabled=("Codex",))
    composition = compose_non_authorizing_live_source_adapters(**clients, security_authority=codex_only, credential_providers={"Codex": _CredentialProvider()})
    assert tuple(composition.readers) == ("Codex",) and composition.live_operation_authorized is False
    with pytest.raises(ValueError, match="security context"):
        GitLiveSourceAdapter(filesystem_client=_ReadOnlyClient(_page("Git")), credential_provider=_CredentialProvider(), security_authority=codex_only).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)


def test_expired_or_untrusted_minted_stage0_authority_fails_before_client_call() -> None:
    from datetime import datetime, timezone
    expired = _authority(expires_at="2026-01-02T00:00:00Z", now=datetime(2026, 1, 1, tzinfo=timezone.utc))
    expired_client = _ReadOnlyClient(_page("Codex"))
    with pytest.raises(ValueError, match="security context"):
        CodexLiveSourceAdapter(api_client=expired_client, credential_provider=_CredentialProvider(), security_authority=expired).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    assert expired_client.calls == []
    untrusted = _authority()
    object.__setattr__(untrusted, "_SecurityContextAuthority__trusted_keys", object())
    untrusted_client = _ReadOnlyClient(_page("Codex"))
    with pytest.raises(ValueError, match="security context"):
        CodexLiveSourceAdapter(api_client=untrusted_client, credential_provider=_CredentialProvider(), security_authority=untrusted).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    assert untrusted_client.calls == []


def test_source_scope_response_substitution_is_rejected_after_stage0_profile_check() -> None:
    client = _ReadOnlyClient(_page("Codex", source_scope="other-scope"))
    with pytest.raises(ValueError, match="pin"):
        CodexLiveSourceAdapter(api_client=client, credential_provider=_CredentialProvider(), security_authority=AUTHORITY).read_page(source_scope="scope-1", cursor=None, watermark=None, limit=1)
    assert len(client.calls) == 1


def test_infrastructure_does_not_implement_or_import_typed_adapters() -> None:
    root = Path(__file__).resolve().parents[2] / "src/wiki_spike/infrastructure"
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text())
        assert not any(
            (isinstance(node, ast.Import) and any(name.name.startswith("wiki_spike.connectors") for name in node.names))
            or (isinstance(node, ast.ImportFrom) and (node.module or "").startswith("wiki_spike.connectors"))
            or (isinstance(node, ast.ClassDef) and node.name.endswith("LiveSourceAdapter"))
            for node in ast.walk(tree)
        )
