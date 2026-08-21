"""Production capture-authority verify uses the durable passwd-home nonce store."""
from __future__ import annotations

import multiprocessing
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.second_brain.export_authorization_nonce_store_support import (
    private_store_path,
)
from tests.second_brain.export_authorization_nonce_workers import (
    capture_commit_then_hard_exit,
)
from tests.second_brain.unified_db_postgres_capture_authorization_support import (
    NOW,
    authorization_body,
    expected_digests,
    sign_body,
    signed_request,
    trusted_pair,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_types import (
    MetadataCaptureVerifyRequestV1,
)
from wiki_spike.applications.unified_db_postgres_capture_authorization_verify import (
    VerifiedUnifiedDbMetadataCaptureAuthorityV1,
)
from wiki_spike.composition.unified_db_postgres_capture import (
    verify_production_metadata_capture_authorization,
)
from wiki_spike.infrastructure.export_authorization_nonce_capture import (
    SqliteMetadataCaptureNonceStore,
)
from wiki_spike.infrastructure.export_authorization_nonce_store import (
    SqliteExportAuthorizationNonceStore,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_export_authorization_nonce import (
    export_authorization_nonce_digest,
)
from wiki_spike.memory_core.unified_db_postgres_capture_authorization_nonce import (
    metadata_capture_nonce_digest,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError

_WAIT = 10
_DSN = b"postgresql://localhost:5433/unified"


@dataclass(frozen=True, slots=True)
class _PasswdRecord:
    pw_dir: str


def _initialized_store(directory: Path) -> Path:
    path = private_store_path(directory)
    store = SqliteExportAuthorizationNonceStore(path)
    store.close()
    return path


def _production_store(home: Path) -> Path:
    support = home / "Library" / "Application Support"
    support.mkdir(parents=True)
    wiki = support / "wiki-spike"
    os.mkdir(wiki, 0o700)
    os.chmod(wiki, 0o700)
    return _initialized_store(wiki)


def _passwd_lookup(home: Path) -> Callable[[int], _PasswdRecord]:
    def lookup(uid: int) -> _PasswdRecord:
        _ = uid
        return _PasswdRecord(pw_dir=str(home))

    return lookup


def _body_attempt() -> dict[str, str]:
    body = authorization_body()
    return {
        "authorization_id": str(body["authorization_id"]),
        "nonce": str(body["nonce"]),
        "authorization_digest": str(body["authorization_digest"]),
        "authorization_issued_at": str(body["issued_at"]),
    }


def _pipe_dsn() -> tuple[int, bytes]:
    read_fd, write_fd = os.pipe()
    _ = os.write(write_fd, _DSN)
    os.close(write_fd)
    return read_fd, _DSN


def test_production_verify_ignores_home_env_and_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    env_home = tmp_path / "env-home"
    cwd = tmp_path / "cwd"
    passwd_home.mkdir()
    env_home.mkdir()
    cwd.mkdir()
    passwd_path = _production_store(passwd_home)
    env_path = _production_store(env_home)
    monkeypatch.setenv("HOME", str(env_home))
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    request, _ignored = signed_request()
    token = verify_production_metadata_capture_authorization(request)
    assert isinstance(token, VerifiedUnifiedDbMetadataCaptureAuthorityV1)
    assert token.claim().authorization_id == "capture-auth-001"
    replay, _ignored_replay = signed_request()
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_production_metadata_capture_authorization(replay)
    replay_store = SqliteMetadataCaptureNonceStore(passwd_path)
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        replay_store.reserve_and_consume(**_body_attempt())
    replay_store.close()
    env_store = SqliteMetadataCaptureNonceStore(env_path)
    env_store.reserve_and_consume(**_body_attempt())
    env_store.close()
    assert not (cwd / "Library").exists()


def test_production_verify_missing_store_is_refused_and_not_created(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    env_home = tmp_path / "env-home"
    passwd_home.mkdir()
    monkeypatch.setenv("HOME", str(env_home))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    request, _ignored = signed_request()
    with pytest.raises(UnifiedDbExportError):
        _ = verify_production_metadata_capture_authorization(request)
    assert not (passwd_home / "Library").exists()
    assert not env_home.exists()


def test_production_verify_burns_junk_envelopes_and_leaves_dsn_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    passwd_home.mkdir()
    _ = _production_store(passwd_home)
    monkeypatch.setenv("HOME", str(tmp_path / "env-home"))
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    owner = Ed25519PrivateKey.generate()
    approver = Ed25519PrivateKey.generate()
    body = authorization_body()
    envelopes = sign_body(authorization_body(authorization_id="capture-auth-002"), owner, approver)
    junk = MetadataCaptureVerifyRequestV1(
        canonical_bytes(body),
        envelopes,
        trusted_pair(owner, approver),
        expected_digests(),
        NOW,
    )
    read_fd, payload = _pipe_dsn()
    with pytest.raises((InvalidContractValue, UnifiedDbExportError)):
        _ = verify_production_metadata_capture_authorization(junk, dsn_fd=read_fd)
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert leftover == payload
    replay, _ignored = signed_request()
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_production_metadata_capture_authorization(replay)


def test_production_verify_replay_after_close_reopen_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    passwd_home.mkdir()
    _ = _production_store(passwd_home)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    request, _ignored = signed_request()
    first = verify_production_metadata_capture_authorization(request)
    assert first.claim().nonce == str(authorization_body()["nonce"])
    replay, _ignored_replay = signed_request()
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_production_metadata_capture_authorization(replay)


def test_production_verify_replay_after_hard_exit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    passwd_home.mkdir()
    path = _production_store(passwd_home)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    body = authorization_body()
    ctx = multiprocessing.get_context("spawn")
    ready: multiprocessing.Queue[str] = ctx.Queue(1)
    go: multiprocessing.Queue[str] = ctx.Queue(1)
    recv, send = ctx.Pipe(duplex=False)
    worker = ctx.Process(
        target=capture_commit_then_hard_exit,
        args=(
            str(path),
            str(body["authorization_id"]),
            str(body["nonce"]),
            str(body["authorization_digest"]),
            str(body["issued_at"]),
            ready,
            go,
            send,
        ),
    )
    worker.start()
    send.close()
    assert ready.get(timeout=_WAIT) == "READY"
    go.put("GO")
    assert recv.poll(timeout=_WAIT)
    assert recv.recv() == "COMMITTED"
    worker.join(timeout=_WAIT)
    assert not worker.is_alive()
    request, _ignored = signed_request()
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_production_metadata_capture_authorization(request)


def test_production_verify_nonce_is_isolated_from_export_domain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    passwd_home = tmp_path / "passwd"
    passwd_home.mkdir()
    path = _production_store(passwd_home)
    monkeypatch.setattr(
        "wiki_spike.composition.unified_db_postgres_capture.pwd.getpwuid",
        _passwd_lookup(passwd_home),
    )
    request, _ignored = signed_request()
    _ = verify_production_metadata_capture_authorization(request)
    exported = SqliteExportAuthorizationNonceStore(path, allow_create=False)
    exported.reserve_and_consume(**_body_attempt())
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        exported.reserve_and_consume(**_body_attempt())
    exported.close()
    replay, _ignored_replay = signed_request()
    with pytest.raises(UnifiedDbExportError, match="nonce"):
        _ = verify_production_metadata_capture_authorization(replay)
    payload = path.read_bytes()
    nonce = str(authorization_body()["nonce"])
    assert nonce.encode("ascii") not in payload
    capture_digest = metadata_capture_nonce_digest(nonce).encode("ascii")
    export_digest = export_authorization_nonce_digest(nonce).encode("ascii")
    assert capture_digest != export_digest
    assert capture_digest in payload
    assert export_digest in payload
