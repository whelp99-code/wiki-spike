"""Public-only create-only Mac Keychain fingerprint receipt CLI."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tests.second_brain.mac_production_status_compose_support import (
    keychain_directory,
    keychain_index,
    v1_dir,
    write_keychain_layout,
)
from tests.second_brain.mac_production_status_serving_support import PINNED_WORKSPACE
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_ledger_contracts import (
    canonical_ledger_digest,
)

_CLI = Path("scripts/second_brain_mac_keychain_fingerprint.py")
_RELEASE = Path("artifacts/product-release/second-brain-v1/persistence-receipt.json")
_SERVICE = "wiki-spike.second-brain-v1"
_ARK = "serving-ark-v1"
_KIND = "mac-keychain-fingerprint-v1"
_METADATA = "cd" * 32


class _RefuseBackend:
    def add(self, *, service: str, account: str, secret: str) -> bool:
        raise AssertionError("fingerprint CLI must not add Keychain items")

    def read(self, *, service: str, account: str) -> str | None:
        raise AssertionError("fingerprint CLI must not read Keychain secrets")

    def delete(self, *, service: str, account: str) -> bool:
        raise AssertionError("fingerprint CLI must not delete Keychain items")


@pytest.fixture(autouse=True)
def _no_security_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*_a: object, **_k: object) -> None:
        raise AssertionError("SecurityCliKeychainBackend must not be constructed")

    monkeypatch.setattr(
        "wiki_spike.infrastructure.macos_keychain_existing.SecurityCliKeychainBackend",
        _boom,
    )


def _home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    v1_dir(home).mkdir(parents=True)
    return home


def _args(home: Path, dest: Path, extra: list[str] | None = None) -> list[str]:
    return [
        "--index-dir",
        str(keychain_index(home)),
        "--keychain-directory",
        str(keychain_directory(home)),
        "--workspace-ref",
        PINNED_WORKSPACE,
        "--out",
        str(dest),
        *(extra or []),
    ]


def _main(args: list[str]) -> int:
    from scripts.second_brain_mac_keychain_fingerprint import main

    return main(args, backend=_RefuseBackend())


def _public(out: str, err: str, dest: Path | None = None) -> None:
    blob = f"{out}{err}"
    if dest is not None and dest.is_file():
        blob += dest.read_text(encoding="utf-8")
    lowered = blob.casefold()
    assert "begin" not in lowered
    assert "private key" not in lowered
    assert "password data" not in lowered
    assert "/usr/bin/security" not in blob
    assert "add-generic-password" not in blob


def _expected(index_dir: Path) -> dict[str, str]:
    account = hashlib.sha256(f"{PINNED_WORKSPACE}\0{_ARK}".encode()).hexdigest()
    raw = (index_dir / f"{account}.json").read_bytes()
    index_sha256 = hashlib.sha256(raw).hexdigest()
    fingerprint = hashlib.sha256(
        f"{index_sha256}\0{_METADATA}".encode("ascii")
    ).hexdigest()
    body = {
        "ark_handle": _ARK,
        "fingerprint": fingerprint,
        "index_sha256": index_sha256,
        "metadata_digest": _METADATA,
        "namespace": PINNED_WORKSPACE,
        "receipt_kind": _KIND,
        "service": _SERVICE,
    }
    return body | {"receipt_digest": canonical_ledger_digest(_KIND, body)}


def test_missing_index_refuses_without_creating_dest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    dest = tmp_path / "receipt.json"
    keychain_directory(home).mkdir(parents=True)
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc != 0
    assert not dest.exists()
    assert not _RELEASE.exists()
    _public(captured.out, captured.err, dest)


def test_existing_dest_refuses_without_overwrite(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    write_keychain_layout(home)
    dest = tmp_path / "receipt.json"
    _ = dest.write_text("keep-me", encoding="utf-8")
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc != 0
    assert dest.read_text(encoding="utf-8") == "keep-me"
    _public(captured.out, captured.err)


def test_symlink_dest_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    write_keychain_layout(home)
    victim = tmp_path / "victim.json"
    _ = victim.write_text("keep-me", encoding="utf-8")
    dest = tmp_path / "receipt.json"
    dest.symlink_to(victim)
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc != 0
    assert dest.is_symlink()
    assert victim.read_text(encoding="utf-8") == "keep-me"
    _public(captured.out, captured.err)


def test_symlink_dest_ancestor_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    write_keychain_layout(home)
    real = tmp_path / "real-out"
    real.mkdir()
    linked = tmp_path / "link-out"
    linked.symlink_to(real, target_is_directory=True)
    dest = linked / "receipt.json"
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc != 0
    assert not dest.exists()
    assert list(real.iterdir()) == []
    _public(captured.out, captured.err)


def test_destroyed_index_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    index_dir = write_keychain_layout(home)
    account = hashlib.sha256(f"{PINNED_WORKSPACE}\0{_ARK}".encode()).hexdigest()
    record = index_dir / f"{account}.json"
    _ = record.write_bytes(
        canonical_bytes(
            {
                "ark_handle": _ARK,
                "destroyed": True,
                "destroyed_at": "2026-01-01T00:00:00Z",
                "metadata_digest": _METADATA,
                "namespace": PINNED_WORKSPACE,
                "receipt_digest": "ab" * 32,
            }
        )
    )
    record.chmod(0o600)
    dest = tmp_path / "receipt.json"
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc != 0
    assert not dest.exists()
    _public(captured.out, captured.err, dest)


@pytest.mark.parametrize(
    "extra",
    (["--service", "wiki-spike.other"], ["--ark-handle", "other-ark"]),
)
def test_wrong_service_or_handle_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], extra: list[str]
) -> None:
    home = _home(tmp_path)
    write_keychain_layout(home)
    dest = tmp_path / "receipt.json"
    rc = _main(_args(home, dest, extra))
    captured = capsys.readouterr()
    assert rc != 0
    assert not dest.exists()
    _public(captured.out, captured.err, dest)


def test_happy_path_create_only_and_second_write_refuses(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    home = _home(tmp_path)
    index_dir = write_keychain_layout(home)
    dest = tmp_path / "receipt.json"
    rc = _main(_args(home, dest))
    captured = capsys.readouterr()
    assert rc == 0, captured.err
    assert dest.is_file() and not dest.is_symlink()
    expected = _expected(index_dir)
    body = json.loads(dest.read_text(encoding="utf-8"))
    assert body == expected
    assert dest.read_bytes() == canonical_bytes(expected) + b"\n"
    unsigned = {key: value for key, value in body.items() if key != "receipt_digest"}
    assert body["receipt_digest"] == canonical_ledger_digest(_KIND, unsigned)
    _public(captured.out, captured.err, dest)
    assert not _RELEASE.exists()
    source = _CLI.read_text(encoding="utf-8")
    assert "artifacts/product-release" not in source
    assert "add-generic-password" not in source
    assert "find-generic-password" not in source
    assert "delete-generic-password" not in source
    assert "--private-key" not in source
    first = dest.read_bytes()
    second = _main(_args(home, dest))
    captured_second = capsys.readouterr()
    assert second != 0
    assert dest.read_bytes() == first
    _public(captured_second.out, captured_second.err, dest)
