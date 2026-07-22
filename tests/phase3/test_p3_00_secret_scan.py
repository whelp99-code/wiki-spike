from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts.scan_secrets import scan_repository


def root() -> Path:
    return Path(__file__).resolve().parents[2]


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    return repo


def add(repo: Path, name: str, content: bytes | str) -> Path:
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")
    subprocess.run(["git", "add", name], cwd=repo, check=True)
    return path


def rules(repo: Path) -> set[str]:
    return {finding.rule for finding in scan_repository(repo)}


def test_repository_secret_scan_passes():
    assert scan_repository(root()) == []


def test_private_key_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "secret.pem", "-----BEGIN " + "PRIVATE KEY-----\nAAAA\n")
    assert "private-key-pem" in rules(repo)


def test_github_token_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "ghp_" + "abcdefghijklmnopqrstuvwxyz123456")
    assert "github-token" in rules(repo)


def test_anthropic_key_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "sk-ant-" + "abcdefghijklmnopqrstuvwxyz123456")
    assert "anthropic-key" in rules(repo)


def test_openai_key_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "sk-proj-" + "abcdefghijklmnopqrstuvwxyz123456")
    assert "openai-key" in rules(repo)


def test_aws_key_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "AKIA" + "ABCDEFGHIJKLMNOP")
    assert "aws-access-key" in rules(repo)


def test_slack_token_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "xoxb-" + "123456789012-abcdefghijklmnopqrstuvwxyz")
    assert "slack-token" in rules(repo)


def test_google_key_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "x.txt", "AI" + "za" + "A" * 35)
    assert "google-api-key" in rules(repo)


def test_nonempty_env_assignment_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, ".env", "API_" + "KEY=" + "not-a-placeholder-value\n")
    assert "non-empty-secret-assignment" in rules(repo)


def test_empty_env_assignment_allowed(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, ".env.example", "API_" + "KEY=\n")
    assert scan_repository(repo) == []


def test_placeholder_assignment_allowed(tmp_path):
    repo = make_repo(tmp_path)
    key_name = "client_" + "secret"
    add(repo, "config.yaml", f"{key_name}: <pending>\n")
    assert scan_repository(repo) == []


def test_fake_test_key_allowed(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "test_client.py", 'client = Client(api_key="fake-key")\n')
    assert scan_repository(repo) == []


def test_unsafe_symlink_detected(tmp_path):
    repo = make_repo(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    link = repo / "escape.txt"
    try:
        link.symlink_to("../outside.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    subprocess.run(["git", "add", "escape.txt"], cwd=repo, check=True)
    assert "unsafe-symlink" in rules(repo)


def test_safe_relative_symlink_allowed(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "inside.txt", "safe")
    link = repo / "alias.txt"
    try:
        link.symlink_to("inside.txt")
    except OSError:
        pytest.skip("symlinks unavailable")
    subprocess.run(["git", "add", "alias.txt"], cwd=repo, check=True)
    assert scan_repository(repo) == []


def test_binary_secret_signature_is_detected(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "image.bin", b"\x00" + b"sk-ant-" + b"abcdefghijklmnopqrstuvwxyz123456")
    assert "anthropic-key" in rules(repo)


def test_safe_binary_file_is_allowed(tmp_path):
    repo = make_repo(tmp_path)
    add(repo, "image.bin", b"\x00\x01\x02safe-binary")
    assert scan_repository(repo) == []


def test_missing_tracked_file_detected(tmp_path):
    repo = make_repo(tmp_path)
    path = add(repo, "gone.txt", "safe")
    path.unlink()
    assert "tracked-file-missing" in rules(repo)
