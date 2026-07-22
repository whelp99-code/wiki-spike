#!/usr/bin/env python3
"""Conservative secret scanner for tracked repository content.

The scanner is intentionally deterministic and offline.  It catches common
credential formats, private-key material, non-empty credential assignments,
and unsafe tracked symlinks.  It does not claim to replace provider-side secret
scanning; it is the fail-closed local/CI gate for P3-00.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

try:
    from .preflight_common import PreflightError, find_repo_root
except ImportError:  # direct script execution
    from preflight_common import PreflightError, find_repo_root


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    excerpt: str


TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key-pem", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
)


BINARY_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("private-key-pem", re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("github-token", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})")),
    ("anthropic-key", re.compile(rb"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(rb"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("aws-access-key", re.compile(rb"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("slack-token", re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}")),
    ("google-api-key", re.compile(rb"AIza[0-9A-Za-z_-]{35}")),
)
MAX_SCAN_BYTES = 16 * 1024 * 1024


def _scan_binary(relative: str, data: bytes) -> list[Finding]:
    findings: list[Finding] = []
    for rule, pattern in BINARY_TOKEN_PATTERNS:
        match = pattern.search(data)
        if match:
            findings.append(Finding(relative, 0, rule, match.group(0)[:12].decode("latin-1") + "…"))
    return findings

ASSIGNMENT_PATTERN = re.compile(
    r"(?ix)"
    r"\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|private[_-]?key|secret)\b"
    r"\s*(?::|=)\s*"
    r"(?P<quote>['\"]?)(?P<value>[^'\"\s#,;]+)(?P=quote)"
)

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".example",
    ".ini",
    ".json",
    ".md",
    ".pem",
    ".properties",
    ".py",
    ".rst",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

SAFE_ASSIGNMENT_VALUES = {
    "",
    "<pending>",
    "<redacted>",
    "changeme",
    "dummy",
    "example",
    "fake",
    "fake-key",
    "k",
    "none",
    "null",
    "pending",
    "redacted",
    "replace-me",
    "test",
    "token",
    "todo",
}


def _is_safe_assignment(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered in SAFE_ASSIGNMENT_VALUES:
        return True
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.()]*", value):
        return True
    if value.startswith("${") and value.endswith("}"):
        return True
    if value.startswith("os.environ") or value.startswith("env("):
        return True
    if set(value) <= {"*", "x", "X", "-", "_"}:
        return True
    return False


def _scan_text(path: Path, relative: str, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        for rule, pattern in TOKEN_PATTERNS:
            match = pattern.search(line)
            if match:
                findings.append(
                    Finding(relative, line_number, rule, match.group(0)[:12] + "…")
                )
        # Generic assignments in Markdown are often documentation examples.  Strong
        # token formats and private keys are still scanned there; generic assignment
        # checks are limited to configuration/source formats.
        if path.suffix.lower() not in {".md", ".rst", ".txt"}:
            for match in ASSIGNMENT_PATTERN.finditer(line):
                value = match.group("value")
                if not _is_safe_assignment(value):
                    findings.append(
                        Finding(relative, line_number, "non-empty-secret-assignment", "<redacted>")
                    )
    return findings


def _candidate_paths(repo: Path) -> list[Path]:
    import subprocess

    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=str(repo), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode != 0:
        raise PreflightError(result.stderr.decode("utf-8", errors="replace"))
    return [Path(os.fsdecode(item)) for item in result.stdout.split(b"\x00") if item]


def scan_repository(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    for relative_path in _candidate_paths(repo):
        full_path = repo / relative_path
        relative = relative_path.as_posix()
        try:
            stat_result = full_path.lstat()
        except FileNotFoundError:
            findings.append(Finding(relative, 0, "tracked-file-missing", "<missing>"))
            continue
        if full_path.is_symlink():
            target = os.readlink(full_path)
            if os.path.isabs(target) or ".." in Path(target).parts:
                findings.append(Finding(relative, 0, "unsafe-symlink", target))
            continue
        if not full_path.is_file():
            continue
        # Public verification keys are expected; private-key headers are not.
        if relative == "artifacts/checkpoints/g2/phase2-storage-public-key.pem":
            data = full_path.read_bytes()
            if b"PRIVATE KEY" in data:
                findings.append(Finding(relative, 1, "private-key-pem", "<redacted>"))
            continue
        data = full_path.read_bytes()
        if len(data) > MAX_SCAN_BYTES:
            findings.append(Finding(relative, 0, "oversized-unscanned-file", str(len(data))))
            continue
        suffix = full_path.suffix.lower()
        is_text_candidate = suffix in TEXT_EXTENSIONS or full_path.name in {
            ".env", ".env.example", ".gitignore", "Dockerfile", "Makefile",
        }
        if not is_text_candidate or b"\x00" in data:
            findings.extend(_scan_binary(relative, data))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            binary_findings = _scan_binary(relative, data)
            findings.extend(binary_findings)
            if not binary_findings:
                findings.append(Finding(relative, 0, "non-utf8-tracked-text", "<binary>"))
            continue
        findings.extend(_scan_text(full_path, relative, text))
    return sorted(findings, key=lambda f: (f.path, f.line, f.rule))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        repo = find_repo_root(args.repo_root)
        findings = scan_repository(repo)
    except PreflightError as exc:
        print(json.dumps({"status": "fail", "error": str(exc)}) if args.json else f"FAIL: {exc}")
        return 2
    if findings:
        if args.json:
            print(json.dumps({"status": "fail", "findings": [f.__dict__ for f in findings]}, ensure_ascii=False, sort_keys=True))
        else:
            print("Potential secrets detected:")
            for finding in findings:
                print(f"- {finding.path}:{finding.line}: {finding.rule}: {finding.excerpt}")
        return 1
    print(json.dumps({"status": "pass", "findings": []}) if args.json else "PASS: no tracked secrets detected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
