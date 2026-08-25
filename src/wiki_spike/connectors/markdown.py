"""Markdown source-profile adapter and fixture-only capture connector."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Final, assert_never

import yaml

from . import FixtureConnectorReader

_FRONTMATTER_OPEN: Final = "---\n"
_HEADING: Final = re.compile(r"^(#{1,6})[ \t]+(.+?)\s*$")
_MD_LINK: Final = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_WIKI_LINK: Final = re.compile(r"\[\[([^\]|#]+)(?:[|#][^\]]*)?\]\]")


class MarkdownFixtureConnector(FixtureConnectorReader):
    source_profile = "Markdown"
    source_domain = "markdown"


class MarkdownVaultError(Exception):
    """A Markdown vault page or certified Markdown scope was refused."""


@dataclass(frozen=True, slots=True)
class MarkdownUnsafeLinkError(MarkdownVaultError):
    relative_path: str
    target: str

    def __str__(self) -> str:
        return f"unsafe markdown link in {self.relative_path}: {self.target}"


@dataclass(frozen=True, slots=True)
class MarkdownDuplicateIdentityError(MarkdownVaultError):
    native_id: str

    def __str__(self) -> str:
        return f"duplicate markdown native identity: {self.native_id}"


@dataclass(frozen=True, slots=True)
class MarkdownLocatorV1:
    section: str
    line: int


@dataclass(frozen=True, slots=True)
class MarkdownPageV1:
    native_id: str
    relative_path: str | None
    revision: str
    watermark: str
    frontmatter: tuple[tuple[str, str], ...]
    body: str
    locators: tuple[MarkdownLocatorV1, ...]
    content_digest: str
    keyed_dedupe_ref: str | None
    tombstone: bool


@dataclass(frozen=True, slots=True)
class MarkdownVaultSnapshotV1:
    source_profile: str
    complete: bool
    pages: tuple[MarkdownPageV1, ...]


class MarkdownVaultAdapter:
    """Typed Markdown vault reader with path/frontmatter identity and locators."""

    source_profile: Final = "Markdown"

    def authorize_certified_scope(self, outcome: str) -> None:
        if outcome != "GO":
            raise MarkdownVaultError("certified Markdown scope is disabled")

    def read_tree(
        self,
        root: Path,
        previous: tuple[tuple[str, str], ...] = (),
        complete: bool = True,
    ) -> MarkdownVaultSnapshotV1:
        pages = [_page_from_bytes(relative, raw) for relative, raw in _load_markdown_files(root)]
        seen: set[str] = set()
        for page in pages:
            if page.native_id in seen:
                raise MarkdownDuplicateIdentityError(page.native_id)
            seen.add(page.native_id)
        if complete:
            pages.extend(
                _tombstone(native_id, revision)
                for native_id, revision in previous
                if native_id not in seen
            )
        pages.sort(key=lambda page: page.native_id)
        return MarkdownVaultSnapshotV1(self.source_profile, complete, tuple(pages))


def _load_markdown_files(root: Path) -> tuple[tuple[str, bytes], ...]:
    if root.is_symlink() or not root.is_dir():
        raise MarkdownVaultError("vault root must be a real directory")
    found: list[tuple[str, bytes]] = []
    stack = [root]
    while stack:
        current = stack.pop()
        with os.scandir(current) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                relative = Path(entry.path).relative_to(root).as_posix()
                if entry.is_symlink():
                    raise MarkdownUnsafeLinkError(relative, "symlink")
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if entry.is_file(follow_symlinks=False) and Path(entry.name).suffix.casefold() == ".md":
                    found.append((relative, Path(entry.path).read_bytes()))
    return tuple(sorted(found, key=lambda item: item[0]))


def _page_from_bytes(relative_path: str, raw: bytes) -> MarkdownPageV1:
    frontmatter, body = _normalize(raw)
    _assert_safe_links(relative_path, body)
    native_id = _native_id(relative_path, frontmatter)
    digest = sha256(body.encode()).hexdigest()
    revision_body = {
        "body": body,
        "frontmatter": dict(frontmatter),
        "path": relative_path,
    }
    return MarkdownPageV1(
        native_id,
        relative_path,
        sha256(json.dumps(revision_body, separators=(",", ":"), sort_keys=True).encode()).hexdigest(),
        "1",
        frontmatter,
        body,
        _locators(body),
        digest,
        f"keyed-content:{digest}",
        False,
    )


def _tombstone(native_id: str, revision: str) -> MarkdownPageV1:
    return MarkdownPageV1(native_id, None, revision, "1", (), "", (), "", None, True)


def _normalize(raw: bytes) -> tuple[tuple[tuple[str, str], ...], str]:
    text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
    block, body = _split_frontmatter(text)
    body = "\n".join(line.rstrip() for line in body.split("\n")).rstrip()
    return _parse_frontmatter(block), "" if not body else f"{body}\n"


def _split_frontmatter(text: str) -> tuple[str, str]:
    if not text.startswith(_FRONTMATTER_OPEN):
        return "", text
    rest = text[len(_FRONTMATTER_OPEN) :]
    closer = rest.find("\n---\n")
    if closer >= 0:
        return rest[:closer], rest[closer + 5 :]
    if rest.endswith("\n---"):
        return rest[:-4], ""
    raise MarkdownVaultError("unterminated markdown frontmatter")


def _parse_frontmatter(block: str) -> tuple[tuple[str, str], ...]:
    if not block.strip():
        return ()
    loaded = yaml.safe_load(block)
    if not isinstance(loaded, dict):
        raise MarkdownVaultError("frontmatter must be a mapping")
    pairs: list[tuple[str, str]] = []
    for key, value in loaded.items():
        if not isinstance(key, str):
            raise MarkdownVaultError("frontmatter keys must be strings")
        if not isinstance(value, (str, int, float, bool)) and value is not None:
            raise MarkdownVaultError(f"frontmatter {key} must be a scalar")
        pairs.append((key, _frontmatter_value(value)))
    return tuple(sorted(pairs))


def _frontmatter_value(value: str | int | float | bool | None) -> str:
    match value:
        case None:
            return ""
        case bool():
            return "true" if value else "false"
        case int() | float():
            return str(value)
        case str():
            return value
        case unreachable:
            assert_never(unreachable)


def _native_id(relative_path: str, frontmatter: tuple[tuple[str, str], ...]) -> str:
    identity = dict(frontmatter).get("id")
    if identity:
        return identity
    return relative_path


def _locators(body: str) -> tuple[MarkdownLocatorV1, ...]:
    found: list[MarkdownLocatorV1] = []
    for index, line in enumerate(body.split("\n"), start=1):
        matched = _HEADING.fullmatch(line)
        if matched is not None:
            found.append(MarkdownLocatorV1(matched.group(2), index))
    return tuple(found)


def _assert_safe_links(relative_path: str, body: str) -> None:
    targets = [match.group(1) for match in _MD_LINK.finditer(body)]
    targets.extend(match.group(1) for match in _WIKI_LINK.finditer(body))
    for target in targets:
        if not _link_is_safe(target):
            raise MarkdownUnsafeLinkError(relative_path, target)


def _link_is_safe(target: str) -> bool:
    trimmed = target.strip()
    if not trimmed or trimmed.startswith("#"):
        return True
    lowered = trimmed.casefold()
    if "://" in trimmed:
        return lowered.startswith(("http://", "https://"))
    path = trimmed.split("#", 1)[0]
    parts = PurePosixPath(path).parts
    return bool(path) and not path.startswith(("/", "\\")) and ".." not in parts and not PurePosixPath(path).is_absolute()


__all__ = [
    "MarkdownDuplicateIdentityError",
    "MarkdownFixtureConnector",
    "MarkdownLocatorV1",
    "MarkdownPageV1",
    "MarkdownUnsafeLinkError",
    "MarkdownVaultAdapter",
    "MarkdownVaultError",
    "MarkdownVaultSnapshotV1",
]
