"""Application service for the supported desktop experience.

This module deliberately contains no GUI toolkit code so the complete user flow can
be tested without opening a window. It is local-only and delegates all durable work
to :class:`LocalMemoryStore`.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .store import LocalMemoryError, LocalMemoryStore, MemoryHit

APP_NAME = "Wiki Memory"
DEFAULT_SUPPORT_ROOT = Path.home() / "Library" / "Application Support" / APP_NAME
DEFAULT_DATA_ROOT = DEFAULT_SUPPORT_ROOT / "data"
DEFAULT_BACKUP_ROOT = Path.home() / "Documents" / "Wiki Memory Backups"


@dataclass(frozen=True, slots=True)
class DesktopOpenResult:
    service: "DesktopMemoryService"
    first_run: bool


class DesktopMemoryService:
    """Small, user-facing façade over the encrypted local memory store."""

    def __init__(self, root: str | Path = DEFAULT_DATA_ROOT) -> None:
        self.root = Path(root).expanduser()
        self.store = LocalMemoryStore(self.root)

    @classmethod
    def open_or_initialize(
        cls,
        root: str | Path = DEFAULT_DATA_ROOT,
    ) -> DesktopOpenResult:
        target = Path(root).expanduser().resolve()
        first_run = not LocalMemoryStore.is_initialized(target)
        if first_run:
            LocalMemoryStore.initialize(target)
        return DesktopOpenResult(service=cls(target), first_run=first_run)

    def browse(self, query: str = "", *, limit: int = 100) -> tuple[MemoryHit, ...]:
        cleaned = query.strip()
        return (
            self.store.recall(cleaned, limit=min(limit, 50))
            if cleaned
            else self.store.recent(limit=limit)
        )

    def get(self, memory_id: str) -> MemoryHit:
        return self.store.get(memory_id)

    def citation(self, memory_id: str) -> dict[str, str]:
        return self.store.citation(memory_id)

    def save(
        self,
        *,
        memory_id: str | None,
        title: str,
        body: str,
    ) -> dict[str, str]:
        title = self.suggest_title(title, body)
        if memory_id is None:
            return self.store.remember_text(body, title=title)
        return self.store.correct_text(memory_id, body, title=title)

    @staticmethod
    def suggest_title(title: str, body: str) -> str:
        """Return a usable title without making a first-time user learn fields.

        An explicitly entered title always wins. Otherwise the first non-empty
        body line becomes the title, capped to the store's 255-character limit.
        This keeps the desktop editor usable as a single blank page: typing only
        the note body is enough for autosave.
        """
        cleaned = title.strip() if isinstance(title, str) else ""
        if cleaned:
            return cleaned[:255]
        if isinstance(body, str):
            for line in body.splitlines():
                candidate = " ".join(line.strip().split())
                if candidate:
                    return candidate[:80]
        return "새 메모"

    def import_file(self, path: str | Path) -> dict[str, str]:
        source = Path(path).expanduser()
        title = source.stem.strip() or source.name
        return self.store.remember(source, label=title)

    def delete(self, memory_id: str) -> dict[str, str]:
        return self.store.forget(memory_id)

    def status(self) -> dict[str, Any]:
        return self.store.status()

    def events(self, *, limit: int = 20) -> tuple[dict[str, str], ...]:
        return self.store.events(limit=limit)

    def backup(
        self,
        destination: str | Path,
        *,
        passphrase: str,
        overwrite: bool = False,
    ) -> dict[str, str]:
        return self.store.backup(
            destination,
            passphrase=passphrase,
            overwrite=overwrite,
        )

    def restore(
        self,
        backup: str | Path,
        *,
        passphrase: str,
        replace: bool = True,
    ) -> dict[str, str]:
        self.store.close()
        result = LocalMemoryStore.restore(
            backup,
            self.root,
            passphrase=passphrase,
            replace=replace,
        )
        self.store = LocalMemoryStore(self.root)
        return result

    def repair_permissions(self) -> dict[str, Any]:
        """Repair only the three permissions the store itself requires."""
        status = self.repair_workspace_permissions(self.root)
        self.store = LocalMemoryStore(self.root)
        return status

    @classmethod
    def repair_workspace_permissions(cls, root: str | Path) -> dict[str, Any]:
        """Repair a known workspace even when strict opening was initially refused."""
        target = Path(root).expanduser().resolve()
        if not target.exists():
            raise LocalMemoryError("memory workspace does not exist")
        target.chmod(0o700)
        for directory in (
            target / "cas",
            target / "cas/objects",
            target / "cas/tombstones",
            target / "keys",
            target / "keys/platform",
            target / "keys/recovery",
        ):
            if directory.exists() and not directory.is_symlink():
                directory.chmod(0o700)
        for name in (
            "lifecycle.sqlite3",
            "lifecycle.sqlite3-wal",
            "lifecycle.sqlite3-shm",
            ".lock",
            "keys/identity.key",
            "keys/fallback-dek.key",
            "keys/signing.key",
        ):
            path = target / name
            if path.exists() and not path.is_symlink():
                path.chmod(0o600)
        for custody in (target / "keys/platform", target / "keys/recovery"):
            if custody.exists():
                for path in custody.glob("*.json"):
                    if not path.is_symlink():
                        path.chmod(0o600)
        objects = target / "cas/objects"
        if objects.exists():
            for path in objects.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o444)
        tombstones = target / "cas/tombstones"
        if tombstones.exists():
            for path in tombstones.iterdir():
                if path.is_file() and not path.is_symlink():
                    path.chmod(0o600)
        return cls(target).status()
