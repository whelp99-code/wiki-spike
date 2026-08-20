"""Read-only validation for an existing encrypted CAS layout."""
from __future__ import annotations

import os
import stat
from pathlib import Path


class ExistingCASLayoutError(ValueError):
    """The requested existing CAS layout is absent or unsafe."""


def _require_private_directory(path: Path) -> None:
    try:
        metadata = os.lstat(path)
    except OSError as exc:
        raise ExistingCASLayoutError(f"existing CAS directory is missing: {path}") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ExistingCASLayoutError(f"existing CAS path is not a directory: {path}")
    if metadata.st_uid != os.getuid():
        raise ExistingCASLayoutError(f"existing CAS owner is invalid: {path}")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ExistingCASLayoutError(f"existing CAS mode must be 0700: {path}")


def validate_existing_cas_layout(root: Path) -> tuple[Path, Path, Path]:
    """Return fixed existing paths after rejecting symlinks and unsafe modes."""
    root_path = Path(root)
    absolute = Path(os.path.abspath(root_path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            metadata = os.lstat(current)
        except OSError as exc:
            raise ExistingCASLayoutError(
                f"existing CAS directory is missing: {current}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise ExistingCASLayoutError(
                f"existing CAS path would follow a symlink: {current}"
            )
    objects = root_path / "objects"
    tombstones = root_path / "tombstones"
    for path in (root_path, objects, tombstones):
        _require_private_directory(path)
    return root_path, objects, tombstones
