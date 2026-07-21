"""Minimal Git plumbing wrapper (v3.3 §5-1, §4-7).

Uses `commit-tree` + a throwaway index so we never need a work tree (enables the
concurrency model) and so commit OIDs are reproducible given the same tree/parent/
message (fixed author/committer identity + dates).

Key operations for Phase 1b:
- write_tree_from_files: build a tree (incl. nested paths) from an in-memory dict.
- commit_tree: create a commit object (no ref yet -> unreachable until anchored).
- set_retention_anchor: refs/wiki/generations/<gen> -> commit (N3: survives git gc).
- cas_update_ref: compare-and-swap ref update (git's 3-arg update-ref).
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path


class GitError(RuntimeError):
    pass


class GitRepo:
    def __init__(self, gitdir: Path) -> None:
        self.gitdir = Path(gitdir)

    @classmethod
    def init_bare(cls, gitdir: Path, object_format: str = "sha1") -> "GitRepo":
        gitdir = Path(gitdir)
        subprocess.run(
            ["git", "init", "--bare", f"--object-format={object_format}", str(gitdir)],
            check=True,
            capture_output=True,
        )
        return cls(gitdir)

    def _git(self, *args: str, input: bytes | None = None, env: dict | None = None) -> bytes:
        e = dict(os.environ)
        e["GIT_DIR"] = str(self.gitdir)
        e.setdefault("GIT_AUTHOR_NAME", "wiki")
        e.setdefault("GIT_AUTHOR_EMAIL", "wiki@local")
        e.setdefault("GIT_COMMITTER_NAME", "wiki")
        e.setdefault("GIT_COMMITTER_EMAIL", "wiki@local")
        e.setdefault("GIT_AUTHOR_DATE", "2026-07-19T00:00:00 +0000")
        e.setdefault("GIT_COMMITTER_DATE", "2026-07-19T00:00:00 +0000")
        if env:
            e.update(env)
        r = subprocess.run(["git", *args], input=input, capture_output=True, env=e)
        if r.returncode != 0:
            raise GitError(f"git {' '.join(args)}: {r.stderr.decode().strip()}")
        return r.stdout

    def object_format(self) -> str:
        return self._git("rev-parse", "--show-object-format").decode().strip()

    def hash_object(self, data: bytes) -> str:
        return self._git("hash-object", "-w", "--stdin", input=data).decode().strip()

    def write_tree_from_files(self, files: dict[str, bytes]) -> str:
        idx = self.gitdir / ("index.tmp." + os.urandom(6).hex())
        env = {"GIT_INDEX_FILE": str(idx)}
        try:
            for path, data in sorted(files.items()):
                oid = self.hash_object(data)
                self._git("update-index", "--add", "--cacheinfo", f"100644,{oid},{path}", env=env)
            return self._git("write-tree", env=env).decode().strip()
        finally:
            if idx.exists():
                idx.unlink()

    def commit_tree(self, tree: str, message: str, parent: str | None = None) -> str:
        args = ["commit-tree", tree, "-m", message]
        if parent:
            args += ["-p", parent]
        return self._git(*args).decode().strip()

    def set_retention_anchor(self, ref: str, commit_oid: str) -> None:
        self._git("update-ref", ref, commit_oid)

    def cas_update_ref(self, ref: str, new_oid: str, expected_old_oid: str | None) -> None:
        if expected_old_oid is None:
            # create-only: fails if ref already exists
            self._git("update-ref", ref, new_oid, "0" * 40 if self.object_format() == "sha1" else "0" * 64)
        else:
            self._git("update-ref", ref, new_oid, expected_old_oid)

    def read_ref(self, ref: str) -> str | None:
        r = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", ref],
            capture_output=True,
            env={**os.environ, "GIT_DIR": str(self.gitdir)},
        )
        out = r.stdout.decode().strip()
        return out or None

    def cat_file(self, spec: str) -> bytes:
        return self._git("cat-file", "-p", spec)

    def ls_tree(self, commit_oid: str, prefix: str = "") -> list[str]:
        out = self._git("ls-tree", "-r", "--name-only", commit_oid).decode()
        paths = [p for p in out.splitlines() if p]
        return [p for p in paths if p.startswith(prefix)] if prefix else paths

    def create_ref_only(self, ref: str, new_oid: str) -> None:
        """Create-only ref update: fails if the ref already exists (immutable anchor)."""
        zero = "0" * (64 if self.object_format() == "sha256" else 40)
        self._git("update-ref", ref, new_oid, zero)

    def object_exists(self, oid: str) -> bool:
        r = subprocess.run(
            ["git", "cat-file", "-e", oid],
            capture_output=True,
            env={**os.environ, "GIT_DIR": str(self.gitdir)},
        )
        return r.returncode == 0

    def gc_prune_now(self) -> None:
        self._git("gc", "--prune=now", "--quiet")
