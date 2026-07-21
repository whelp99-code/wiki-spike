"""Remote mirror (SUB-07, v3.3 §5-3 remote_publish).

The control-plane DB is authoritative; the Git remote is a derived mirror. The
outbox drives idempotent pushes: if a push fails the event stays unprocessed and is
retried; re-pushing already-present objects is a no-op ("Everything up-to-date").
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .controlplane import ControlPlane
from .gitrepo import GitRepo


class MirrorError(RuntimeError):
    pass


class RemoteMirror:
    def __init__(self, repo: GitRepo, remote_gitdir: Path) -> None:
        self.repo = repo
        self.remote_gitdir = Path(remote_gitdir)

    def ensure_remote(self, object_format: str = "sha1") -> None:
        if not (self.remote_gitdir / "HEAD").exists():
            subprocess.run(
                ["git", "init", "--bare", f"--object-format={object_format}", str(self.remote_gitdir)],
                check=True,
                capture_output=True,
            )

    def _push(self, refspec: str) -> None:
        env = {**os.environ, "GIT_DIR": str(self.repo.gitdir)}
        r = subprocess.run(
            ["git", "push", str(self.remote_gitdir), refspec], capture_output=True, env=env
        )
        if r.returncode != 0:
            raise MirrorError(f"push {refspec}: {r.stderr.decode().strip()}")

    def push_generation(self, generation_id: str) -> None:
        # generations/<gen> is immutable -> never conflicts.
        self._push(f"refs/wiki/generations/{generation_id}:refs/wiki/generations/{generation_id}")

    def sync_release_ref(self, cp: ControlPlane) -> None:
        # The release pointer is authoritative in SQLite; the git ref is a derived
        # mirror. Materialize it locally from the DB, then force-push (it is a mutable
        # pointer whose history need not be fast-forward).
        rel_oid = cp.current_release_oid()
        if rel_oid:
            self.repo.set_retention_anchor("refs/wiki/releases/current", rel_oid)
            self._push("+refs/wiki/releases/current:refs/wiki/releases/current")

    def process_outbox(self, cp: ControlPlane) -> int:
        """Relay pending mirror events. An event is marked processed ONLY after the
        full mirror (generation ref + release pointer) succeeds, so a release-push
        failure leaves the event pending for retry. Reconciles even with no events.
        """
        self.ensure_remote(self.repo.object_format())
        pending = cp.pending_outbox()
        processed = 0
        for event_id, event_type, generation_id in pending:
            if event_type == "release_mirror_requested":
                self.push_generation(generation_id)
                self.sync_release_ref(cp)  # must succeed BEFORE marking processed
            cp.mark_outbox_processed(event_id)
            processed += 1
        if not pending:
            # Reconcile the remote release pointer with the authoritative DB pointer.
            self.sync_release_ref(cp)
        return processed

    def remote_has(self, oid: str) -> bool:
        r = subprocess.run(
            ["git", "cat-file", "-e", oid],
            capture_output=True,
            env={**os.environ, "GIT_DIR": str(self.remote_gitdir)},
        )
        return r.returncode == 0
