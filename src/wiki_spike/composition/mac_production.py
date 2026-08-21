"""Mac-first private authenticated V2 production composition."""
from __future__ import annotations

import os
import pwd
import stat
import sys
from datetime import datetime
from pathlib import Path

from wiki_spike.cli import _root_from_argv
from wiki_spike.cli import main as run_authenticated_v2_cli
from wiki_spike.composition.mac_artifact_io import (
    MacArtifactReadError,
    read_mac_artifact_bundle,
)
from wiki_spike.composition.mac_production_admit import (
    closed_artifacts_are_regular,
    mac_workspace_ref,
    refuse_unauthorized,
    verify_existing_serving,
    verify_present_authority,
    verify_present_persistence,
)
from wiki_spike.composition.mac_production_compose import (
    MacProductionComposeError,
    compose_existing_mac_product,
)
from wiki_spike.composition.mac_production_trusted import (
    load_pinned_expected_scope_manifest,
    load_pinned_trusted_keys,
)
from wiki_spike.infrastructure.lifecycle_db_existing import (
    inspect_existing_serving_ready,
    open_existing_lifecycle_database,
)
from wiki_spike.memory_core.second_brain_security_contracts import (
    mint_security_context_authority,
)
from wiki_spike.resources import load_pinned_sqlcipher_artifact_bytes
from wiki_spike.workspace_format import V2WorkspaceRoot, WorkspaceRootError

PINNED_TRUSTED_KEYS = load_pinned_trusted_keys()
PINNED_TRUSTED_NOW: datetime | None = None
PINNED_SQLCIPHER_ARTIFACT_BYTES: bytes = load_pinned_sqlcipher_artifact_bytes()
PINNED_EXPECTED_SCOPE_MANIFEST = load_pinned_expected_scope_manifest()
PINNED_WORKSPACE_REF: str | None = ""


def _resolved_workspace_ref(argv: list[str] | None) -> str:
    if PINNED_WORKSPACE_REF:
        return PINNED_WORKSPACE_REF
    admitted = V2WorkspaceRoot.inspect(
        Path(_root_from_argv(list(sys.argv[1:] if argv is None else argv)))
    )
    return mac_workspace_ref(admitted.marker.workspace_id)


def main(argv: list[str] | None = None) -> int:
    """Admit existing Mac stores after SERVING_READY; refuse closed otherwise."""
    support = (
        Path(pwd.getpwuid(os.getuid()).pw_dir)
        / "Library"
        / "Application Support"
        / "wiki-spike"
    )
    try:
        meta = os.lstat(support)
    except OSError:
        return refuse_unauthorized(argv)
    if stat.S_ISLNK(meta.st_mode) or not stat.S_ISDIR(meta.st_mode):
        return refuse_unauthorized(argv)
    if not closed_artifacts_are_regular(support):
        return refuse_unauthorized(argv)
    try:
        artifacts = read_mac_artifact_bundle(support / "second-brain-v1")
    except MacArtifactReadError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    try:
        workspace_ref = _resolved_workspace_ref(argv)
    except WorkspaceRootError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    authority, refused = verify_present_authority(
        artifacts,
        trusted_keys=PINNED_TRUSTED_KEYS,
        trusted_now=PINNED_TRUSTED_NOW,
        mint_authority=mint_security_context_authority,
        expected_scope_manifest=PINNED_EXPECTED_SCOPE_MANIFEST,
        workspace_ref=workspace_ref,
    )
    if refused is not None or authority is None:
        return 1 if refused is None else refused
    authorization, refused = verify_present_persistence(
        artifacts,
        trusted_keys=PINNED_TRUSTED_KEYS,
        sqlcipher_artifact_bytes=PINNED_SQLCIPHER_ARTIFACT_BYTES,
    )
    if refused is not None or authorization is None:
        return 1 if refused is None else refused
    database, refused = verify_existing_serving(
        support,
        workspace_ref=workspace_ref,
        open_database=open_existing_lifecycle_database,
        inspect_serving=inspect_existing_serving_ready,
    )
    if refused is not None or database is None:
        return 1 if refused is None else refused
    try:
        try:
            product = compose_existing_mac_product(
                v1_dir=support / "second-brain-v1",
                database=database,
                authorization=authorization,
                workspace_ref=workspace_ref,
                keychain_directory=support.parent.parent / "Keychains",
                authority=authority,
            )
        except MacProductionComposeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return run_authenticated_v2_cli(argv, product=product)
    finally:
        database.close()


if __name__ == "__main__":
    raise SystemExit(main())
