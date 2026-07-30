"""Shared plumbing for the offline DB-01..DB-08 evidence-bundle tools.

DB-03 and DB-05 both build a body-free bundle whose digest a signed decision
record binds. They read operator-supplied JSON, hash a corpus directory into
item digests, and write one canonical artifact carrying its own binding digest.
That plumbing lives here so a hardening lands once for both tools rather than
being fixed twice.

The guarantees this module is responsible for:

- duplicate JSON keys are refused rather than last-one-wins;
- a corpus directory yields digests only, never content;
- symlinks under a corpus directory are refused, not followed, so bytes from
  outside the declared tree can never enter an artifact;
- an artifact is written atomically, so a failed write cannot leave a truncated
  file that still parses.
"""
from __future__ import annotations

import json
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import Any

from wiki_spike.memory_core.second_brain_ledger_contracts import canonical_ledger_digest


class EvidenceToolError(Exception):
    """Operator-facing failure. Every tool exits 2 on this."""


def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceToolError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_object(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except (OSError, ValueError) as exc:
        raise EvidenceToolError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise EvidenceToolError(f"{path} must contain a JSON object")
    return data


def write_atomic(path: Path, text: str) -> None:
    """Write via a sibling temp file and rename, refusing an existing symlink.

    A half-written artifact that still parses is worse than no artifact, and a
    symlink at the destination would redirect the write outside the intended
    directory.
    """
    if path.is_symlink():
        raise EvidenceToolError(f"{path} is a symlink; refusing to write through it")
    temporary = path.with_name(path.name + ".tmp")
    try:
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise EvidenceToolError(f"cannot write {path}: {exc}") from exc


def emit(body: dict[str, Any], digest_field: str, domain: str, out: str | None) -> int:
    """Bind a body with its own digest and print or write the canonical artifact."""
    body = dict(body)
    body[digest_field] = canonical_ledger_digest(domain, body)
    text = json.dumps(body, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    if out:
        write_atomic(Path(out), text)
        print(json.dumps({"written_to": out, digest_field: body[digest_field]}, indent=2))
    else:
        print(text, end="")
    return 0


def item_digests(directory: Path) -> list[str]:
    """Hash every regular file under ``directory``, sorted path order.

    Only digests leave this function. No corpus content enters a manifest, which
    is what keeps the evidence body-free under DB-08.

    Symlinks are refused rather than skipped or followed: following one would
    silently fold bytes from outside the declared tree into the digest set, and
    skipping one would silently drop a file the operator believes was measured.

    Anything else that is not a regular file -- a FIFO, socket, or device node --
    is refused for the second of those reasons. Reading a FIFO would block
    forever, so it cannot be measured, and skipping it would report a count that
    silently omits an entry the operator can see in the directory.
    """
    if not directory.is_dir():
        raise EvidenceToolError(f"{directory} is not a directory")
    digests = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise EvidenceToolError(
                f"{path} is a symlink; a corpus tree must contain only regular files "
                "so every digest comes from inside the declared directory"
            )
        if path.is_dir():
            continue
        if not path.is_file():
            raise EvidenceToolError(
                f"{path} is not a regular file; a corpus tree must contain only regular "
                "files so the digest count matches what the operator can see"
            )
        digests.append(sha256(path.read_bytes()).hexdigest())
    if not digests:
        raise EvidenceToolError(f"{directory} holds no files to digest")
    if len(set(digests)) != len(digests):
        raise EvidenceToolError(
            f"{directory} holds byte-identical duplicates; a content-digest comparison "
            "cannot tell them apart, so deduplicate deliberately before using it"
        )
    return digests


def dispatch_version(
    path: Path,
    data: dict[str, Any],
    version_fields: tuple[str, ...],
    artifacts: dict[str, tuple[type, str]],
) -> tuple[str, type, str]:
    """Resolve an artifact to its loader and its own binding-digest field.

    Several artifacts carry other artifacts' digests, so dispatch is on the
    version constant. Probing attributes in turn would report a borrowed digest.
    """
    versions = [data[field] for field in version_fields if field in data]
    if len(versions) != 1:
        raise EvidenceToolError(
            f"{path} must carry exactly one version field; found {len(versions)}"
        )
    entry = artifacts.get(versions[0])
    if entry is None:
        raise EvidenceToolError(f"{path} carries an unrecognised version: {versions[0]!r}")
    loader, digest_field = entry
    return versions[0], loader, digest_field


def run(func, args) -> int:
    """Uniform exit contract: 0 accepted, 2 rejected, never a traceback."""
    try:
        return int(func(args))
    except EvidenceToolError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - operator-facing tool, never a traceback
        print(f"FAIL: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
