#!/usr/bin/env python3
"""Offline hash-only deny-class scan for a synthetic non-serving cohort."""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import tempfile
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from wiki_spike.memory_core.contracts import canonical_bytes  # noqa: E402
from wiki_spike.memory_core.second_brain_ports import CohortBoundaryScanFindingV1, CohortBoundaryScanRequestV1, CohortBoundaryScanResultV1  # noqa: E402

SCANNER_VERSION = "second-brain-cohort-boundary-scan-v1"
DENY_SCHEMA_VERSION = "second-brain-deny-class-v1"
MANDATORY_CLASSES = (
    "credential", "hidden-reasoning", "keychain", "private-key", "secret-token", "session-cookie",
)
RULES: dict[str, tuple[tuple[str, bytes], ...]] = {
    "credential": (("credential-assignment", b"credential="), ("password-assignment", b"password="), ("json-password-key", b"\"password\":"), ("json-credential-key", b"\"credential\":")),
    "hidden-reasoning": (("analysis-tag", b"<analysis>"), ("reasoning-content", b"reasoning_content"), ("chain-of-thought", b"chain_of_thought"), ("hidden-reasoning", b"hidden-reasoning")),
    "keychain": (("keychain-item", b"keychain-item"), ("security-find-generic-password", b"security find-generic-password"), ("ksec-class-generic-password", b"ksecclassgenericpassword")),
    "private-key": (("generic-pem-private-key", b"-----begin private key-----"), ("rsa-pem-private-key", b"-----begin rsa private key-----"), ("ec-pem-private-key", b"-----begin ec private key-----"), ("openssh-private-key", b"-----begin openssh private key-----")),
    "secret-token": (("authorization-bearer", b"authorization: bearer"), ("access-token", b"access_token"), ("refresh-token", b"refresh_token"), ("api-key-assignment", b"api_key="), ("api-key-header", b"x-api-key:")),
    "session-cookie": (("cookie-header", b"cookie:"), ("set-cookie-header", b"set-cookie:"), ("session-assignment", b"session="), ("session-cookie", b"session_cookie")),
}
CHUNK_SIZE = 8192
OVERLAP = max(len(pattern) for rules in RULES.values() for _, pattern in rules) - 1
PATH_COMPONENT_MAX_BYTES = 4096


class ScanError(Exception): pass


def _path_digest(surface: str, relative: str) -> str:
    """Return the only path identity allowed to leave this scanner."""
    return sha256(canonical_bytes({"relative_path": relative, "surface_id": surface})).hexdigest()


def _component_hits(component: str) -> tuple[set[tuple[str, str]], bool]:
    """Scan one filesystem name without retaining or emitting that name.

    Filesystem component limits are normally much smaller, but the explicit
    bound keeps the privacy scan fail-closed on unusual filesystem adapters.
    """
    encoded = os.fsencode(component)
    if len(encoded) > PATH_COMPONENT_MAX_BYTES:
        return set(), False
    folded = encoded.lower()
    hits: set[tuple[str, str]] = set()
    for class_id, rules in RULES.items():
        for rule_id, pattern in rules:
            if pattern in folded:
                hits.add((class_id, rule_id))
    return hits, True


def _entry(surface: str, relative: str, size: str | None, digest: str | None, result: str, class_ids: list[str], rule_ids: list[str]) -> dict[str, Any]:
    return {"surface_id": surface, "path_digest": _path_digest(surface, relative), "size": size, "sha256": digest, "scan_result": result, "class_ids": class_ids, "rule_ids": rule_ids}


def _finding(surface: str, relative: str, digest: str | None, class_id: str | None, rule_id: str) -> dict[str, Any]:
    return {"surface_id": surface, "path_digest": _path_digest(surface, relative), "sha256": digest, "class_id": class_id, "rule_id": rule_id}


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result: raise ScanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _path(raw: str, label: str, *, leaf: bool) -> Path:
    if not os.path.isabs(raw) or raw.startswith("//") or raw != os.path.normpath(raw) or any(x in {".", ".."} for x in raw.split(os.sep)):
        raise ScanError(f"{label} must be a canonical absolute path")
    path = Path(raw); current = Path(path.anchor)
    checked = path.parts[1:] if leaf else path.parts[1:-1]
    for index, part in enumerate(checked):
        current /= part
        try: info = current.lstat()
        except FileNotFoundError:
            if leaf and index == len(checked) - 1: return path
            raise ScanError(f"cannot stat {label}: missing ancestor")
        except OSError as exc: raise ScanError(f"cannot stat {label}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode): raise ScanError(f"{label} traverses a symlink")
    return path


def _object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode): raise ScanError(f"{label} must be a regular file")
        raw = path.read_bytes(); value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except ScanError: raise
    except (OSError, UnicodeDecodeError, ValueError) as exc: raise ScanError(f"cannot load {label}: {exc}") from exc
    if not isinstance(value, dict) or canonical_bytes(value) != raw: raise ScanError(f"{label} must be canonical JSON object")
    return value, raw


def _schema(path: Path) -> tuple[str, tuple[tuple[str, str], ...]]:
    data, raw = _object(path, "deny schema")
    if set(data) != {"deny_class_schema_version", "classes"} or data["deny_class_schema_version"] != DENY_SCHEMA_VERSION or not isinstance(data["classes"], list):
        raise ScanError("deny schema has unsupported fields or version")
    entries: list[tuple[str, str]] = []
    for item in data["classes"]:
        if not isinstance(item, Mapping) or set(item) != {"class_id", "rule_id"} or not isinstance(item["class_id"], str) or not isinstance(item["rule_id"], str): raise ScanError("deny schema classes must be closed class/rule objects")
        entries.append((item["class_id"], item["rule_id"]))
    expected = tuple((class_id, rule_id) for class_id in MANDATORY_CLASSES for rule_id, _ in RULES[class_id])
    if tuple(entries) != expected or len(set(entries)) != len(entries): raise ScanError("deny schema must contain exactly every mandatory class and rule")
    return sha256(raw).hexdigest(), tuple(entries)


def _file(path: Path, surface: str, relative: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    fd: int | None = None
    try:
        path_hits, bounded = _component_hits(path.name)
        if not bounded:
            raise OSError("path component exceeds bounded scan limit")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode): raise OSError("not a regular non-symlink file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0); fd = os.open(path, flags); opened = os.fstat(fd)
        if (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino): raise OSError("replaced before open")
        digest = sha256(); hits = path_hits; tail = b""
        with os.fdopen(fd, "rb") as handle:
            fd = None
            while chunk := handle.read(CHUNK_SIZE):
                digest.update(chunk); window = (tail + chunk).lower()
                for class_id, rules in RULES.items():
                    for rule_id, pattern in rules:
                        if pattern in window: hits.add((class_id, rule_id))
                tail = window[-OVERLAP:]
        final = path.stat(); after = os.stat(path)
        if any(getattr(opened, name) != getattr(after, name) for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")) or any(getattr(opened, name) != getattr(final, name) for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")): raise OSError("file changed during scan")
        item = _entry(surface, relative, str(info.st_size), digest.hexdigest(), "DENY_HIT" if hits else "CLEAR", [x[0] for x in sorted(hits)], [x[1] for x in sorted(hits)])
        findings = [_finding(surface, relative, item["sha256"], c, r) for c, r in sorted(hits)]
        return item, findings
    except OSError:
        item = _entry(surface, relative, None, None, "INCOMPLETE", [], ["surface-incomplete"])
        return item, [_finding(surface, relative, None, None, "surface-incomplete")]
    finally:
        if fd is not None:
            os.close(fd)


def _tree(path: Path, surface: str, seen: set[tuple[int, int]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []; findings: list[dict[str, Any]] = []
    def visit(directory: Path) -> None:
        relative = directory.relative_to(path).as_posix() if directory != path else "."
        try:
            if directory != path:
                path_hits, bounded = _component_hits(directory.name)
                if not bounded:
                    raise OSError("path component exceeds bounded scan limit")
                for class_id, rule_id in sorted(path_hits):
                    findings.append(_finding(surface, relative, _path_digest(surface, relative), class_id, rule_id))
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode): raise OSError("not a directory")
            key = (info.st_dev, info.st_ino)
            if key in seen: raise OSError("duplicate inode")
            seen.add(key); children = sorted(directory.iterdir(), key=lambda p: p.name); snapshot = (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns, tuple(child.name for child in children))
        except OSError:
            entries.append(_entry(surface, relative, None, None, "INCOMPLETE", [], ["surface-incomplete"]))
            findings.append(_finding(surface, relative, None, None, "surface-incomplete")); return
        for child in children:
            try: mode = child.lstat().st_mode
            except OSError: mode = 0
            if stat.S_ISDIR(mode): visit(child); continue
            relative = child.relative_to(path).as_posix()
            if not stat.S_ISREG(mode):
                entries.append(_entry(surface, relative, None, None, "INCOMPLETE", [], ["surface-incomplete"])); findings.append(_finding(surface, relative, None, None, "surface-incomplete")); continue
            info = child.lstat(); key = (info.st_dev, info.st_ino)
            if key in seen:
                entries.append(_entry(surface, relative, None, None, "INCOMPLETE", [], ["surface-incomplete"])); findings.append(_finding(surface, relative, None, None, "surface-incomplete")); continue
            seen.add(key); item, found = _file(child, surface, relative); entries.append(item); findings.extend(found)
        try:
            after = directory.stat(); names = tuple(child.name for child in sorted(directory.iterdir(), key=lambda p: p.name))
            if snapshot != (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns, names): raise OSError("directory changed during scan")
        except OSError:
            relative = (directory.relative_to(path).as_posix() + "/.inventory") if directory != path else ".inventory"
            entries.append(_entry(surface, relative, None, None, "INCOMPLETE", [], ["surface-incomplete"])); findings.append(_finding(surface, relative, None, None, "surface-incomplete"))
    visit(path)
    root_path_digest = _path_digest(surface, ".")
    if not (entries and entries[0]["path_digest"] == root_path_digest and entries[0]["scan_result"] == "INCOMPLETE"):
        inventory = [{"path_digest": item["path_digest"], "size": item["size"], "sha256": item["sha256"]} for item in entries]
        states = {item["scan_result"] for item in entries}
        states.update("DENY_HIT" for finding in findings if finding["class_id"] is not None)
        root_state = "INCOMPLETE" if "INCOMPLETE" in states else "DENY_HIT" if "DENY_HIT" in states else "CLEAR"
        classes = sorted({value for finding in findings if (value := finding["class_id"]) is not None}); rules = sorted({finding["rule_id"] for finding in findings})
        digest = sha256(canonical_bytes({"files": inventory})).hexdigest()
        root = _entry(surface, ".", "0", digest, root_state, classes, rules)
        root["inventory_count"] = str(len(inventory)); root["inventory_digest"] = digest
        entries.insert(0, root)
    return entries, findings


def _publish(path: Path, receipt: Mapping[str, Any]) -> None:
    payload = canonical_bytes(receipt)
    try: path.lstat()
    except FileNotFoundError: pass
    except OSError as exc: raise ScanError(f"cannot stat output: {exc}") from exc
    else: raise ScanError("output collision")
    temporary: str | None = None; linked = False; temporary_stat = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        with os.fdopen(fd, "wb") as out: out.write(payload); out.flush(); os.fsync(out.fileno())
        temporary_stat = os.stat(temporary)
        os.link(temporary, path)
        linked = True
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    except FileExistsError as exc: raise ScanError("output collision") from exc
    except OSError as exc:
        if linked and temporary_stat is not None:
            try:
                published = os.stat(path)
                if (published.st_dev, published.st_ino) == (temporary_stat.st_dev, temporary_stat.st_ino): os.unlink(path)
                directory = os.open(path.parent, os.O_RDONLY)
                try: os.fsync(directory)
                finally: os.close(directory)
            except OSError: pass
        raise ScanError(f"cannot publish receipt: {exc}") from exc
    finally:
        if temporary:
            try: os.unlink(temporary)
            except FileNotFoundError: pass


def verify(args: argparse.Namespace) -> int:
    schema = _path(args.deny_class_schema, "--deny-class-schema", leaf=True)
    singles = {"source_export": _path(args.source_export, "--source-export", leaf=True), "manifest": _path(args.manifest, "--manifest", leaf=True), "cohort_payload": _path(args.cohort_payload, "--cohort-payload", leaf=True), "db": _path(args.db, "--db", leaf=True), "wal": _path(args.wal, "--wal", leaf=True), "cohort_receipt": _path(args.receipt, "--receipt", leaf=True)}
    trees = {"cas": _path(args.cas, "--cas", leaf=True), "log": _path(args.log_dir, "--log-dir", leaf=True)}
    output = _path(args.out, "--out", leaf=False)
    for root in trees.values():
        try: output.relative_to(root)
        except ValueError: pass
        else: raise ScanError("output must not be inside a scanned tree")
    schema_digest, _ = _schema(schema)
    seen: set[tuple[int, int]] = set(); entries: list[dict[str, Any]] = []; findings: list[dict[str, Any]] = []
    for surface, path in singles.items():
        try:
            info = path.lstat(); key = (info.st_dev, info.st_ino)
            if key in seen: raise OSError("duplicate inode")
            seen.add(key)
        except OSError:
            entries.append(_entry(surface, ".", None, None, "INCOMPLETE", [], ["surface-incomplete"])); findings.append(_finding(surface, ".", None, None, "surface-incomplete")); continue
        item, found = _file(path, surface, "."); entries.append(item); findings.extend(found)
    for surface, path in trees.items():
        items, found = _tree(path, surface, seen); entries.extend(items); findings.extend(found)
    required_surfaces = {"source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log", "cohort_receipt"}
    present = [item["surface_id"] for item in entries]
    top_level = [item["surface_id"] for item in entries if item["path_digest"] == _path_digest(item["surface_id"], ".")]
    if set(present) != required_surfaces or tuple(sorted(top_level)) != tuple(sorted(required_surfaces)):
        raise ScanError("receipt surface coverage is incomplete")
    result = "PASS" if not findings else "QUARANTINED"
    digests = tuple((surface, _path_digest(surface, "."), sha256(canonical_bytes({"entries": [item for item in entries if item["surface_id"] == surface]})).hexdigest()) for surface in sorted(required_surfaces))
    try:
        CohortBoundaryScanRequestV1(SCANNER_VERSION, schema_digest, digests)
        contract_findings = tuple(CohortBoundaryScanFindingV1(item["surface_id"], item["path_digest"], item["sha256"], item["class_id"], item["rule_id"]) for item in findings)
        CohortBoundaryScanResultV1(result, result != "PASS", contract_findings)
    except ValueError as exc: raise ScanError(f"scan contract rejected: {exc}") from exc
    receipt = {"boundary_scan_receipt_version": "second-brain-cohort-boundary-scan-receipt-v1", "scanner_version": SCANNER_VERSION, "deny_schema_digest": schema_digest, "result": result, "no_import": result != "PASS", "surfaces": entries, "findings": findings}
    _publish(output, receipt)
    print(json.dumps({"out_digest": sha256(canonical_bytes({"out": args.out})).hexdigest(), "result": result}, sort_keys=True))
    return 0 if result == "PASS" else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); commands = parser.add_subparsers(dest="command", required=True); command = commands.add_parser("verify")
    for option in ("deny_class_schema", "source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log_dir", "receipt", "out"): command.add_argument("--" + option.replace("_", "-"), required=True)
    try: args = parser.parse_args(argv); return verify(args)
    except (ScanError, SystemExit) as exc:
        if isinstance(exc, SystemExit): return int(exc.code) if isinstance(exc.code, int) else 2
        print(f"FAIL: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
