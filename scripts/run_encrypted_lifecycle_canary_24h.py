#!/usr/bin/env python3
"""Exactly-24-hour canary runner for the Encrypted Single-Memory Lifecycle
(Gate 8, CANARY_24H lane).

Periodically exercises a full encrypted-lifecycle round-trip on a fresh
disposable workspace and records the outcome, for the configured duration
(production: exactly 24 hours on a self-hosted macOS runner). Each probe:

  1. REMEMBER a body (sealed encrypted-before-durability).
  2. Decrypt the stored envelope and verify the round-trip plaintext.
  3. FORGET under dual custody (platform + recovery) and verify the immediate
     deletion veto.

After the duration elapses it writes ``canary-report.json`` (probe count,
failures, started/finished timestamps, duration) and, with the bundle
arguments supplied, wraps it into an immutable ``CANARY_24H`` bundle for the
Gate 8 three-lane join.

The runner is fail-closed: any probe failure is recorded and the final report
marks ``healthy=false``; a non-healthy run exits non-zero and refuses to emit a
bundle. Production bundle issuance is restricted to an exactly 86400-second
run with 900-second probe intervals. Short runs are simulations and cannot
produce ``CANARY_24H`` evidence.
"""
from __future__ import annotations

import argparse
from decimal import Decimal, InvalidOperation, ROUND_DOWN
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from build_encrypted_lifecycle_bundle import canonical_bytes

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from wiki_spike.infrastructure import crypto  # noqa: E402
from wiki_spike.infrastructure.encrypted_cas import EncryptedContentStore  # noqa: E402
from wiki_spike.infrastructure.keystore import PlatformKeyStore, RecoveryKeyStore  # noqa: E402
from wiki_spike.infrastructure.lifecycle_db import LifecycleDatabase  # noqa: E402
from wiki_spike.applications.encrypted_lifecycle_pipeline import (  # noqa: E402
    EncryptedLifecyclePipeline,
    PipelineError,
)

REPORT_SCHEMA = "wiki-gate8-canary-report-v1"
CANARY_IKM = hashlib.sha256(b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-CANARY-IKM-V1").digest()
CANARY_DEK = hashlib.sha256(b"WIKI-SPIKE-ENCRYPTED-LIFECYCLE-CANARY-DEK").digest()

PRODUCTION_DURATION_SECONDS = "86400"
PRODUCTION_INTERVAL_SECONDS = "900"
DEFAULT_DURATION_SECONDS = int(PRODUCTION_DURATION_SECONDS)
DEFAULT_INTERVAL_SECONDS = int(PRODUCTION_INTERVAL_SECONDS)


def run_probe(probe_index: int) -> dict:
    """Run one full encrypted-lifecycle canary round-trip on a fresh disposable
    workspace. Returns a probe result dict; never raises."""
    started = time.time()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            db = LifecycleDatabase(db_path=tmp_path / "lifecycle.db")
            db.initialize()
            cas = EncryptedContentStore(root=tmp_path / "cas")
            platform = PlatformKeyStore(tmp_path / "keystore-platform")
            recovery = RecoveryKeyStore(tmp_path / "keystore-recovery")
            keys = crypto.derive_identity_keys(CANARY_IKM)
            pipeline = EncryptedLifecyclePipeline(
                workspace_id="ws-canary",
                derived_keys=keys,
                db=db,
                cas=cas,
                dek=CANARY_DEK,
                platform_keystore=platform,
                recovery_keystore=recovery,
            )

            body = f"canary probe {probe_index} body".encode("utf-8")
            remembered = pipeline.remember(raw_body=body, project_id="canary-project")

            # Round-trip: unwrap the per-artifact ARK DEK from the platform
            # custodian (dual custody means remember() sealed under a random
            # per-artifact DEK, not the pipeline DEK), decrypt, and verify.
            ark_dek = platform.get_ark_dek("ws-canary", remembered.artifact_semantic_digest)
            envelope_bytes = cas.get(remembered.blob_id)
            envelope = json.loads(envelope_bytes.decode("utf-8"))
            aad = crypto.domain_prefix("wiki.envelope.v1") + bytes.fromhex(remembered.artifact_semantic_digest)
            plaintext = crypto.aes_gcm_open(
                ark_dek, envelope["nonce"], envelope["ciphertext"], envelope["tag"], aad
            )
            if plaintext != body:
                raise PipelineError("canary_roundtrip_mismatch", "decrypted body != remembered body")

            # Forget under dual custody and verify the immediate veto.
            pipeline.forget(artifact_id=remembered.artifact_semantic_digest, blob_id=remembered.blob_id)
            if not pipeline.is_object_vetoed(remembered.artifact_semantic_digest):
                raise PipelineError("canary_veto_missing", "object not vetoed after forget")

            db.close()
        return {
            "probe_index": str(probe_index),
            "passed": True,
            "error": None,
            "elapsed_seconds": f"{time.time() - started:.3f}",
        }
    except Exception as exc:  # noqa: BLE001 - record any probe failure
        return {
            "probe_index": str(probe_index),
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
            "elapsed_seconds": f"{time.time() - started:.3f}",
        }


CHECKPOINT_SCHEMA = "wiki-gate8-canary-checkpoint-v3"
_EPOCH_PRECISION = Decimal("0.001")
_CANONICAL_INTEGER_RE = re.compile(r"(?:0|[1-9][0-9]*)")
_CANONICAL_EPOCH_RE = re.compile(r"(?:0|[1-9][0-9]*)\.[0-9]{3}")


def _canonical_epoch(value: Decimal | float) -> str:
    epoch = (value if isinstance(value, Decimal) else Decimal(str(value))).quantize(
        _EPOCH_PRECISION, rounding=ROUND_DOWN
    )
    if not epoch.is_finite() or epoch < 0:
        raise ValueError("CANARY_24H epoch is invalid")
    return format(epoch, ".3f")


def _parse_canonical_integer(value: object, field: str) -> int:
    if not isinstance(value, str) or _CANONICAL_INTEGER_RE.fullmatch(value) is None:
        raise ValueError(f"CANARY_24H checkpoint {field} must be a canonical decimal string")
    return int(value)


def _parse_canonical_epoch(value: object, field: str) -> Decimal:
    if not isinstance(value, str) or _CANONICAL_EPOCH_RE.fullmatch(value) is None:
        raise ValueError(f"CANARY_24H checkpoint {field} must be a fixed-precision canonical decimal string")
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"CANARY_24H checkpoint {field} is invalid") from exc
_CHECKPOINT_GENESIS_SHA256 = hashlib.sha256(b"wiki-gate8-canary-checkpoint-genesis-v1").hexdigest()


def _checkpoint_binding(
    *,
    repository: str,
    workflow_run_id: str,
    implementation_commit: str,
    workflow_file_digest: str,
    contract_digest: str,
    toolchain_lock_digest: str,
) -> dict[str, str]:
    return {
        "repository": repository,
        "original_workflow_run_id": workflow_run_id,
        "implementation_commit": implementation_commit,
        "workflow_file_digest": workflow_file_digest,
        "contract_digest": contract_digest,
        "toolchain_lock_digest": toolchain_lock_digest,
    }
def _static_binding(binding: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in binding.items() if key != "original_workflow_run_id"}


def _require_secure_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"CANARY_24H durable state path is not a directory: {path}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError(f"CANARY_24H durable state path is not service-owned private storage: {path}")
def _require_secure_file(path: Path) -> None:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"CANARY_24H durable checkpoint path is unsafe: {path}")
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError(f"CANARY_24H durable checkpoint is not service-owned private storage: {path}")


def _durable_state_directory(root: Path, binding: dict[str, str], *, create: bool) -> Path:
    if not root.is_absolute():
        raise ValueError("CANARY_24H durable state root must be an absolute service-owned path")
    _require_secure_directory(root)
    path = root
    for component in (
        hashlib.sha256(binding["repository"].encode()).hexdigest(),
        binding["implementation_commit"],
        hashlib.sha256(binding["original_workflow_run_id"].encode()).hexdigest(),
    ):
        path = path / component
        _require_secure_directory(path, create=create)
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_private(path: Path, payload: bytes) -> None:
    _require_secure_directory(path.parent)
    temporary = path.parent / f".{path.name}.{os.getpid()}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _canonical_checkpoint_digest(checkpoint: dict) -> str:
    unsigned = {key: value for key, value in checkpoint.items() if key != "checkpoint_sha256"}
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def _require_ordered_probe_prefix(probes: list[dict], next_probe_index: int) -> None:
    if len(probes) > 97 or len(probes) != next_probe_index:
        raise ValueError("CANARY_24H checkpoint has an invalid probe history")
    for index, probe in enumerate(probes):
        if (
            not isinstance(probe, dict)
            or probe.get("probe_index") != str(index)
            or set(probe) != {
                "probe_index",
                "passed",
                "error",
                "elapsed_seconds",
                "scheduled_at_epoch",
                "completed_at_epoch",
            }
        ):
            raise ValueError("CANARY_24H checkpoint probes are reordered or tampered")
        if (
            _parse_canonical_epoch(probe["scheduled_at_epoch"], "probe scheduled_at_epoch")
            > _parse_canonical_epoch(probe["completed_at_epoch"], "probe completed_at_epoch")
        ):
            raise ValueError("CANARY_24H checkpoint probe timestamps are invalid")


def _load_checkpoint(
    path: Path,
    binding: dict[str, str] | None,
    duration_seconds: int,
    interval_seconds: int,
    *,
    validate_freshness: bool = True,
) -> dict:
    try:
        checkpoint = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("CANARY_24H checkpoint is unreadable") from exc
    required = {
        "schema", "binding", "state", "duration_seconds", "interval_seconds", "started_at_epoch",
        "deadline_at_epoch", "next_probe_index", "next_probe_at_epoch", "last_observed_epoch",
        "probes", "probe_history_sha256", "prior_checkpoint_sha256", "checkpoint_sha256",
    }
    if set(checkpoint) != required or checkpoint["schema"] != CHECKPOINT_SCHEMA:
        raise ValueError("CANARY_24H checkpoint wire is invalid")
    if not isinstance(checkpoint["binding"], dict):
        raise ValueError("CANARY_24H checkpoint binding is invalid")
    if binding is not None and checkpoint["binding"] != binding:
        raise ValueError("CANARY_24H checkpoint is bound to another repository, commit, run, workflow, or digest")
    stored_duration = _parse_canonical_integer(checkpoint["duration_seconds"], "duration_seconds")
    stored_interval = _parse_canonical_integer(checkpoint["interval_seconds"], "interval_seconds")
    next_probe_index = _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index")
    if stored_duration != duration_seconds or stored_interval != interval_seconds:
        raise ValueError("CANARY_24H checkpoint configuration does not match")
    if not isinstance(checkpoint["probes"], list):
        raise ValueError("CANARY_24H checkpoint probes are invalid")
    started_at = _parse_canonical_epoch(checkpoint["started_at_epoch"], "started_at_epoch")
    deadline_at = _parse_canonical_epoch(checkpoint["deadline_at_epoch"], "deadline_at_epoch")
    next_probe_at = _parse_canonical_epoch(checkpoint["next_probe_at_epoch"], "next_probe_at_epoch")
    last_observed = _parse_canonical_epoch(checkpoint["last_observed_epoch"], "last_observed_epoch")
    if checkpoint["state"] not in {"incomplete", "failed", "terminal-issued"}:
        raise ValueError("CANARY_24H checkpoint lifecycle state is invalid")
    if deadline_at != started_at + duration_seconds or next_probe_index < 0:
        raise ValueError("CANARY_24H checkpoint schedule is tampered")
    expected_next = min(started_at + (next_probe_index * interval_seconds), deadline_at)
    if next_probe_at != expected_next or next_probe_at > deadline_at:
        raise ValueError("CANARY_24H checkpoint schedule is tampered")
    _require_ordered_probe_prefix(checkpoint["probes"], next_probe_index)
    previous_completed = started_at
    for index, probe in enumerate(checkpoint["probes"]):
        scheduled_at = _parse_canonical_epoch(probe["scheduled_at_epoch"], "probe scheduled_at_epoch")
        completed_at = _parse_canonical_epoch(probe["completed_at_epoch"], "probe completed_at_epoch")
        if (
            scheduled_at != min(started_at + (index * interval_seconds), deadline_at)
            or completed_at < previous_completed
            or completed_at > scheduled_at + interval_seconds
        ):
            raise ValueError("CANARY_24H checkpoint probes are skipped or reordered")
        previous_completed = completed_at
    history = hashlib.sha256(canonical_bytes(checkpoint["probes"])).hexdigest()
    if checkpoint["probe_history_sha256"] != history or checkpoint["checkpoint_sha256"] != _canonical_checkpoint_digest(checkpoint):
        raise ValueError("CANARY_24H checkpoint state is tampered")
    if not re.fullmatch(r"[0-9a-f]{64}", checkpoint["prior_checkpoint_sha256"]):
        raise ValueError("CANARY_24H checkpoint chain is invalid")
    now = Decimal(str(time.time()))
    if now < last_observed:
        raise ValueError("CANARY_24H clock rollback detected")
    if last_observed != previous_completed:
        raise ValueError("CANARY_24H checkpoint last observed time is tampered")
    if checkpoint["state"] == "incomplete":
        if validate_freshness:
            if next_probe_index <= duration_seconds // interval_seconds and now >= next_probe_at + interval_seconds:
                raise ValueError("CANARY_24H checkpoint has skipped a scheduled probe")
            if now > deadline_at:
                raise ValueError("CANARY_24H checkpoint is stale")
    elif next_probe_index != duration_seconds // interval_seconds + 1:
        raise ValueError("CANARY_24H terminal checkpoint is incomplete")
    return checkpoint


def _write_checkpoint(path: Path, checkpoint: dict) -> None:
    _parse_canonical_integer(checkpoint["duration_seconds"], "duration_seconds")
    _parse_canonical_integer(checkpoint["interval_seconds"], "interval_seconds")
    _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index")
    for field in ("started_at_epoch", "deadline_at_epoch", "next_probe_at_epoch", "last_observed_epoch"):
        _parse_canonical_epoch(checkpoint[field], field)
    _require_ordered_probe_prefix(
        checkpoint["probes"], _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index")
    )
    checkpoint["probe_history_sha256"] = hashlib.sha256(canonical_bytes(checkpoint["probes"])).hexdigest()
    checkpoint["checkpoint_sha256"] = _canonical_checkpoint_digest(checkpoint)
    _atomic_write_private(path, canonical_bytes(checkpoint))


def _persist_durable_checkpoint(state_dir: Path, checkpoint: dict) -> None:
    checkpoint["probe_history_sha256"] = hashlib.sha256(canonical_bytes(checkpoint["probes"])).hexdigest()
    checkpoint["checkpoint_sha256"] = _canonical_checkpoint_digest(checkpoint)
    _write_checkpoint(state_dir / f"checkpoint-{checkpoint['next_probe_index']}-{checkpoint['checkpoint_sha256']}.json", checkpoint)


def _load_durable_chain(state_dir: Path, static_binding: dict[str, str], duration_seconds: int, interval_seconds: int) -> dict:
    _require_secure_directory(state_dir)
    entries = list(state_dir.iterdir())
    if any(entry.is_symlink() for entry in entries):
        raise ValueError("CANARY_24H durable state contains a symlink")
    checkpoint_paths = [
        entry for entry in entries if re.fullmatch(r"checkpoint-[0-9]+-[0-9a-f]{64}\.json", entry.name)
    ]
    if not checkpoint_paths:
        raise ValueError("CANARY_24H durable state has no checkpoint chain")

    checkpoints_by_digest: dict[str, dict] = {}
    successors: dict[str, list[str]] = {}
    checkpoint_paths_by_digest: dict[str, Path] = {}
    chain_binding = None
    for entry in checkpoint_paths:
        _require_secure_file(entry)
        checkpoint = _load_checkpoint(
            entry, None, duration_seconds, interval_seconds, validate_freshness=False
        )
        digest = checkpoint["checkpoint_sha256"]
        expected_name = f"checkpoint-{checkpoint['next_probe_index']}-{digest}.json"
        if entry.name != expected_name:
            raise ValueError("CANARY_24H durable checkpoint filename is tampered")
        if digest in checkpoints_by_digest:
            raise ValueError("CANARY_24H durable checkpoint chain has a duplicate digest")
        if _static_binding(checkpoint["binding"]) != static_binding:
            raise ValueError("CANARY_24H durable checkpoint has wrong binding")
        if chain_binding is None:
            chain_binding = checkpoint["binding"]
        elif checkpoint["binding"] != chain_binding:
            raise ValueError("CANARY_24H durable checkpoint chain has inconsistent binding")
        checkpoints_by_digest[digest] = checkpoint
        checkpoint_paths_by_digest[digest] = entry
        successors.setdefault(checkpoint["prior_checkpoint_sha256"], []).append(digest)

    genesis_children = successors.get(_CHECKPOINT_GENESIS_SHA256, [])
    if len(genesis_children) != 1:
        raise ValueError("CANARY_24H durable checkpoint chain must have exactly one genesis child")
    for prior, children in successors.items():
        if prior != _CHECKPOINT_GENESIS_SHA256 and prior not in checkpoints_by_digest:
            raise ValueError("CANARY_24H durable checkpoint chain has an orphan")
        if len(children) > 1:
            raise ValueError("CANARY_24H durable checkpoint chain has a fork")

    walked: set[str] = set()
    digest = genesis_children[0]
    previous = None
    while True:
        if digest in walked:
            raise ValueError("CANARY_24H durable checkpoint chain has a cycle")
        checkpoint = checkpoints_by_digest.get(digest)
        if checkpoint is None:
            raise ValueError("CANARY_24H durable checkpoint chain has an orphan")
        if previous is not None:
            previous_index = _parse_canonical_integer(previous["next_probe_index"], "next_probe_index")
            index = _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index")
            if index != previous_index + 1 and not (
                index == previous_index and checkpoint["state"] in {"failed", "terminal-issued"}
            ):
                raise ValueError("CANARY_24H durable checkpoint chain has a schedule gap")
        walked.add(digest)
        children = successors.get(digest, [])
        if checkpoint["state"] in {"failed", "terminal-issued"} and children:
            raise ValueError("CANARY_24H durable checkpoint chain extends a terminal checkpoint")
        if not children:
            break
        digest = children[0]
        previous = checkpoint

    if len(walked) != len(checkpoints_by_digest):
        raise ValueError("CANARY_24H durable checkpoint chain has an orphan or cycle")
    _load_checkpoint(
        checkpoint_paths_by_digest[checkpoint["checkpoint_sha256"]],
        checkpoint["binding"],
        duration_seconds,
        interval_seconds,
    )
    return checkpoint


def _discover_durable_checkpoint(root: Path, binding: dict[str, str], duration_seconds: int, interval_seconds: int) -> tuple[Path, dict] | None:
    """Discover only this original workflow run's durable state."""
    if not root.is_absolute():
        raise ValueError("CANARY_24H durable state root must be absolute")
    _require_secure_directory(root)
    state_dir = root / hashlib.sha256(binding["repository"].encode()).hexdigest() / binding["implementation_commit"] / hashlib.sha256(binding["original_workflow_run_id"].encode()).hexdigest()
    if not state_dir.exists():
        return None
    checkpoint = _load_durable_chain(state_dir, _static_binding(binding), duration_seconds, interval_seconds)
    if checkpoint["binding"] != binding:
        raise ValueError("CANARY_24H durable checkpoint belongs to another original workflow run")
    if checkpoint["state"] == "terminal-issued":
        raise ValueError("CANARY_24H completed evidence cannot be replayed or relabeled")
    if checkpoint["state"] == "failed":
        raise ValueError("CANARY_24H failed original workflow run requires a fresh dispatch")
    return state_dir, checkpoint


def run_canary(
    duration_seconds: int,
    interval_seconds: int,
    *,
    durable_state_root: Path | None = None,
    checkpoint_binding: dict[str, str] | None = None,
    interrupt_after_probe: int | None = None,
) -> dict:
    """Run fixed wall-clock probes and durably chain each completed probe."""
    state_dir = None
    checkpoint = None
    if durable_state_root is not None:
        if checkpoint_binding is None:
            raise ValueError("checkpoint binding is required")
        discovered = _discover_durable_checkpoint(
            durable_state_root, checkpoint_binding, duration_seconds, interval_seconds
        )
        if discovered is not None:
            state_dir, checkpoint = discovered
        else:
            state_dir = _durable_state_directory(durable_state_root, checkpoint_binding, create=True)
    if checkpoint is None:
        started_at = Decimal(str(time.time())).quantize(_EPOCH_PRECISION, rounding=ROUND_DOWN)
        checkpoint = {
            "schema": CHECKPOINT_SCHEMA,
            "binding": checkpoint_binding or {},
            "state": "incomplete",
            "duration_seconds": str(duration_seconds),
            "interval_seconds": str(interval_seconds),
            "started_at_epoch": _canonical_epoch(started_at),
            "deadline_at_epoch": _canonical_epoch(started_at + duration_seconds),
            "next_probe_index": "0",
            "next_probe_at_epoch": _canonical_epoch(started_at),
            "last_observed_epoch": _canonical_epoch(started_at),
            "probes": [],
            "probe_history_sha256": hashlib.sha256(canonical_bytes([])).hexdigest(),
            "prior_checkpoint_sha256": _CHECKPOINT_GENESIS_SHA256,
            "checkpoint_sha256": "",
        }
        if state_dir is not None:
            _persist_durable_checkpoint(state_dir, checkpoint)
    started_at = _parse_canonical_epoch(checkpoint["started_at_epoch"], "started_at_epoch")
    deadline_at = _parse_canonical_epoch(checkpoint["deadline_at_epoch"], "deadline_at_epoch")
    probes = checkpoint["probes"]
    monotonic_origin = time.monotonic()
    wall_origin = Decimal(str(time.time()))
    while _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index") <= duration_seconds // interval_seconds:
        probe_index = _parse_canonical_integer(checkpoint["next_probe_index"], "next_probe_index")
        scheduled_at = _parse_canonical_epoch(checkpoint["next_probe_at_epoch"], "next_probe_at_epoch")
        last_observed = _parse_canonical_epoch(checkpoint["last_observed_epoch"], "last_observed_epoch")
        now = Decimal(str(time.time()))
        if now < last_observed:
            raise ValueError("CANARY_24H clock rollback detected")
        if now >= scheduled_at + interval_seconds:
            raise ValueError("CANARY_24H scheduled probe was skipped")
        delay = float(scheduled_at - wall_origin) - (time.monotonic() - monotonic_origin)
        if delay > 0:
            time.sleep(delay)
        probe = run_probe(probe_index)
        completed_at = Decimal(str(time.time())).quantize(_EPOCH_PRECISION, rounding=ROUND_DOWN)
        if completed_at < last_observed or completed_at > scheduled_at + interval_seconds:
            raise ValueError("CANARY_24H clock rollback or skipped probe detected")
        probe["scheduled_at_epoch"] = _canonical_epoch(scheduled_at)
        probe["completed_at_epoch"] = _canonical_epoch(completed_at)
        probes.append(probe)
        checkpoint["prior_checkpoint_sha256"] = checkpoint["checkpoint_sha256"]
        next_probe_index = probe_index + 1
        checkpoint["next_probe_index"] = str(next_probe_index)
        checkpoint["next_probe_at_epoch"] = _canonical_epoch(
            min(started_at + (next_probe_index * interval_seconds), deadline_at)
        )
        checkpoint["last_observed_epoch"] = _canonical_epoch(completed_at)
        if state_dir is not None and next_probe_index <= duration_seconds // interval_seconds:
            _persist_durable_checkpoint(state_dir, checkpoint)
        if interrupt_after_probe is not None and probe_index == interrupt_after_probe:
            raise InterruptedError("CANARY_24H simulated interruption after durable checkpoint")
    failures = sum(1 for probe in probes if not probe["passed"])
    finished_at = Decimal(str(time.time())).quantize(_EPOCH_PRECISION, rounding=ROUND_DOWN)
    if finished_at < _parse_canonical_epoch(checkpoint["last_observed_epoch"], "last_observed_epoch") or finished_at < deadline_at:
        raise ValueError("CANARY_24H clock rollback or shortened schedule detected")
    checkpoint["state"] = "terminal-issued" if failures == 0 else "failed"
    checkpoint["prior_checkpoint_sha256"] = checkpoint["checkpoint_sha256"]
    if state_dir is not None:
        _persist_durable_checkpoint(state_dir, checkpoint)
    return {
        "schema": REPORT_SCHEMA,
        "evidence_lane": "CANARY_SIMULATION",
        "healthy": failures == 0,
        "probe_count": str(len(probes)),
        "failure_count": str(failures),
        "configured_duration_seconds": str(duration_seconds),
        "interval_seconds": str(interval_seconds),
        "original_workflow_run_id": checkpoint["binding"].get("original_workflow_run_id"),
        "observed_duration_seconds": f"{max(Decimal(0), finished_at - started_at):.3f}",
        "produced_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(finished_at))),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(started_at))),
        "started_at_epoch": _canonical_epoch(started_at),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(finished_at))),
        "finished_at_epoch": _canonical_epoch(finished_at),
        "probes": probes,
    }
def _required_sha256(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("provenance digest must be a lowercase 64-hex SHA-256")
    return value


def _require_ordered_healthy_probes(report: dict) -> None:
    probes = report.get("probes")
    if not isinstance(probes, list) or len(probes) != 97:
        raise ValueError("CANARY_24H requires exactly 97 probe records")
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict) or probe.get("probe_index") != str(index):
            raise ValueError("CANARY_24H probe records must be ordered from 0 through 96")
        if probe.get("passed") is not True:
            raise ValueError("CANARY_24H requires every probe to be healthy")
def _require_production_canary_contract(
    report: dict, duration_seconds: str, interval_seconds: str
) -> None:
    """Reject every condition that could mint shortened CANARY_24H evidence."""
    if duration_seconds != PRODUCTION_DURATION_SECONDS or report.get("configured_duration_seconds") != PRODUCTION_DURATION_SECONDS:
        raise ValueError("CANARY_24H requires configured_duration_seconds='86400'")
    if interval_seconds != PRODUCTION_INTERVAL_SECONDS or report.get("interval_seconds") != PRODUCTION_INTERVAL_SECONDS:
        raise ValueError("CANARY_24H requires interval_seconds='900'")
    try:
        observed_duration = Decimal(report["observed_duration_seconds"])
    except (KeyError, InvalidOperation) as exc:
        raise ValueError("CANARY_24H report has invalid observed_duration_seconds") from exc
    if not observed_duration.is_finite() or observed_duration < Decimal(PRODUCTION_DURATION_SECONDS):
        raise ValueError("CANARY_24H observed duration is shorter than 86400 seconds")
    if report.get("failure_count") != "0" or report.get("healthy") is not True:
        raise ValueError("CANARY_24H requires failure_count='0' and healthy=true")
    if report.get("probe_count") != "97":
        raise ValueError("CANARY_24H requires exactly 97 probes")
    _require_ordered_healthy_probes(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", required=True)
    parser.add_argument("--interval-seconds", required=True)
    parser.add_argument("--output-dir", required=True, help="directory to write rollout-evidence.json")
    parser.add_argument("--bundle-output-dir")
    parser.add_argument("--durable-state-root", required=True)
    parser.add_argument("--interrupt-after-probe", type=int)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--workflow-run-id", required=True)
    parser.add_argument("--workflow-run-attempt", required=True)
    parser.add_argument("--implementation-commit", required=True)
    parser.add_argument("--source-run-url", required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--contract-digest", required=True)
    parser.add_argument("--toolchain-lock-digest", required=True)
    parser.add_argument("--workflow-file-digest", required=True)
    args = parser.parse_args(argv)
    try:
        for name in ("repository", "workflow_run_id", "workflow_run_attempt", "implementation_commit", "source_run_url", "platform"):
            if not getattr(args, name):
                raise ValueError(f"{name} is required")
        for name in ("contract_digest", "toolchain_lock_digest", "workflow_file_digest"):
            _required_sha256(getattr(args, name))
        duration_seconds = int(args.duration_seconds)
        interval_seconds = int(args.interval_seconds)
        if duration_seconds < 0 or interval_seconds <= 0:
            raise ValueError("duration and interval must be positive production values")
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT, capture_output=True, text=True
        )
        producer_commit = proc.stdout.strip() if proc.returncode == 0 else ""
        if not re.fullmatch(r"[0-9a-f]{40}", producer_commit):
            raise ValueError("checked-out implementation commit must be a 40-hex Git object ID")
        if args.implementation_commit != producer_commit:
            raise ValueError("workflow input, detached HEAD, and envelope commit must be identical")
    except ValueError as exc:
        parser.error(str(exc))

    binding = _checkpoint_binding(
        repository=args.repository,
        workflow_run_id=args.workflow_run_id,
        implementation_commit=producer_commit,
        workflow_file_digest=args.workflow_file_digest,
        contract_digest=args.contract_digest,
        toolchain_lock_digest=args.toolchain_lock_digest,
    )
    report = run_canary(
        duration_seconds,
        interval_seconds,
        durable_state_root=Path(args.durable_state_root),
        checkpoint_binding=binding,
        interrupt_after_probe=args.interrupt_after_probe,
    )
    report["provenance"] = {
        **binding,
        "original_workflow_run_id": report.get(
            "original_workflow_run_id", binding["original_workflow_run_id"]
        ),
        "current_workflow_run_id": args.workflow_run_id,
        "current_workflow_run_attempt": args.workflow_run_attempt,
        "platform": args.platform,
        "contract_digest": args.contract_digest,
        "toolchain_lock_digest": args.toolchain_lock_digest,
        "workflow_file_digest": args.workflow_file_digest,
        "source_run_url": args.source_run_url,
    }

    if args.bundle_output_dir:
        try:
            _require_production_canary_contract(
                report, args.duration_seconds, args.interval_seconds
            )
        except ValueError as exc:
            print(f"CANARY_24H ISSUANCE REFUSED: {exc}", file=sys.stderr)
            return 1
        report["evidence_lane"] = "CANARY_24H"
    payload_bytes = canonical_bytes(report)

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "rollout-evidence.json").write_bytes(payload_bytes)

    print(
        f"canary probes={report['probe_count']} failures={report['failure_count']} "
        f"healthy={report['healthy']} observed_duration_seconds={report['observed_duration_seconds']}"
    )

    if not report["healthy"]:
        print("CANARY UNHEALTHY: one or more probes failed", file=sys.stderr)
        return 1

    if args.bundle_output_dir:
        import tempfile as _tf

        from build_encrypted_lifecycle_bundle import (
            ENVELOPE_ENTRY_PATH,
            MANIFEST_ENTRY_PATH,
            build_bundle,
            write_deterministic_tar,
        )

        with _tf.TemporaryDirectory() as tmp:
            payload_dir = Path(tmp)
            payload_path = payload_dir / "payload" / "rollout-evidence.json"
            payload_path.parent.mkdir()
            payload_path.write_bytes(payload_bytes)
            built = build_bundle(
                input_dir=payload_dir,
                payload_names=["payload/rollout-evidence.json"],
                artifact_kind="CANARY_24H",
                repository=args.repository,
                producer_commit=producer_commit,
                contract_digest=args.contract_digest,
                toolchain_lock_digest=args.toolchain_lock_digest,
                workflow_file_digest=args.workflow_file_digest,
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                platform_token=args.platform,
                produced_at=report["finished_at"],
            )
            out = Path(args.bundle_output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
            (out / MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])
            (out / "canary-expected-tuple.json").write_text(
                json.dumps(
                    {
                        "repository": built["envelope"]["repository"],
                        "artifact_kind": built["envelope"]["artifact_kind"],
                        "platform": built["envelope"]["platform"],
                        "producer_commit": built["envelope"]["producer_commit"],
                        "contract_digest": built["envelope"]["contract_digest"],
                        "toolchain_lock_digest": built["envelope"]["toolchain_lock_digest"],
                        "workflow_file_digest": built["envelope"]["workflow_file_digest"],
                        "workflow_run_id": built["envelope"]["workflow_run_id"],
                        "workflow_run_attempt": built["envelope"]["workflow_run_attempt"],
                        "artifact_name": built["envelope"]["artifact_name"],
                        "bundle_sha256": built["envelope"]["bundle_sha256"],
                        "payload_paths": built["envelope"]["payload_paths"],
                        "payload_sha256": built["envelope"]["payload_sha256"],
                        "source_run_url": args.source_run_url,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ) + "\n",
                encoding="utf-8",
            )
            tar_files = [
                (ENVELOPE_ENTRY_PATH, built["envelope_bytes"]),
                (MANIFEST_ENTRY_PATH, built["manifest_bytes"]),
                *built["payload_bytes"].items(),
            ]
            tar_path = out / f"{built['artifact_name']}.tar"
            write_deterministic_tar(tar_path, tar_files)
            print(f"built canary bundle {tar_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
