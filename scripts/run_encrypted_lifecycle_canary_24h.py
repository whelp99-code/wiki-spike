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
bundle. ``--duration-seconds``/``--interval-seconds`` are parameterised so the
same code runs a short canary in tests and the full 24h canary in production.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

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

DEFAULT_DURATION_SECONDS = 24 * 60 * 60  # exactly 24 hours
DEFAULT_INTERVAL_SECONDS = 15 * 60  # probe every 15 minutes


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


def run_canary(duration_seconds: int, interval_seconds: int) -> dict:
    """Run canary probes for ``duration_seconds``, sleeping ``interval_seconds``
    between probes. Returns the canary report dict."""
    started_at = time.time()
    deadline = started_at + duration_seconds
    probes: list[dict] = []
    probe_index = 0
    while True:
        probes.append(run_probe(probe_index))
        probe_index += 1
        if time.time() >= deadline:
            break
        time.sleep(interval_seconds)

    failures = sum(1 for p in probes if not p["passed"])
    finished_at = time.time()
    return {
        "schema": REPORT_SCHEMA,
        "healthy": failures == 0,
        "probe_count": str(len(probes)),
        "failure_count": str(failures),
        "duration_seconds": f"{finished_at - started_at:.3f}",
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(started_at)),
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(finished_at)),
        "probes": probes,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--duration-seconds", type=int, default=DEFAULT_DURATION_SECONDS)
    parser.add_argument("--interval-seconds", type=int, default=DEFAULT_INTERVAL_SECONDS)
    parser.add_argument("--output-dir", help="directory to write canary-report.json")
    parser.add_argument("--bundle-output-dir", help="also build a CANARY_24H bundle here")
    parser.add_argument("--repository", default="wiki-spike")
    parser.add_argument("--workflow-run-id", default="0")
    parser.add_argument("--workflow-run-attempt", default="1")
    parser.add_argument("--platform", default="self-hosted/macos-15/arm64/wiki-canary-workstation")
    parser.add_argument("--contract-digest", default="")
    parser.add_argument("--toolchain-lock-digest", default="")
    parser.add_argument("--workflow-file-digest", default="")
    args = parser.parse_args(argv)

    report = run_canary(args.duration_seconds, args.interval_seconds)

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "canary-report.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    print(
        f"canary probes={report['probe_count']} failures={report['failure_count']} "
        f"healthy={report['healthy']} duration_seconds={report['duration_seconds']}"
    )

    if not report["healthy"]:
        print("CANARY UNHEALTHY: one or more probes failed", file=sys.stderr)
        return 1

    if args.bundle_output_dir:
        import tempfile as _tf

        sys.path.insert(0, str(_REPO_ROOT / "scripts"))
        from build_encrypted_lifecycle_bundle import (
            ENVELOPE_ENTRY_PATH,
            MANIFEST_ENTRY_PATH,
            build_bundle,
            write_deterministic_tar,
        )

        proc = __import__("subprocess").run(
            ["git", "rev-parse", "HEAD"], cwd=_REPO_ROOT, capture_output=True, text=True
        )
        producer_commit = proc.stdout.strip() if proc.returncode == 0 else ""
        with _tf.TemporaryDirectory() as tmp:
            payload_dir = Path(tmp)
            (payload_dir / "canary-report.json").write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            built = build_bundle(
                input_dir=payload_dir,
                payload_names=["canary-report.json"],
                artifact_kind="CANARY_24H",
                repository=args.repository,
                producer_commit=producer_commit,
                contract_digest=args.contract_digest or ("0" * 64),
                toolchain_lock_digest=args.toolchain_lock_digest or ("0" * 64),
                workflow_file_digest=args.workflow_file_digest or ("0" * 64),
                workflow_run_id=args.workflow_run_id,
                workflow_run_attempt=args.workflow_run_attempt,
                platform_token=args.platform,
                produced_at=report["finished_at"],
            )
            out = Path(args.bundle_output_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / ENVELOPE_ENTRY_PATH).write_bytes(built["envelope_bytes"])
            (out / MANIFEST_ENTRY_PATH).write_bytes(built["manifest_bytes"])
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
