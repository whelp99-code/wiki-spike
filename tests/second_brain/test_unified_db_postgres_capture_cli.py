"""Public inspect/verify/plan CLI for body-free capture contracts."""
from __future__ import annotations

import ast
import datetime
import os
import subprocess
import sys
from pathlib import Path

from tests.second_brain.unified_db_postgres_capture_support import (
    SCRIPT,
    bound_identity_body,
    capture_plan_body,
    catalog_body,
)
from wiki_spike.applications.unified_db_postgres_capture_verify import (
    CapturePlanRequestV1,
    plan_postgres_identity_capture,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object


def _run(args: list[str], *, pass_fds: tuple[int, ...] = ()) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        check=False,
        pass_fds=pass_fds,
    )


def _write_bundle(tmp_path: Path, *, fresh: bool = True) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    manifest = PostgresCaptureQueryManifestV1.closed().to_mapping()
    catalog = catalog_body()
    if fresh:
        current = datetime.datetime.now(datetime.UTC).replace(microsecond=0)
        captured_at = current.isoformat().replace("+00:00", "Z")
        identity = bound_identity_body(captured_at=captured_at)
        plan = plan_postgres_identity_capture(
            CapturePlanRequestV1(
                PostgresCaptureQueryManifestV1.from_mapping(manifest),
                PostgresIdentityReceiptV1.from_mapping(identity),
                PostgresCatalogSnapshotV1.from_mapping(catalog),
            ),
            datetime.datetime.now(datetime.UTC),
        ).to_mapping()
    else:
        identity = bound_identity_body()
        plan = capture_plan_body(str(manifest["manifest_digest"]), identity, catalog)
    payloads = {
        "query-manifest": manifest,
        "catalog": catalog,
        "identity": identity,
        "plan": plan,
    }
    paths: dict[str, Path] = {}
    for name, payload in payloads.items():
        path = tmp_path / f"{name}.json"
        _ = path.write_bytes(canonical_bytes(payload) + b"\n")
        paths[name] = path
    return paths


def test_help_lists_capture_inspect_verify_plan_without_dsn() -> None:
    completed = _run(["--help"])
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout.decode("utf-8")
    assert "capture-inspect" in text
    assert "capture-verify" in text
    assert "capture-plan" in text
    for command in ("capture-inspect", "capture-verify", "capture-plan"):
        shown = _run([command, "--help"])
        assert shown.returncode == 0, shown.stderr
        assert b"--dsn-fd" not in shown.stdout
        assert b"--dsn" not in shown.stdout
        assert b"--key" not in shown.stdout


def test_capture_inspect_verify_and_plan_accept_synthetic_fixtures(
    tmp_path: Path,
) -> None:
    paths = _write_bundle(tmp_path)
    inspected = _run(
        ["capture-inspect", "--kind", "identity", "--input", str(paths["identity"])]
    )
    assert inspected.returncode == 0, inspected.stderr
    shown = decode_json_object(inspected.stdout.decode("utf-8"))
    assert shown["identity_version"] == "second-brain-unified-db-postgres-identity-v1"
    assert "body" not in shown
    verified = _run(
        [
            "capture-verify",
            "--plan",
            str(paths["plan"]),
            "--identity",
            str(paths["identity"]),
            "--catalog",
            str(paths["catalog"]),
            "--query-manifest",
            str(paths["query-manifest"]),
        ]
    )
    assert verified.returncode == 0, verified.stderr
    report = decode_json_object(verified.stdout.decode("utf-8"))
    assert report["verified"] is True
    planned = _run(
        [
            "capture-plan",
            "--identity",
            str(paths["identity"]),
            "--catalog",
            str(paths["catalog"]),
            "--query-manifest",
            str(paths["query-manifest"]),
        ]
    )
    assert planned.returncode == 0, planned.stderr
    emitted = decode_json_object(planned.stdout.decode("utf-8"))
    assert emitted["plan_version"] == "second-brain-unified-db-postgres-capture-plan-v1"
    assert emitted["catalog_digest"] == shown["catalog_digest"]


def test_capture_inspect_rejects_malformed_identity(tmp_path: Path) -> None:
    path = tmp_path / "bad-identity.json"
    _ = path.write_bytes(canonical_bytes(bound_identity_body(system_identifier="016")) + b"\n")
    refused = _run(["capture-inspect", "--kind", "identity", "--input", str(path)])
    assert refused.returncode != 0
    assert b"refused" in refused.stderr


def test_capture_verify_rejects_stale_identity(tmp_path: Path) -> None:
    paths = _write_bundle(tmp_path / "stale", fresh=False)
    stale = _run(
        [
            "capture-verify",
            "--plan",
            str(paths["plan"]),
            "--identity",
            str(paths["identity"]),
            "--catalog",
            str(paths["catalog"]),
            "--query-manifest",
            str(paths["query-manifest"]),
        ]
    )
    assert stale.returncode != 0
    assert b"stale" in stale.stderr


def test_production_capture_command_refuses_and_leaves_dsn_unread(
    tmp_path: Path,
) -> None:
    read_fd, write_fd = os.pipe()
    payload = b"postgresql://localhost:5433/unified"
    _ = os.write(write_fd, payload)
    os.close(write_fd)
    dest = tmp_path / "capture-out"
    refused = _run(
        ["capture", "--dsn-fd", str(read_fd), "--output", str(dest)],
        pass_fds=(read_fd,),
    )
    leftover = os.read(read_fd, 64)
    os.close(read_fd)
    assert refused.returncode != 0
    assert b"owner approval required" in refused.stderr
    assert leftover == payload
    assert not dest.exists()


def test_production_capture_returns_refusal_without_fixture_fallthrough() -> None:
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    returned = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not isinstance(test, ast.Compare) or len(test.comparators) != 1:
            continue
        comparator = test.comparators[0]
        if not isinstance(comparator, ast.Constant) or comparator.value != "capture":
            continue
        returns = [item for item in node.body if isinstance(item, ast.Return)]
        assert len(returns) == 1
        value = returns[0].value
        assert isinstance(value, ast.Call)
        func = value.func
        name = func.id if isinstance(func, ast.Name) else ""
        if isinstance(func, ast.Attribute):
            name = func.attr
        assert name == "refuse_postgres_identity_capture"
        returned = True
    assert returned
