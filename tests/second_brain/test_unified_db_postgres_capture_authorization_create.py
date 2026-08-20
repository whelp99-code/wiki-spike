"""CLI tests for public capture-authority-create unsigned bodies."""
from __future__ import annotations

import re
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

from tests.second_brain.unified_db_postgres_capture_authorization_support import SCRIPT
from wiki_spike.memory_core.unified_db_export_authorization import parse_utc
from wiki_spike.memory_core.unified_db_postgres_capture_authorization import (
    AUTHORIZATION_KIND,
    AUTHORIZATION_VERSION,
    CLOSED_QUERY_MANIFEST_DIGEST,
    MAX_CAPTURE_WINDOW,
    UnifiedDbMetadataCaptureOnlyAuthorizationV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_destination import (
    PostgresMetadataCaptureDestinationV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_FALSE_FLAGS = (
    "application_row_allowed",
    "source_body_read_allowed",
    "mutation_allowed",
    "export_allowed",
    "import_allowed",
    "register_allowed",
    "cohort_allowed",
    "serve_allowed",
    "promote_allowed",
    "cutover_allowed",
)
_DEFAULT_BODY = Path(
    "artifacts/product-release/second-brain-v1/capture-authority-signing/POSTGRES_METADATA_CAPTURE_ONLY.body.json"
)
_SCRIPT = SCRIPT.resolve()


def _run(
    args: list[str], *, cwd: Path | None = None
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), *args],
        capture_output=True,
        check=False,
        cwd=cwd,
    )


def _create(destination: Path, out: Path) -> list[str]:
    return [
        "capture-authority-create",
        "--destination",
        str(destination),
        "--out",
        str(out),
    ]


def test_create_help_lists_destination_without_private_key_flags() -> None:
    completed = _run(["capture-authority-create", "--help"])
    assert completed.returncode == 0, completed.stderr
    text = completed.stdout.decode("utf-8")
    assert "--destination" in text
    assert "--out" in text
    for banned in ("--key ", "--key-fd", "--private-key", "--import", "--serve"):
        assert banned not in text


def test_create_writes_unsigned_body_when_destination_is_create_only(
    tmp_path: Path,
) -> None:
    destination = tmp_path / "capture-out"
    out = tmp_path / "POSTGRES_METADATA_CAPTURE_ONLY.body.json"
    completed = _run(_create(destination, out))
    assert completed.returncode == 0, completed.stderr
    parsed = decode_json_object(out.read_text(encoding="utf-8"))
    body = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(parsed)
    assert body.authorization_version == AUTHORIZATION_VERSION
    assert body.authorization_kind == AUTHORIZATION_KIND
    assert body.source_name == "unified-db"
    assert body.operation == "METADATA_CAPTURE_ONLY"
    assert body.query_manifest_digest == CLOSED_QUERY_MANIFEST_DIGEST
    assert body.max_captures == "1"
    assert _HEX64.fullmatch(body.nonce)
    assert _HEX64.fullmatch(body.capture_plan_digest)
    assert _HEX64.fullmatch(body.output_digest)
    assert body.destination.destination_path == str(destination)
    assert body.destination.destination_digest == body.destination.computed_digest()
    assert body.authorization_digest == body.computed_digest()
    for flag in _FALSE_FLAGS:
        assert getattr(body, flag) is False
    issued = parse_utc(body.issued_at, "issued_at")
    not_before = parse_utc(body.not_before, "not_before")
    expires = parse_utc(body.expires_at, "expires_at")
    assert issued == not_before
    assert expires - issued == MAX_CAPTURE_WINDOW
    assert expires - issued == timedelta(minutes=15)
    rebuilt = PostgresMetadataCaptureDestinationV1.from_mapping(
        body.destination.to_mapping()
    )
    assert rebuilt.destination_digest == body.destination.destination_digest


def test_create_emits_fresh_nonce_when_invoked_twice(tmp_path: Path) -> None:
    destination_a = tmp_path / "capture-a"
    destination_b = tmp_path / "capture-b"
    out_a = tmp_path / "a.body.json"
    out_b = tmp_path / "b.body.json"
    first = _run(_create(destination_a, out_a))
    second = _run(_create(destination_b, out_b))
    assert first.returncode == 0, first.stderr
    assert second.returncode == 0, second.stderr
    nonce_a = decode_json_object(out_a.read_text(encoding="utf-8"))["nonce"]
    nonce_b = decode_json_object(out_b.read_text(encoding="utf-8"))["nonce"]
    assert isinstance(nonce_a, str) and isinstance(nonce_b, str)
    assert _HEX64.fullmatch(nonce_a)
    assert _HEX64.fullmatch(nonce_b)
    assert nonce_a != nonce_b


def test_create_defaults_out_to_runner_body_path(tmp_path: Path) -> None:
    destination = tmp_path / "capture-out"
    parent = tmp_path / _DEFAULT_BODY.parent
    parent.mkdir(parents=True)
    completed = _run(
        ["capture-authority-create", "--destination", str(destination)],
        cwd=tmp_path,
    )
    assert completed.returncode == 0, completed.stderr
    written = tmp_path / _DEFAULT_BODY
    parsed = decode_json_object(written.read_text(encoding="utf-8"))
    body = UnifiedDbMetadataCaptureOnlyAuthorizationV1.from_mapping(parsed)
    assert body.destination.destination_path == str(destination)


def test_create_refuses_when_destination_is_relative(tmp_path: Path) -> None:
    out = tmp_path / "body.json"
    completed = _run(
        [
            "capture-authority-create",
            "--destination",
            "captured/out",
            "--out",
            str(out),
        ]
    )
    assert completed.returncode != 0
    assert b"absolute" in completed.stderr
    assert not out.exists()


def test_create_refuses_when_destination_already_exists(tmp_path: Path) -> None:
    destination = tmp_path / "capture-out"
    destination.mkdir()
    out = tmp_path / "body.json"
    completed = _run(_create(destination, out))
    assert completed.returncode != 0
    assert b"exists" in completed.stderr or b"overwrite" in completed.stderr
    assert not out.exists()


def test_create_refuses_when_destination_is_symlink(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.mkdir()
    destination = tmp_path / "link"
    destination.symlink_to(target)
    out = tmp_path / "body.json"
    completed = _run(_create(destination, out))
    assert completed.returncode != 0
    assert b"symlink" in completed.stderr
    assert not out.exists()


def test_create_refuses_when_out_already_exists(tmp_path: Path) -> None:
    destination = tmp_path / "capture-out"
    out = tmp_path / "body.json"
    _ = out.write_text("keep-me", encoding="utf-8")
    completed = _run(_create(destination, out))
    assert completed.returncode != 0
    assert b"exists" in completed.stderr or b"overwrite" in completed.stderr
    assert out.read_text(encoding="utf-8") == "keep-me"


def test_create_refuses_when_extra_fields_are_supplied(tmp_path: Path) -> None:
    destination = tmp_path / "capture-out"
    out = tmp_path / "body.json"
    completed = _run([*_create(destination, out), "--serve", "true"])
    assert completed.returncode != 0
    assert not out.exists()
