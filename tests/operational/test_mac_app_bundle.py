from __future__ import annotations

import json
import plistlib
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.build_mac_app import APP_NAME, DEFAULT_PYTHON, build_app


pytestmark = pytest.mark.skipif(sys.platform != "darwin", reason="macOS app bundle test")
ROOT = Path(__file__).resolve().parents[2]


def test_mac_app_bundle_is_double_clickable_and_self_checks(tmp_path: Path) -> None:
    app = tmp_path / f"{APP_NAME}.app"
    result = build_app(ROOT, app, python=DEFAULT_PYTHON, verify=True)
    assert result["status"] == "pass"
    assert result["version"] == "0.1.0"
    assert result["ui_smoke"] == "pass"
    assert result["signature"] == "ad-hoc-verified"

    with (app / "Contents" / "Info.plist").open("rb") as handle:
        info = plistlib.load(handle)
    assert info["CFBundleExecutable"] == APP_NAME
    assert info["CFBundlePackageType"] == "APPL"

    resources = app / "Contents" / "Resources"
    manifest = json.loads((resources / "build-manifest.json").read_text("utf-8"))
    assert manifest["network_enabled"] is False
    assert manifest["external_models_enabled"] is False
    assert manifest["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    assert manifest["parallel_memory_database"] is False
    assert manifest["read_only_ai_recall"] is True
    assert int(manifest["product_module_count"]) < 40
    assert (resources / "python/wiki_spike/operational/desktop.py").is_file()
    assert (resources / "python/wiki_spike/composition/local_second_brain.py").is_file()
    assert (resources / "python/wiki_spike/applications/encrypted_lifecycle_pipeline.py").is_file()
    assert (resources / "python/wiki_spike/infrastructure/lifecycle_db.py").is_file()
    assert not (resources / "python/wiki_spike/workspace.py").exists()
    assert not (resources / "python/wiki_spike/controlplane.py").exists()
    assert not (resources / "python/wiki_spike/connectors").exists()
    assert not (resources / "python/wiki_spike/memory_runtime").exists()
    store_source = (resources / "python/wiki_spike/operational/store.py").read_text("utf-8")
    assert "CREATE TABLE" not in store_source
    assert "import sqlite3" not in store_source

    launcher = app / "Contents" / "MacOS" / APP_NAME
    checked = subprocess.run(
        [str(launcher), "--check", "--root", str(tmp_path / "checked-data")],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert checked.returncode == 0, checked.stderr
    checked_payload = json.loads(checked.stdout)
    assert checked_payload["operational_ready"] is True
    assert checked_payload["authority"] == "ENCRYPTED_LIFECYCLE_CORE"
    assert checked_payload["parallel_memory_database"] is False
