"""Task 53 local-product acceptance driver, receipt, and documented commands."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import assert_never

from scripts import second_brain_acceptance as accept

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/second-brain/acceptance"
DOCS = ROOT / "docs/ops/second-brain-local.md"
README = ROOT / "README.md"
EVIDENCE = ".omo/evidence/wiki-spike-complete-second-brain/task-53/local-acceptance.json"
TASK53 = [
    "local",
    "--workspace-root",
    "/tmp/workspace",
    "--fixture-root",
    "tests/fixtures/second-brain/acceptance",
    "--evidence-out",
    EVIDENCE,
    "--expect-mode",
    "LOCAL",
    "--mcp-protocol",
    "2026-07-28",
    "--mcp-protocol",
    "2025-11-25",
]
FORBIDDEN = frozenset({"path", "paths", "query", "label", "body", "native_id", "excerpt"})
CERTIFIED_CLAIMS = ("certified release", "cutover", "decommission", "deletion certificate")


def _walk_keys(node: accept.JsonValue) -> list[str]:
    match node:
        case dict() as mapping:
            keys = list(mapping)
            for value in mapping.values():
                keys.extend(_walk_keys(value))
            return keys
        case list() as items:
            nested: list[str] = []
            for item in items:
                nested.extend(_walk_keys(item))
            return nested
        case str() | int() | bool() | None:
            return []
        case unreachable:
            assert_never(unreachable)


def test_parser_accepts_exact_task_53_local_argv() -> None:
    # Given: the published Task 53 local acceptance argv.
    # When: the driver parses that argv.
    parsed = accept.parse_argv(TASK53)
    # Then: the local surface, fixture, receipt, mode, and both MCP revisions bind.
    assert isinstance(parsed, accept.LocalRun)
    assert parsed.expect_mode == "LOCAL"
    assert parsed.mcp_protocols == ("2026-07-28", "2025-11-25")
    assert parsed.evidence_out.as_posix().endswith("task-53/local-acceptance.json")


def test_owner_and_workspace_refs_use_kind_and_64_hex() -> None:
    # Given: the acceptance driver must mint sealed local refs.
    # When: it issues one owner ref and one workspace ref.
    owner = accept.opaque_ref("owner")
    workspace = accept.opaque_ref("workspace")
    # Then: both match owner:<64hex> / workspace:<64hex>.
    assert accept.REF_RE.fullmatch(owner)
    assert accept.REF_RE.fullmatch(workspace)
    assert owner.startswith("owner:")
    assert workspace.startswith("workspace:")


def test_workspace_base_is_0700_and_recovery_uses_devspace_device(tmp_path: Path) -> None:
    # Given: a caller-supplied workspace base on the boot volume.
    workspace = tmp_path / "workspace"
    # When: the driver prepares local roots.
    roots = accept.prepare_roots(workspace)
    # Then: the base is 0700 and recovery is on /Volumes/DevSpace, a different device from Keychain.
    metadata = os.lstat(roots.workspace)
    assert stat.S_IMODE(metadata.st_mode) == 0o700
    keychain = Path.home() / "Library/Keychains"
    assert roots.recovery.is_relative_to(Path("/Volumes/DevSpace"))
    assert os.stat(roots.recovery).st_dev != os.stat(keychain).st_dev
    assert stat.S_IMODE(os.lstat(roots.recovery).st_mode) == 0o700
    accept.remove_tree(roots.recovery)


def test_receipt_records_cli_and_mcp_journeys_without_certified_claims(tmp_path: Path) -> None:
    # Given: successful CLI and dual-revision MCP journeys.
    out = tmp_path / "local-acceptance.json"
    # When: the driver writes the fixed local receipt.
    payload = accept.write_receipt(
        out,
        cli=accept.JOURNEY,
        mcp={"2026-07-28": accept.JOURNEY, "2025-11-25": accept.JOURNEY},
        bins=("wiki", "wiki-mcp"),
    )
    # Then: both surfaces record init→remember→inbox→review→recall→forget and stay body-free.
    text = out.read_text(encoding="utf-8")
    loaded = json.loads(text)
    surfaces = loaded["surfaces"]
    assert payload["ok"] is True
    assert payload["schema"] == accept.RECEIPT_SCHEMA
    assert payload["expect_mode"] == "LOCAL"
    assert payload["governance"] == "UNCERTIFIED"
    assert surfaces["cli"]["steps"] == list(accept.JOURNEY)
    assert surfaces["mcp:2026-07-28"]["ok"] is True
    assert surfaces["mcp:2025-11-25"]["steps"] == list(accept.JOURNEY)
    assert payload["certified_claims"] is False
    assert FORBIDDEN.isdisjoint(_walk_keys(payload))
    lowered = text.lower()
    assert all(claim not in lowered for claim in CERTIFIED_CLAIMS)


def test_certified_subcommand_fails_closed_without_release_claim(tmp_path: Path) -> None:
    # Given: the shared driver also exposes the later certified subcommand.
    out = tmp_path / "certified-acceptance.json"
    argv = [
        "certified",
        "--workspace-root",
        str(tmp_path / "certified"),
        "--resolution",
        "resolution",
        "--route-receipt",
        "route",
        "--retention-certificate",
        "retention",
        "--deletion-receipt",
        "deletion",
        "--evidence-out",
        str(out),
    ]
    # When: Task 53 invokes certified without protected receipts.
    code = accept.main(argv)
    # Then: the process fails closed and writes no certified success claim.
    assert code == 2
    assert not out.exists()


def test_fake_execute_cleans_keychain_workspaces_and_venvs(tmp_path: Path) -> None:
    # Given: a recording execute seam that created disposable custody.
    deleted: list[str] = []

    class Fake:
        def install(self, repo: Path) -> accept.InstalledProduct:
            venv = tmp_path / "venv"
            venv.mkdir()
            (venv / "wiki").write_text("", encoding="utf-8")
            (venv / "wiki-mcp").write_text("", encoding="utf-8")
            return accept.InstalledProduct(venv / "wiki", venv / "wiki-mcp", venv)

        def run_cli(self, product: accept.InstalledProduct, session: accept.Session) -> tuple[str, ...]:
            del product, session
            return accept.JOURNEY

        def run_mcp(
            self, product: accept.InstalledProduct, session: accept.Session, protocol: str
        ) -> tuple[str, ...]:
            del product, session, protocol
            return accept.JOURNEY

        def cleanup(
            self, product: accept.InstalledProduct, sessions: tuple[accept.Session, ...]
        ) -> accept.CleanupReport:
            deleted.extend(["keychain", "workspaces", "venvs"])
            accept.remove_tree(product.venv)
            for session in sessions:
                accept.remove_tree(session.workspace)
                accept.remove_tree(session.recovery)
            return accept.CleanupReport(True, True, True)

    request = accept.LocalRun(
        tmp_path / "workspace",
        FIXTURE,
        tmp_path / "local-acceptance.json",
        "LOCAL",
        ("2026-07-28", "2025-11-25"),
    )
    # When: the local driver runs through the fake seam.
    code = accept.run_local(request, execute=Fake())
    # Then: it passes and cleanup covered Keychain, workspaces, and venvs.
    assert code == 0
    assert deleted == ["keychain", "workspaces", "venvs"]
    assert not (tmp_path / "venv").exists()
    payload = json.loads((tmp_path / "local-acceptance.json").read_text(encoding="utf-8"))
    assert payload["cleanup"] == {"keychain": True, "workspaces": True, "venvs": True}


def test_docs_and_readme_publish_verified_local_operations_only() -> None:
    # Given: the local operations page and README after Task 53.
    docs = DOCS.read_text(encoding="utf-8")
    readme = README.read_text(encoding="utf-8")
    fixture = json.loads((FIXTURE / "journey.json").read_text(encoding="utf-8"))
    # When: a reader looks for the documented local product surface.
    # Then: documented commands stay LOCAL / UNCERTIFIED and never certify release work.
    assert "LOCAL / UNCERTIFIED" in docs
    assert "bin/wiki" in docs and "bin/wiki-mcp" in docs
    assert "2026-07-28" in docs and "2025-11-25" in docs
    assert fixture["steps"] == list(accept.JOURNEY)
    assert "LOCAL / UNCERTIFIED" in readme
    assert "docs/ops/second-brain-local.md" in readme
    blob = f"{docs}\n{readme}".lower()
    assert all(claim not in blob for claim in CERTIFIED_CLAIMS)
