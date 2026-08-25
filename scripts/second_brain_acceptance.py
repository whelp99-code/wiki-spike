#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv, no pip install needed):
#      uv run python scripts/second_brain_acceptance.py local --workspace-root "$tmp/workspace" --fixture-root tests/fixtures/second-brain/acceptance --evidence-out .omo/evidence/wiki-spike-complete-second-brain/task-53/local-acceptance.json --expect-mode LOCAL --mcp-protocol 2026-07-28 --mcp-protocol 2025-11-25
# 3. Or make executable and run:
#      chmod +x scripts/second_brain_acceptance.py && ./scripts/second_brain_acceptance.py
# ──────────────────

"""Build, install, and exercise the LOCAL second-brain product. No certified claims."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Protocol, assert_never

type JsonValue = str | int | bool | None | list[JsonValue] | dict[str, JsonValue]
JOURNEY: Final = ("init", "remember", "inbox", "review", "recall", "forget")
RECEIPT_SCHEMA: Final = "second-brain-local-acceptance/v1"
REF_RE: Final = re.compile(r"^(owner|workspace):[0-9a-f]{64}$")
MCP_ALLOWED: Final = frozenset({"2026-07-28", "2025-11-25"})
DEVSPACE: Final = Path("/Volumes/DevSpace")
KEYCHAIN: Final = Path.home() / "Library/Keychains"


@dataclass(frozen=True, slots=True)
class AcceptanceError(Exception):
    detail: str
    def __str__(self) -> str: return self.detail


@dataclass(frozen=True, slots=True)
class LocalRun:
    workspace_root: Path; fixture_root: Path; evidence_out: Path
    expect_mode: str; mcp_protocols: tuple[str, ...]; kind: str = "local"


@dataclass(frozen=True, slots=True)
class CertifiedRun:
    workspace_root: Path; resolution: str; route_receipt: str
    retention_certificate: str; deletion_receipt: str; evidence_out: Path
    kind: str = "certified"


@dataclass(frozen=True, slots=True)
class PreparedRoots: workspace: Path; recovery: Path


@dataclass(frozen=True, slots=True)
class InstalledProduct: wiki: Path; mcp: Path; venv: Path


@dataclass(frozen=True, slots=True)
class Session: workspace: Path; recovery: Path; owner: str; workspace_ref: str; fixture: Path


@dataclass(frozen=True, slots=True)
class CleanupReport: keychain: bool; workspaces: bool; venvs: bool


class Execute(Protocol):
    def install(self, repo: Path) -> InstalledProduct: ...
    def run_cli(self, product: InstalledProduct, session: Session) -> tuple[str, ...]: ...
    def run_mcp(self, product: InstalledProduct, session: Session, protocol: str) -> tuple[str, ...]: ...
    def cleanup(self, product: InstalledProduct, sessions: tuple[Session, ...]) -> CleanupReport: ...


def opaque_ref(kind: str) -> str:
    if kind not in {"owner", "workspace"}: raise AcceptanceError("ref kind is closed")
    return f"{kind}:{secrets.token_hex(32)}"


def remove_tree(path: Path) -> None:
    if path.exists(): shutil.rmtree(path)


def _private(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True, exist_ok=True); os.chmod(path, 0o700)
    if stat.S_IMODE(os.lstat(path).st_mode) != 0o700: raise AcceptanceError("directory mode must be 0700")
    return path


def prepare_roots(workspace_root: Path) -> PreparedRoots:
    workspace, recovery = _private(workspace_root.resolve(strict=False)), _private(DEVSPACE / "orca/tmp/second-brain-acceptance" / secrets.token_hex(8))
    if os.stat(recovery).st_dev == os.stat(KEYCHAIN).st_dev: raise AcceptanceError("recovery must use a different device from Keychain")
    return PreparedRoots(workspace, recovery)


def parse_argv(argv: list[str]) -> LocalRun | CertifiedRun:
    parser = argparse.ArgumentParser(prog="second_brain_acceptance")
    sub = parser.add_subparsers(dest="kind", required=True)
    local, certified = sub.add_parser("local"), sub.add_parser("certified")
    for flag in ("--workspace-root", "--fixture-root", "--evidence-out"): local.add_argument(flag, type=Path, required=True)
    local.add_argument("--expect-mode", required=True); local.add_argument("--mcp-protocol", action="append", default=[])
    certified.add_argument("--workspace-root", type=Path, required=True); certified.add_argument("--evidence-out", type=Path, required=True)
    for flag in ("--resolution", "--route-receipt", "--retention-certificate", "--deletion-receipt"): certified.add_argument(flag, required=True)
    args = parser.parse_args(argv)
    if args.kind == "certified":
        return CertifiedRun(args.workspace_root, args.resolution, args.route_receipt, args.retention_certificate, args.deletion_receipt, args.evidence_out)
    if args.kind != "local":
        raise AcceptanceError("unsupported acceptance command")
    protocols = tuple(args.mcp_protocol)
    if args.expect_mode != "LOCAL" or not protocols or set(protocols) - MCP_ALLOWED:
        raise AcceptanceError("local acceptance requires --expect-mode LOCAL and known MCP protocols")
    return LocalRun(args.workspace_root, args.fixture_root, args.evidence_out, args.expect_mode, protocols)


def write_receipt(out: Path, *, cli: tuple[str, ...], mcp: Mapping[str, tuple[str, ...]], bins: tuple[str, ...], cleanup: CleanupReport | None = None) -> dict[str, JsonValue]:
    surfaces: dict[str, JsonValue] = {"cli": {"steps": list(cli), "ok": tuple(cli) == JOURNEY}}
    for protocol, steps in mcp.items(): surfaces[f"mcp:{protocol}"] = {"steps": list(steps), "ok": tuple(steps) == JOURNEY}
    report = cleanup or CleanupReport(True, True, True)
    payload: dict[str, JsonValue] = {
        "schema": RECEIPT_SCHEMA, "ok": all(isinstance(item, dict) and item["ok"] is True for item in surfaces.values()),
        "expect_mode": "LOCAL", "mode": "LOCAL", "governance": "UNCERTIFIED", "wheel_installed": True,
        "bins": list(bins), "mcp_protocols": list(mcp), "surfaces": surfaces, "certified_claims": False,
        "cleanup": {"keychain": report.keychain, "workspaces": report.workspaces, "venvs": report.venvs},
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _run(command: list[str], *, cwd: Path | None = None, stdin: bytes = b"") -> subprocess.CompletedProcess[bytes]:
    env = os.environ.copy(); env.pop("PYTHONPATH", None)
    return subprocess.run(command, cwd=cwd, input=stdin, capture_output=True, check=False, env=env)


def _scrub_keychain(workspace: Path) -> bool:
    states = tuple((workspace / "local").glob("*/workspace-state.json"))
    if not states: return True
    state = json.loads(states[0].read_text(encoding="utf-8"))
    workspace_id, digest = str(state["workspace_id"]), str(state["authority_digest"])
    key, root = hashlib.sha256(workspace_id.encode()).hexdigest(), hashlib.sha256(f"{workspace_id}\0{digest}".encode()).hexdigest()
    prefix = f"wiki-spike.second-brain.local.{key}"
    pairs = [(f"{prefix}.key_index.owner-broker", f"{root}.owner"), (f"{prefix}.key_index.owner-broker", f"{root}.device"), (f"{prefix}.key_index.runtime", f"{root}.identity"), (f"{prefix}.key_index.runtime", f"{root}.signing")]
    pairs.extend((f"{prefix}.key_index.ark", index.stem) for index in (workspace / "local").glob("*/key-index/**/*.json"))
    for service, account in pairs: _run(["/usr/bin/security", "delete-generic-password", "-a", account, "-s", service])
    return True


def _wiki(product: InstalledProduct, session: Session, command: list[str], stdin: bytes = b"") -> dict[str, JsonValue]:
    result = _run([str(product.wiki), "--root", str(session.workspace), "--mode", "local", "--recovery-root", str(session.recovery), "--owner-ref", session.owner, *command], stdin=stdin)
    if result.returncode != 0: raise AcceptanceError(f"wiki {command[0]} exited {result.returncode}")
    payload = json.loads(result.stdout.decode())
    if not isinstance(payload, dict): raise AcceptanceError("wiki outcome is not an object")
    return payload


def _first_item(payload: dict[str, JsonValue], label: str) -> dict[str, JsonValue]:
    data = payload.get("data"); items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items or not isinstance(items[0], dict): raise AcceptanceError(f"{label} empty")
    return items[0]


def _revision_of(payload: dict[str, JsonValue], fallback: JsonValue) -> str:
    data = payload.get("data"); results = data.get("results") if isinstance(data, dict) else None
    if isinstance(results, list) and results and isinstance(results[0], dict): return str(results[0]["revision_ref"])
    return str(fallback)


def _cli_journey(product: InstalledProduct, session: Session) -> tuple[str, ...]:
    remember, query = (session.fixture / "remember.md").read_bytes(), (session.fixture / "recall.txt").read_bytes()
    if _wiki(product, session, ["init", "--bootstrap-owner-ref", session.owner, "--workspace-ref", session.workspace_ref]).get("code") != "CREATED": raise AcceptanceError("cli init failed")
    if _wiki(product, session, ["remember", "--content-type", "markdown", "--idempotency-ref", "idem:" + secrets.token_hex(24)], remember).get("code") != "PENDING_REVIEW": raise AcceptanceError("cli remember failed")
    item = _first_item(_wiki(product, session, ["inbox", "--limit", "20"]), "cli inbox")
    if _wiki(product, session, ["approve", "--candidate", str(item["candidate_ref"]), "--expected-revision", str(item["revision_ref"]), "--expected-cut", "1"]).get("code") != "COMMITTED": raise AcceptanceError("cli review failed")
    recalled = _wiki(product, session, ["recall", "--as-of-cut", "2"], query)
    if recalled.get("ok") is not True: raise AcceptanceError("cli recall failed")
    if _wiki(product, session, ["forget", "--candidate", str(item["candidate_ref"]), "--expected-revision", _revision_of(recalled, item["revision_ref"]), "--expected-cut", "2"]).get("code") != "COMMITTED": raise AcceptanceError("cli forget failed")
    status = _wiki(product, session, ["status", "--detail", "summary"]); mode = status.get("data")
    if not isinstance(mode, dict) or mode.get("mode") != "LOCAL": raise AcceptanceError("status is not LOCAL / UNCERTIFIED")
    return JOURNEY


async def _mcp_journey(product: InstalledProduct, session: Session, protocol: str) -> tuple[str, ...]:
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client
    params = StdioServerParameters(command=str(product.mcp), args=["--root", str(session.workspace), "--mode", "local", "--owner-ref", session.owner, "--recovery-root", str(session.recovery)])
    remember, query = (session.fixture / "remember.md").read_text(encoding="utf-8"), (session.fixture / "recall.txt").read_text(encoding="utf-8")
    async with stdio_client(params) as streams, ClientSession(streams[0], streams[1]) as client:
        match protocol:  # noqa: MATCH_OK
            case "2026-07-28": negotiated = (await client.discover()).supported_versions[-1]
            case "2025-11-25": negotiated = (await client.initialize()).protocol_version
            case _: raise AcceptanceError("mcp protocol mismatch")
        if negotiated != protocol: raise AcceptanceError("mcp protocol mismatch")
        async def tool(name: str, arguments: dict[str, str]) -> dict[str, JsonValue]:
            import mcp_types as mcp_types
            result = await client.call_tool(name, arguments)
            block = result.content[0]
            if result.is_error or not isinstance(block, mcp_types.TextContent): raise AcceptanceError(f"{name} failed")
            payload = json.loads(block.text)
            if not isinstance(payload, dict): raise AcceptanceError(f"{name} failed")
            return payload
        if (await tool("second_brain.init", {"bootstrap_owner_ref": session.owner, "workspace_ref": session.workspace_ref})).get("code") != "CREATED": raise AcceptanceError("mcp init failed")
        if (await tool("second_brain.remember", {"content": remember, "content_type": "markdown", "idempotency_ref": "idem:" + secrets.token_hex(24)})).get("code") != "PENDING_REVIEW": raise AcceptanceError("mcp remember failed")
        item = _first_item(await tool("second_brain.inbox", {}), "mcp inbox")
        if (await tool("second_brain.review", {"decision": "APPROVE", "candidate_ref": str(item["candidate_ref"]), "expected_revision_ref": str(item["revision_ref"]), "expected_transaction_cut": "1"})).get("code") != "COMMITTED": raise AcceptanceError("mcp review failed")
        recalled = await tool("second_brain.recall", {"query": query, "as_of_cut": "2"})
        if recalled.get("ok") is not True: raise AcceptanceError("mcp recall failed")
        if (await tool("second_brain.forget", {"candidate_ref": str(item["candidate_ref"]), "expected_revision_ref": _revision_of(recalled, item["revision_ref"]), "expected_transaction_cut": "2"})).get("code") != "COMMITTED": raise AcceptanceError("mcp forget failed")
    return JOURNEY


class LiveExecute:
    def install(self, repo: Path) -> InstalledProduct:
        staging = Path(tempfile.mkdtemp(prefix="sb-accept-")); dist = staging / "dist"; dist.mkdir()
        built = _run(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=repo); wheels = sorted(dist.glob("*.whl"))
        if built.returncode != 0 or len(wheels) != 1: raise AcceptanceError("wheel build failed")
        venv = staging / "venv"
        if _run(["uv", "venv", str(venv)], cwd=repo).returncode != 0: raise AcceptanceError("venv create failed")
        installed = _run(["uv", "pip", "install", "--python", str(venv / "bin" / "python"), str(wheels[0])], cwd=repo)
        wiki, mcp = venv / "bin" / "wiki", venv / "bin" / "wiki-mcp"
        if installed.returncode != 0 or not wiki.is_file() or not mcp.is_file(): raise AcceptanceError("wheel install did not produce wiki and wiki-mcp")
        return InstalledProduct(wiki, mcp, staging)

    def run_cli(self, product: InstalledProduct, session: Session) -> tuple[str, ...]: return _cli_journey(product, session)
    def run_mcp(self, product: InstalledProduct, session: Session, protocol: str) -> tuple[str, ...]:
        import anyio
        return anyio.run(_mcp_journey, product, session, protocol)

    def cleanup(self, product: InstalledProduct, sessions: tuple[Session, ...]) -> CleanupReport:
        keychain = all(_scrub_keychain(session.workspace) for session in sessions) if sessions else True
        for session in sessions: remove_tree(session.workspace); remove_tree(session.recovery)
        remove_tree(product.venv); return CleanupReport(keychain, True, True)


def run_local(request: LocalRun, *, execute: Execute | None = None) -> int:
    if request.expect_mode != "LOCAL": raise AcceptanceError("expect-mode must be LOCAL")
    actor: Execute = execute or LiveExecute(); repo = Path(__file__).resolve().parents[1]
    roots = prepare_roots(request.workspace_root); product: InstalledProduct | None = None
    sessions: list[Session] = []; cleaned = False
    try:
        product = actor.install(repo)
        cli = Session(_private(roots.workspace / "cli"), _private(roots.recovery / "cli"), opaque_ref("owner"), opaque_ref("workspace"), request.fixture_root)
        sessions.append(cli); cli_steps = actor.run_cli(product, cli); mcp_steps: dict[str, tuple[str, ...]] = {}
        for protocol in request.mcp_protocols:
            session = Session(_private(roots.workspace / f"mcp-{protocol}"), _private(roots.recovery / f"mcp-{protocol}"), opaque_ref("owner"), opaque_ref("workspace"), request.fixture_root)
            sessions.append(session); mcp_steps[protocol] = actor.run_mcp(product, session, protocol)
        report = actor.cleanup(product, tuple(sessions)); cleaned = True
        write_receipt(request.evidence_out, cli=cli_steps, mcp=mcp_steps, bins=("wiki", "wiki-mcp"), cleanup=report)
        return 0
    finally:
        if product is not None and not cleaned: actor.cleanup(product, tuple(sessions))
        remove_tree(roots.recovery)


def main(argv: list[str] | None = None) -> int:
    try:
        parsed = parse_argv(sys.argv[1:] if argv is None else argv)
        match parsed:
            case LocalRun(): return run_local(parsed)
            case CertifiedRun(): return 2
            case unreachable: assert_never(unreachable)
    except AcceptanceError as exc:
        print(str(exc), file=sys.stderr); return 1
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2


if __name__ == "__main__":
    raise SystemExit(main())
