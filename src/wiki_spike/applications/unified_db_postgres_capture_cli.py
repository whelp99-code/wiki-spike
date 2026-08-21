"""Public inspect/verify/plan CLI for body-free capture contracts."""
from __future__ import annotations

import argparse
import datetime
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol

from wiki_spike.applications.unified_db_postgres_capture_verify import (
    CapturePlanRequestV1,
    CaptureVerifyRequestV1,
    plan_postgres_identity_capture,
    verify_postgres_capture_plan,
)
from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    read_bounded_path,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.unified_db_postgres_capture_catalog import (
    PostgresCatalogSnapshotV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_plan import (
    PostgresCapturePlanV1,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    PostgresCaptureQueryManifestV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

CAPTURE_CONTRACT_COMMANDS: Final = frozenset(
    {"capture-inspect", "capture-verify", "capture-plan"}
)
CAPTURE_INSPECT_KINDS: Final = ("query-manifest", "catalog", "identity", "plan")


class SubparserRegistrar(Protocol):
    def add_parser(self, name: str, *, help: str = ...) -> argparse.ArgumentParser: ...


class CaptureInspectKind(StrEnum):
    QUERY_MANIFEST = "query-manifest"
    CATALOG = "catalog"
    IDENTITY = "identity"
    PLAN = "plan"


@dataclass(frozen=True, slots=True)
class CaptureCliPaths:
    kind: str
    input_path: Path
    plan: Path
    identity: Path
    catalog: Path
    query_manifest: Path


def is_capture_contract_command(command: str) -> bool:
    return command in CAPTURE_CONTRACT_COMMANDS


def register_capture_parsers(sub: SubparserRegistrar) -> None:
    inspect = sub.add_parser("capture-inspect", help="inspect a body-free capture contract")
    _ = inspect.add_argument("--kind", required=True, choices=CAPTURE_INSPECT_KINDS)
    _ = inspect.add_argument("--input", dest="input_path", required=True, type=Path)
    verify = sub.add_parser("capture-verify", help="verify capture-plan contract bindings")
    plan = sub.add_parser("capture-plan", help="emit a user-reviewable capture plan")
    for command in (verify, plan):
        _ = command.add_argument("--identity", required=True, type=Path)
        _ = command.add_argument("--catalog", required=True, type=Path)
        _ = command.add_argument("--query-manifest", dest="query_manifest", required=True, type=Path)
    _ = verify.add_argument("--plan", required=True, type=Path)
    capture = sub.add_parser("capture", help="production capture (refused without owner approval)")
    _ = capture.add_argument("--dsn-fd", type=int)
    _ = capture.add_argument("--output", type=Path)


def run_capture_contract_command(command: str, paths: CaptureCliPaths) -> int:
    match command:  # noqa: MATCH_OK
        case "capture-inspect":
            return inspect_capture_contract(paths.kind, paths.input_path)
        case "capture-verify":
            return verify_capture_contracts(paths)
        case "capture-plan":
            return emit_capture_plan(paths)
        case _ as unreachable:
            raise UnifiedDbExportError(f"unknown capture contract command: {unreachable}")


def inspect_capture_contract(kind: str, path: Path) -> int:
    parsed = _parse_kind(_inspect_kind(kind), _load(path))
    print(json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def verify_capture_contracts(paths: CaptureCliPaths) -> int:
    verify_postgres_capture_plan(_request(paths), datetime.datetime.now(datetime.UTC))
    print(json.dumps({"verified": True}, indent=2, sort_keys=True))
    return 0


def emit_capture_plan(paths: CaptureCliPaths) -> int:
    planned = plan_postgres_identity_capture(
        CapturePlanRequestV1(
            PostgresCaptureQueryManifestV1.from_mapping(_load(paths.query_manifest)),
            PostgresIdentityReceiptV1.from_mapping(_load(paths.identity)),
            PostgresCatalogSnapshotV1.from_mapping(_load(paths.catalog)),
        ),
        datetime.datetime.now(datetime.UTC),
    )
    print(json.dumps(planned.to_mapping(), indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def _request(paths: CaptureCliPaths) -> CaptureVerifyRequestV1:
    return CaptureVerifyRequestV1.from_mappings(
        {
            "query_manifest": _load(paths.query_manifest),
            "identity": _load(paths.identity),
            "catalog": _load(paths.catalog),
            "plan": _load(paths.plan),
        }
    )


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))


def _inspect_kind(raw: str) -> CaptureInspectKind:
    match raw:  # noqa: MATCH_OK
        case "query-manifest":
            return CaptureInspectKind.QUERY_MANIFEST
        case "catalog":
            return CaptureInspectKind.CATALOG
        case "identity":
            return CaptureInspectKind.IDENTITY
        case "plan":
            return CaptureInspectKind.PLAN
        case _:
            raise UnifiedDbExportError("unknown capture inspect kind")


def _parse_kind(kind: CaptureInspectKind, data: dict[str, JsonValue]) -> dict[str, JsonValue]:
    match kind:  # noqa: MATCH_OK
        case CaptureInspectKind.QUERY_MANIFEST:
            return PostgresCaptureQueryManifestV1.from_mapping(data).to_mapping()
        case CaptureInspectKind.CATALOG:
            return PostgresCatalogSnapshotV1.from_mapping(data).to_mapping()
        case CaptureInspectKind.IDENTITY:
            return PostgresIdentityReceiptV1.from_mapping(data).to_mapping()
        case CaptureInspectKind.PLAN:
            return PostgresCapturePlanV1.from_mapping(data).to_mapping()
