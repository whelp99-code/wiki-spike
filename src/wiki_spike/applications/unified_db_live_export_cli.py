"""Public inspect/verify/preflight for body-free live-export contracts."""
from __future__ import annotations

import argparse
import datetime
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, Protocol, assert_never

from wiki_spike.applications.unified_db_live_export_preflight import (
    preflight_live_export,
)
from wiki_spike.applications.unified_db_live_export_verify import (
    LiveExportVerifyRequestV1,
    verify_live_export_plan,
)
from wiki_spike.applications.unified_db_snapshot_export_io import (
    HARD_CAP,
    read_bounded_path,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.unified_db_live_export_commitments import (
    UnifiedDbLiveExportAdapterV1,
    UnifiedDbLiveExportDestinationV1,
    UnifiedDbWriterQuiescenceV1,
)
from wiki_spike.memory_core.unified_db_live_export_mapping import (
    UnifiedDbLiveExportMappingV1,
)
from wiki_spike.memory_core.unified_db_live_export_plan import UnifiedDbLiveExportPlanV1
from wiki_spike.memory_core.unified_db_live_export_registry import (
    PRODUCTION_MAPPER_REGISTRY,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)
from wiki_spike.memory_core.unified_db_snapshot_export import UnifiedDbExportError
from wiki_spike.memory_core.unified_db_snapshot_export_json import decode_json_object

LIVE_CONTRACT_COMMANDS: Final = frozenset(
    {"live-inspect", "live-verify", "live-preflight"}
)
INSPECT_KINDS: Final = (
    "identity",
    "mapping",
    "adapter",
    "destination",
    "quiescence",
    "plan",
)


class SubparserRegistrar(Protocol):
    def add_parser(self, name: str, *, help: str = ...) -> argparse.ArgumentParser: ...


class LiveExportInspectKind(StrEnum):
    IDENTITY = "identity"
    MAPPING = "mapping"
    ADAPTER = "adapter"
    DESTINATION = "destination"
    QUIESCENCE = "quiescence"
    PLAN = "plan"


@dataclass(frozen=True, slots=True)
class LiveExportCliPaths:
    kind: str
    input_path: Path
    plan: Path
    identity: Path
    mapping: Path
    adapter: Path
    destination: Path
    quiescence: Path
    authorization: Path


def is_live_contract_command(command: str) -> bool:
    return command in LIVE_CONTRACT_COMMANDS


def register_live_parsers(sub: SubparserRegistrar) -> None:
    inspect = sub.add_parser("live-inspect", help="inspect a body-free live-export contract")
    _ = inspect.add_argument("--kind", required=True, choices=INSPECT_KINDS)
    _ = inspect.add_argument("--input", dest="input_path", required=True, type=Path)
    live_verify = sub.add_parser("live-verify", help="verify live-export contract bindings")
    live_preflight = sub.add_parser(
        "live-preflight", help="preflight live export against the empty production registry"
    )
    for live in (live_verify, live_preflight):
        _ = live.add_argument("--plan", required=True, type=Path)
        _ = live.add_argument("--identity", required=True, type=Path)
        _ = live.add_argument("--mapping", required=True, type=Path)
        _ = live.add_argument("--adapter", required=True, type=Path)
        _ = live.add_argument("--destination", required=True, type=Path)
        _ = live.add_argument("--quiescence", required=True, type=Path)
        _ = live.add_argument("--authorization", required=True, type=Path)


def run_live_contract_command(command: str, paths: LiveExportCliPaths) -> int:
    if command == "live-inspect":
        return inspect_live_contract(paths.kind, paths.input_path)
    if command == "live-verify":
        return verify_live_contracts(paths)
    if command == "live-preflight":
        return preflight_live_contracts(paths)
    raise UnifiedDbExportError(f"unknown live contract command: {command}")


def inspect_live_contract(kind: str, path: Path) -> int:
    parsed = _parse_kind(_inspect_kind(kind), _load(path))
    print(json.dumps(parsed, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


def verify_live_contracts(paths: LiveExportCliPaths) -> int:
    request = _request(paths)
    verify_live_export_plan(request, datetime.datetime.now(datetime.UTC))
    print(json.dumps({"verified": True}, indent=2, sort_keys=True))
    return 0


def preflight_live_contracts(paths: LiveExportCliPaths) -> int:
    request = _request(paths)
    preflight_live_export(
        request,
        PRODUCTION_MAPPER_REGISTRY,
        datetime.datetime.now(datetime.UTC),
    )
    print(json.dumps({"preflight": True}, indent=2, sort_keys=True))
    return 0


def _request(paths: LiveExportCliPaths) -> LiveExportVerifyRequestV1:
    return LiveExportVerifyRequestV1.from_mappings(
        {
            "identity": _load(paths.identity),
            "mapping": _load(paths.mapping),
            "adapter": _load(paths.adapter),
            "destination": _load(paths.destination),
            "quiescence": _load(paths.quiescence),
            "plan": _load(paths.plan),
            "authorization": _load(paths.authorization),
        }
    )


def _load(path: Path) -> dict[str, JsonValue]:
    return decode_json_object(read_bounded_path(path, HARD_CAP).decode("utf-8"))


def _inspect_kind(raw: str) -> LiveExportInspectKind:
    if raw == "identity":
        return LiveExportInspectKind.IDENTITY
    if raw == "mapping":
        return LiveExportInspectKind.MAPPING
    if raw == "adapter":
        return LiveExportInspectKind.ADAPTER
    if raw == "destination":
        return LiveExportInspectKind.DESTINATION
    if raw == "quiescence":
        return LiveExportInspectKind.QUIESCENCE
    if raw == "plan":
        return LiveExportInspectKind.PLAN
    raise UnifiedDbExportError("unknown live inspect kind")


def _parse_kind(kind: LiveExportInspectKind, data: dict[str, JsonValue]) -> dict[str, JsonValue]:
    match kind:
        case LiveExportInspectKind.IDENTITY:
            return PostgresIdentityReceiptV1.from_mapping(data).to_mapping()
        case LiveExportInspectKind.MAPPING:
            return UnifiedDbLiveExportMappingV1.from_mapping(data).to_mapping()
        case LiveExportInspectKind.ADAPTER:
            return UnifiedDbLiveExportAdapterV1.from_mapping(data).to_mapping()
        case LiveExportInspectKind.DESTINATION:
            return UnifiedDbLiveExportDestinationV1.from_mapping(data).to_mapping()
        case LiveExportInspectKind.QUIESCENCE:
            return UnifiedDbWriterQuiescenceV1.from_mapping(data).to_mapping()
        case LiveExportInspectKind.PLAN:
            return UnifiedDbLiveExportPlanV1.from_mapping(data).to_mapping()
        case _:
            assert_never(kind)
