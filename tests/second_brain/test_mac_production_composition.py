"""Installed Mac production composition refuses storage and network constructors."""
from __future__ import annotations

import ast
import json
from pathlib import Path

from wiki_spike.composition.mac_production import (
    PINNED_EXPECTED_SCOPE_MANIFEST,
    PINNED_TRUSTED_KEYS,
)
from wiki_spike.memory_core.contracts import canonical_bytes
from wiki_spike.memory_core.second_brain_contracts import ExpectedScopeManifestV1

COMPOSITION = Path("src/wiki_spike/composition/mac_production.py")
ADMIT = Path("src/wiki_spike/composition/mac_production_admit.py")
COMPOSE = Path("src/wiki_spike/composition/mac_production_compose.py")
PYPROJECT = Path("pyproject.toml")
COMMITTED_BINDINGS = Path(
    "artifacts/product-release/second-brain-v1/governance/trusted-bindings.json"
)
PACKAGED_BINDINGS = Path("src/wiki_spike/resources/trusted-bindings.json")
COMMITTED_SCOPES = Path(
    "artifacts/product-release/second-brain-v1/governance/expected-scopes.json"
)
PACKAGED_SCOPES = Path("src/wiki_spike/resources/expected-scopes.json")
BANNED_IMPORTS = {
    "http",
    "importlib",
    "multiprocessing",
    "requests",
    "socket",
    "sqlite3",
    "subprocess",
    "urllib",
    "wiki_spike.infrastructure.encrypted_cas",
    "wiki_spike.infrastructure.lifecycle_db",
    "wiki_spike.infrastructure.macos_keychain",
    "wiki_spike.infrastructure.macos_keychain_backend",
}
NETWORK_BANNED = {
    "http",
    "multiprocessing",
    "requests",
    "socket",
    "subprocess",
    "urllib",
}


def _imported(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
            names.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"__import__", "eval", "exec"}:
                names.add(node.func.id)
    return names


def test_mac_production_does_not_import_storage_or_network_constructors() -> None:
    imported = _imported(COMPOSITION)
    assert BANNED_IMPORTS.isdisjoint(imported), sorted(imported & BANNED_IMPORTS)
    for path in (COMPOSITION, ADMIT, COMPOSE):
        names = _imported(path)
        assert NETWORK_BANNED.isdisjoint(names), (path, sorted(names & NETWORK_BANNED))


def test_installed_wiki_entry_points_at_cli_main() -> None:
    assert 'wiki = "wiki_spike.cli:main"' in PYPROJECT.read_text(encoding="utf-8")


def test_production_default_pinned_trusted_keys_match_committed_public_bindings() -> None:
    raw = COMMITTED_BINDINGS.read_bytes()
    payload = json.loads(raw)
    aggregate = payload["aggregate_binding"]
    pinned = PINNED_TRUSTED_KEYS.aggregate_bindings
    assert pinned.owner_key_id == "wiki-spike-local-owner-2026"
    assert pinned.approver_key_id == "wiki-spike-local-approver-2026"
    assert pinned.owner_public_key_b64 == aggregate["owner_public_key_b64"]
    assert pinned.approver_public_key_b64 == aggregate["approver_public_key_b64"]
    identities: set[tuple[str, str, str | None]] = set()
    for entry in payload["decision_bindings"]:
        identity = (entry["decision_id"], entry["scope_kind"], entry["scope_name"])
        binding = PINNED_TRUSTED_KEYS.decision_bindings[identity]
        assert binding.owner_key_id == "wiki-spike-local-owner-2026"
        assert binding.approver_key_id == "wiki-spike-local-approver-2026"
        assert binding.owner_public_key_b64 == entry["owner_public_key_b64"]
        assert binding.approver_public_key_b64 == entry["approver_public_key_b64"]
        identities.add(identity)
    assert set(PINNED_TRUSTED_KEYS.decision_bindings) == identities
    assert PACKAGED_BINDINGS.read_bytes() == raw


def test_production_default_pin_parses_committed_expected_scopes() -> None:
    raw = COMMITTED_SCOPES.read_bytes()
    parsed = ExpectedScopeManifestV1.from_mapping(json.loads(raw))
    assert PINNED_EXPECTED_SCOPE_MANIFEST.digest == parsed.digest
    assert PINNED_EXPECTED_SCOPE_MANIFEST == parsed
    assert PACKAGED_SCOPES.read_bytes() == raw


def test_packaged_trust_files_are_canonical() -> None:
    for path in (PACKAGED_BINDINGS, PACKAGED_SCOPES, COMMITTED_BINDINGS, COMMITTED_SCOPES):
        raw = path.read_bytes()
        assert raw == canonical_bytes(json.loads(raw))


def test_compose_uses_fixed_keychain_service_and_ark_handle() -> None:
    from wiki_spike.infrastructure.macos_keychain_existing import (
        MAC_KEYCHAIN_SERVICE,
        SERVING_ARK_HANDLE,
    )

    source = Path(
        "src/wiki_spike/composition/mac_production_compose.py"
    ).read_text(encoding="utf-8")
    assert MAC_KEYCHAIN_SERVICE == "wiki-spike.second-brain-v1"
    assert SERVING_ARK_HANDLE == "serving-ark-v1"
    assert "MAC_KEYCHAIN_SERVICE" in source
    assert "SERVING_ARK_HANDLE" in source
