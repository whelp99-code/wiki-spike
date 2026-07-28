"""Compatibility bridge isolation checks."""
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).parents[3]


def test_v1_mcp_factory_is_explicitly_compatibility_only() -> None:
    source = (ROOT / "src/wiki_spike/composition/compat_mcp_v1.py").read_text()
    assert "def create_compat_mcp_v1(" in source
    assert "from wiki_spike.infrastructure.mcp import McpNonceGuard, McpServer" in source


def test_product_entrypoints_do_not_import_the_v1_factory_or_legacy_runtime() -> None:
    for relative in (
        "src/wiki_spike/cli.py",
        "src/wiki_spike/composition/second_brain_product.py",
        "src/wiki_spike/composition/api_v2.py",
        "src/wiki_spike/composition/mcp_v2.py",
    ):
        source = (ROOT / relative).read_text()
        assert "compat_mcp_v1" not in source
        assert "wiki_spike.workspace import" not in source
        assert "McpServer" not in source
