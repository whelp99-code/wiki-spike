from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_transports_expose_only_identical_bounded_v2_operations():
    api = (ROOT / "src/wiki_spike/composition/api_v2.py").read_text()
    mcp = (ROOT / "src/wiki_spike/composition/mcp_v2.py").read_text()
    for operation in ("command", "recall", "citation", "status"):
        assert f"def {operation}(" in api
        assert f"def {operation}(" in mcp
    for forbidden in ("list", "dump", "Workspace", "McpServer", "raw_key", "derived_key", "artifact", "blob", "Gate8"):
        assert forbidden not in api
        assert forbidden not in mcp


def test_api_has_required_capability_scope_and_replay_checks():
    api = (ROOT / "src/wiki_spike/composition/api_v2.py").read_text()
    assert "class CapabilityUseV2" in api
    assert "capability action is out of scope" in api
    assert "capability use was replayed" in api
    assert "nonce exceeds bound" in api
    assert "self._product.authority.require()" in api
