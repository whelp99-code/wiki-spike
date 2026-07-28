from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_product_root_is_the_only_stage3_composition_surface():
    source = (ROOT / "src/wiki_spike/composition/second_brain_product.py").read_text()
    assert "require_security_context_authority(authority)" in source
    assert "LifecycleLedgerAuthority(database, cas)" in source
    assert "SecondBrainLedgerService" in source
    assert "SecondBrainRecallService" in source
    assert "Workspace" not in source
    assert "McpServer" not in source
    assert "dek" not in source.lower()
    assert "Gate8" not in source


def test_root_validates_before_constructing_ledger_authority():
    source = (ROOT / "src/wiki_spike/composition/second_brain_product.py").read_text()
    assert source.index("require_security_context_authority(authority)") < source.index("LifecycleLedgerAuthority(database, cas)")
