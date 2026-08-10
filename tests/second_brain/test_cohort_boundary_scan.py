from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from scripts import second_brain_cohort_boundary_scan as TOOL
from wiki_spike.memory_core.contracts import canonical_bytes


def write(path: Path, value: object) -> None:
    if isinstance(value, dict): path.write_bytes(canonical_bytes(value))
    else: path.write_bytes(value)


def fixture(tmp_path: Path) -> dict[str, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    schema = {"deny_class_schema_version": TOOL.DENY_SCHEMA_VERSION, "classes": [{"class_id": c, "rule_id": r} for c in TOOL.MANDATORY_CLASSES for r, _ in TOOL.RULES[c]]}
    paths = {"deny_class_schema": tmp_path / "schema.json", "source_export": tmp_path / "export.bin", "manifest": tmp_path / "manifest.json", "cohort_payload": tmp_path / "payload.bin", "db": tmp_path / "cohort.db", "wal": tmp_path / "cohort.wal", "cas": tmp_path / "cas", "log_dir": tmp_path / "logs", "receipt": tmp_path / "cohort-receipt.json", "out": tmp_path / "scan.json"}
    write(paths["deny_class_schema"], schema)
    for key in ("source_export", "cohort_payload", "db", "wal"): write(paths[key], b"synthetic-clean-boundary")
    write(paths["manifest"], {"manifest": "synthetic-clean-boundary"}); write(paths["receipt"], {"receipt": "synthetic-clean-boundary"})
    paths["cas"].mkdir(); paths["log_dir"].mkdir(); (paths["cas"] / "nested").mkdir(); (paths["log_dir"] / "nested").mkdir()
    write(paths["cas"] / "nested" / "object.bin", b"synthetic-clean-boundary"); write(paths["log_dir"] / "nested" / "event.log", b"synthetic-clean-boundary")
    return paths


def argv(paths: dict[str, Path]) -> list[str]:
    result = ["verify"]
    for key in ("deny_class_schema", "source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log_dir", "receipt", "out"):
        result.extend(["--" + key.replace("_", "-"), str(paths[key])])
    return result


def test_clean_full_boundary_passes_and_receipt_is_deterministic_hash_only(tmp_path):
    first, second = fixture(tmp_path / "one"), fixture(tmp_path / "two")
    assert TOOL.main(argv(first)) == 0 and TOOL.main(argv(second)) == 0
    receipt = json.loads(first["out"].read_bytes())
    assert first["out"].read_bytes() == second["out"].read_bytes() == canonical_bytes(receipt)
    assert receipt["result"] == "PASS" and receipt["no_import"] is False
    assert {item["surface_id"] for item in receipt["surfaces"]} == {"source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log", "cohort_receipt"}
    assert b"synthetic-clean-boundary" not in first["out"].read_bytes()
    assert all(set(item) >= {"surface_id", "path_digest"} and len(item["path_digest"]) == 64 for item in receipt["surfaces"])
    assert all("relative_path" not in item for item in receipt["surfaces"] + receipt["findings"])


def test_port_contract_is_hash_only_and_fail_closed():
    from wiki_spike.memory_core.second_brain_ports import CohortBoundaryScanFindingV1, CohortBoundaryScanRequestV1, CohortBoundaryScanResultV1
    result = CohortBoundaryScanResultV1("QUARANTINED", True, (CohortBoundaryScanFindingV1("db", TOOL._path_digest("db", "."), "a" * 64, "credential", "literal-credential-marker"),))
    surfaces = tuple((name, TOOL._path_digest(name, "."), "a" * 64) for name in ("cas", "cohort_payload", "cohort_receipt", "db", "log", "manifest", "source_export", "wal"))
    assert CohortBoundaryScanRequestV1(TOOL.SCANNER_VERSION, "a" * 64, surfaces).scanner_version == TOOL.SCANNER_VERSION
    assert result.no_import is True and not hasattr(result.findings[0], "matched_content")


def test_empty_trees_still_emit_root_inventory_summaries(tmp_path):
    paths = fixture(tmp_path); (paths["cas"] / "nested" / "object.bin").unlink(); (paths["log_dir"] / "nested" / "event.log").unlink()
    assert TOOL.main(argv(paths)) == 0
    roots = [item for item in json.loads(paths["out"].read_bytes())["surfaces"] if item["path_digest"] == TOOL._path_digest(item["surface_id"], ".") and item["surface_id"] in {"cas", "log"}]
    assert len(roots) == 2 and all(item["inventory_count"] == "0" for item in roots)


def test_port_contract_rejects_contradictory_states():
    from wiki_spike.memory_core.second_brain_ports import CohortBoundaryScanResultV1
    import pytest
    with pytest.raises(ValueError): CohortBoundaryScanResultV1("PASS", True, ())


def test_cli_help_is_success_but_invalid_invocation_is_rejected():
    script = Path(__file__).resolve().parents[2] / "scripts" / "second_brain_cohort_boundary_scan.py"
    for arguments, expected in ((["--help"], 0), (["verify", "--help"], 0), (["verify"], 2)):
        result = subprocess.run([sys.executable, str(script), *arguments], text=True, capture_output=True, check=False)
        assert result.returncode == expected
