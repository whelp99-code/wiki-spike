from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from scripts import second_brain_cohort_boundary_scan as TOOL
from wiki_spike.memory_core.contracts import canonical_bytes
from test_cohort_boundary_scan import argv, fixture, write


@pytest.mark.parametrize("class_id", TOOL.MANDATORY_CLASSES)
@pytest.mark.parametrize("surface", ("source_export", "manifest", "cohort_payload", "db", "wal", "cas", "log_dir", "receipt"))
def test_each_mandatory_class_and_boundary_quarantines_without_content(tmp_path, class_id, surface):
    paths = fixture(tmp_path / f"{class_id}-{surface}"); marker = TOOL.RULES[class_id][0][1]
    target = paths[surface]
    if surface in {"cas", "log_dir"}: target = target / "nested" / "hit.bin"
    write(target, b"prefix-" + marker + b"fixture-only")
    assert TOOL.main(argv(paths)) == 2
    receipt = json.loads(paths["out"].read_bytes())
    assert receipt["result"] == "QUARANTINED" and receipt["no_import"] is True
    assert b"fixture-only" not in paths["out"].read_bytes()


@pytest.mark.parametrize("class_id,rule_id,marker", [(class_id, rule_id, marker) for class_id, rules in TOOL.RULES.items() for rule_id, marker in rules])
def test_every_bounded_production_shaped_rule_is_detected_case_insensitively(tmp_path, class_id, rule_id, marker):
    paths = fixture(tmp_path / rule_id); paths["db"].write_bytes(b"prefix" + marker.upper() + b"fixture")
    assert TOOL.main(argv(paths)) == 2
    raw = paths["out"].read_bytes(); assert b"fixture" not in raw and rule_id.encode() in raw


def test_chunk_boundary_schema_path_and_collision_fail_closed(tmp_path):
    paths = fixture(tmp_path)
    marker = TOOL.RULES["credential"][0][1]; paths["db"].write_bytes(b"x" * (TOOL.CHUNK_SIZE - len(marker) + 2) + marker)
    assert TOOL.main(argv(paths)) == 2
    paths = fixture(tmp_path / "schema")
    schema = json.loads(paths["deny_class_schema"].read_bytes()); schema["classes"].pop(); write(paths["deny_class_schema"], schema)
    assert TOOL.main(argv(paths)) == 2 and not paths["out"].exists()
    paths = fixture(tmp_path / "collision"); paths["out"].write_bytes(b"tampered")
    assert TOOL.main(argv(paths)) == 2 and paths["out"].read_bytes() == b"tampered"
    paths = fixture(tmp_path / "relative"); args = argv(paths); args[args.index("--db") + 1] = "relative.db"
    assert TOOL.main(args) == 2


def test_alias_special_nested_extra_and_atomic_failure_quarantine_or_reject(tmp_path, monkeypatch):
    paths = fixture(tmp_path / "alias"); alias = paths["out"].parent / "alias"; alias.symlink_to(paths["out"].parent, target_is_directory=True)
    args = argv(paths); args[args.index("--cas") + 1] = str(alias / "cas")
    assert TOOL.main(args) == 2
    paths = fixture(tmp_path / "extra"); (paths["cas"] / "link").symlink_to(paths["db"])
    assert TOOL.main(argv(paths)) == 2 and json.loads(paths["out"].read_bytes())["no_import"] is True
    paths = fixture(tmp_path / "atomic"); monkeypatch.setattr(TOOL.os, "fsync", lambda _: (_ for _ in ()).throw(OSError("forced")))
    assert TOOL.main(argv(paths)) == 2 and not paths["out"].exists()


@pytest.mark.parametrize("target", ("db", "cas", "log_dir"))
def test_missing_boundary_surface_emits_quarantined_receipt(tmp_path, target):
    paths = fixture(tmp_path / target)
    if target == "db": paths[target].unlink()
    else:
        import shutil; shutil.rmtree(paths[target])
    assert TOOL.main(argv(paths)) == 2
    receipt = json.loads(paths["out"].read_bytes())
    assert receipt["no_import"] is True and any(item["surface_id"] == ("log" if target == "log_dir" else target) and item["scan_result"] == "INCOMPLETE" for item in receipt["surfaces"])


def test_tree_root_never_claims_clear_when_child_is_denied_or_incomplete(tmp_path):
    paths = fixture(tmp_path / "deny"); write(paths["cas"] / "nested" / "hit", TOOL.RULES["credential"][0][1])
    assert TOOL.main(argv(paths)) == 2
    root = next(item for item in json.loads(paths["out"].read_bytes())["surfaces"] if item["surface_id"] == "cas" and item["path_digest"] == TOOL._path_digest("cas", "."))
    assert root["scan_result"] == "DENY_HIT"
    paths = fixture(tmp_path / "incomplete"); (paths["log_dir"] / "nested" / "bad").symlink_to(paths["db"])
    assert TOOL.main(argv(paths)) == 2
    root = next(item for item in json.loads(paths["out"].read_bytes())["surfaces"] if item["surface_id"] == "log" and item["path_digest"] == TOOL._path_digest("log", "."))
    assert root["scan_result"] == "INCOMPLETE"


def test_file_identity_mismatch_is_quarantined_and_closes_descriptor(tmp_path, monkeypatch):
    paths = fixture(tmp_path); real_fstat = TOOL.os.fstat; opened: list[int] = []
    def mismatch(fd):
        opened.append(fd); current = real_fstat(fd)
        return SimpleNamespace(st_dev=current.st_dev, st_ino=current.st_ino + 1, st_size=current.st_size, st_mtime_ns=current.st_mtime_ns, st_ctime_ns=current.st_ctime_ns)
    monkeypatch.setattr(TOOL.os, "fstat", mismatch)
    assert TOOL.main(argv(paths)) == 2
    assert json.loads(paths["out"].read_bytes())["no_import"] is True
    monkeypatch.setattr(TOOL.os, "fstat", real_fstat)
    with pytest.raises(OSError): real_fstat(opened[0])


def test_directory_inventory_mutation_is_quarantined(tmp_path, monkeypatch):
    paths = fixture(tmp_path); original = TOOL._file; changed = False
    def mutate(path, surface, relative):
        nonlocal changed
        item, findings = original(path, surface, relative)
        if surface == "cas" and not changed:
            changed = True; (paths["cas"] / "new-after-snapshot").write_bytes(b"clean")
        return item, findings
    monkeypatch.setattr(TOOL, "_file", mutate)
    assert TOOL.main(argv(paths)) == 2
    root = next(item for item in json.loads(paths["out"].read_bytes())["surfaces"] if item["surface_id"] == "cas" and item["path_digest"] == TOOL._path_digest("cas", "."))
    assert root["scan_result"] == "INCOMPLETE"


def test_post_link_directory_fsync_failure_removes_its_own_output(tmp_path, monkeypatch):
    paths = fixture(tmp_path); real = TOOL.os.fsync; calls = 0
    def fail_second(fd):
        nonlocal calls
        calls += 1
        if calls == 2: raise OSError("directory fsync failure")
        return real(fd)
    monkeypatch.setattr(TOOL.os, "fsync", fail_second)
    assert TOOL.main(argv(paths)) == 2
    assert not paths["out"].exists()


@pytest.mark.parametrize("directory", (False, True))
def test_sensitive_path_component_quarantines_without_name_leakage(tmp_path, capsys, directory):
    paths = fixture(tmp_path)
    marker = "password=supersecret"
    if directory:
        target_dir = paths["cas"] / marker
        target_dir.mkdir()
        write(target_dir / "clean.bin", b"synthetic-clean-boundary")
    else:
        write(paths["cas"] / "nested" / marker, b"synthetic-clean-boundary")

    assert TOOL.main(argv(paths)) == 2
    captured = capsys.readouterr()
    receipt = paths["out"].read_bytes()
    parsed = json.loads(receipt)
    assert parsed["result"] == "QUARANTINED" and parsed["no_import"] is True
    assert marker not in captured.out and marker not in captured.err and marker.encode() not in receipt
    assert all("relative_path" not in item for item in parsed["surfaces"] + parsed["findings"])
    assert all(len(item["path_digest"]) == 64 for item in parsed["surfaces"] + parsed["findings"])
