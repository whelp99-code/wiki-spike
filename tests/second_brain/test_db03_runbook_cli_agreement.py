"""The DB-03 runbook section is a contract; pin it against the actual CLI.

`docs/ops/decision-record-signing-runbook.md` tells an operator exactly which
commands to run to produce a signable DB-03 record. Its first line promises the
commands were executed end to end and that the outputs shown are real. Nothing
enforced that afterwards: renaming a flag, adding a required argument, or
dropping a subcommand would leave the runbook quietly wrong, and the only thing
catching it would be a human replaying it by hand.

This checks both directions. Every flag the runbook uses must exist on the
subcommand it is used with, and every required flag of a documented subcommand
must appear in the runbook -- otherwise the documented invocation would fail for
an operator who followed it literally.

Follows the existing doc-agreement convention of `test_decision_doc_slo_agreement.py`
(DB-05) and `test_db07_doc_cutover_agreement.py`.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
RUNBOOK = ROOT / "docs" / "ops" / "decision-record-signing-runbook.md"
SCRIPT = ROOT / "scripts" / "second_brain_migration_source_evidence.py"
SECTION = "## Producing a DB-03 evidence bundle"


def load_tool():
    spec = importlib.util.spec_from_file_location("db03_runbook_tool", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TOOL = load_tool()


def db03_section() -> str:
    text = RUNBOOK.read_text(encoding="utf-8")
    start = text.index(SECTION)
    rest = text[start + len(SECTION):]
    end = rest.find("\n## ")
    return rest if end == -1 else rest[:end]


def documented_invocations() -> dict[str, set[str]]:
    """Map each documented subcommand to the set of flags the runbook uses with it."""
    invocations: dict[str, set[str]] = {}
    for block in re.findall(r"```sh\n(.*?)```", db03_section(), re.DOTALL):
        # Join backslash continuations into single logical commands.
        joined = block.replace("\\\n", " ")
        for line in joined.splitlines():
            line = line.strip()
            if "second_brain_migration_source_evidence.py" not in line:
                continue
            tokens = line.split()
            tail = tokens[tokens.index("scripts/second_brain_migration_source_evidence.py") + 1:]
            if not tail:
                continue
            subcommand, flags = tail[0], {t for t in tail if t.startswith("--")}
            invocations.setdefault(subcommand, set()).update(flags)
    return invocations


def parser_actions() -> dict[str, dict[str, argparse.Action]]:
    """Map each subcommand to its flag-string -> action."""
    sub = next(
        a for a in TOOL.build_parser()._actions
        if isinstance(a, argparse._SubParsersAction)
    )
    return {
        name: {opt: action for action in p._actions for opt in action.option_strings}
        for name, p in sub.choices.items()
    }


def test_the_runbook_documents_the_whole_pipeline():
    documented = documented_invocations()
    assert documented, "the DB-03 section documents no invocations at all"
    # Every step needed to reach an evidence_digest must be shown.
    for required in ("snapshot", "export-profile", "digests", "uniqueness-diff",
                     "history-treatment", "evidence"):
        assert required in documented, f"runbook never shows `{required}`"


@pytest.mark.parametrize("subcommand", sorted(documented_invocations()))
def test_every_flag_the_runbook_uses_exists_on_that_subcommand(subcommand):
    actions = parser_actions()
    assert subcommand in actions, f"runbook documents unknown subcommand `{subcommand}`"
    unknown = documented_invocations()[subcommand] - set(actions[subcommand])
    assert not unknown, f"`{subcommand}` runbook flags that do not exist: {sorted(unknown)}"


@pytest.mark.parametrize("subcommand", sorted(documented_invocations()))
def test_the_runbook_supplies_every_required_flag(subcommand):
    """An operator following the runbook literally must not hit a missing-argument error."""
    actions = parser_actions()[subcommand]
    used = documented_invocations()[subcommand]
    required = {
        action.option_strings[0]
        for action in set(actions.values())
        if action.required and action.option_strings
    }
    missing = required - used
    assert not missing, f"`{subcommand}` runbook omits required flags: {sorted(missing)}"


def test_documented_enum_values_are_accepted_by_the_parser():
    """`--export-method read-only-transaction` must still be a legal choice."""
    actions = parser_actions()
    for block in re.findall(r"```sh\n(.*?)```", db03_section(), re.DOTALL):
        joined = block.replace("\\\n", " ")
        for line in joined.splitlines():
            tokens = line.split()
            if "scripts/second_brain_migration_source_evidence.py" not in tokens:
                continue
            tail = tokens[tokens.index("scripts/second_brain_migration_source_evidence.py") + 1:]
            subcommand = tail[0]
            for flag, value in zip(tail, tail[1:]):
                action = actions.get(subcommand, {}).get(flag)
                if action is not None and action.choices is not None:
                    assert value in action.choices, (
                        f"runbook uses `{flag} {value}` for `{subcommand}`, "
                        f"but the parser allows {sorted(action.choices)}"
                    )
