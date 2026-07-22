from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from wiki_spike.memory_core import (
    CONTRACT_VERSION,
    CapabilityToken,
    CommandEnvelope,
    CoreResult,
    MemoryCommandGateway,
    Sensitivity,
)


class Reader:
    def __init__(self, current="gen-1"):
        self.current = current

    def current_generation_id(self, workspace_id):
        return self.current


class Resolver:
    def __init__(self, actions=frozenset({"memory.revise"})):
        self.actions = actions

    def resolve(self, workspace_id, actor_id):
        return CapabilityToken(
            token_id="tok-1",
            workspace_id=workspace_id,
            actor_id=actor_id,
            actions=self.actions,
            max_sensitivity=Sensitivity.PRIVATE,
            expires_at="2026-07-23T00:00:00Z",
        )


class Handler:
    def __init__(self, reader, *, fail=False):
        self.reader = reader
        self.fail = fail
        self.calls = 0

    def handle(self, command):
        self.calls += 1
        if self.fail:
            raise RuntimeError("temporary")
        self.reader.current = "gen-2"
        return CoreResult(CONTRACT_VERSION, command.command_id, "accepted", "gen-2", {"memory_id": "mem-1"})


def command(*, command_id="cmd-1", idempotency_key="idem-1", expected="gen-1", body="first"):
    return CommandEnvelope.create(
        command_id=command_id,
        idempotency_key=idempotency_key,
        workspace_id="ws-1",
        actor_id="user-1",
        command_type="memory.revise",
        expected_generation_id=expected,
        payload={"body": body, "sensitivity": "private"},
    )


def gateway(reader=None, resolver=None, handler=None):
    reader = reader or Reader()
    handler = handler or Handler(reader)
    return MemoryCommandGateway(
        reader,
        resolver or Resolver(),
        handler,
        now="2026-07-22T00:00:00Z",
    ), reader, handler


def test_replay_returns_identical_result_without_second_handler_call():
    api, _, handler = gateway()
    first = api.execute(command())
    second = api.execute(command())
    assert first is second
    assert handler.calls == 1


def test_same_idempotency_key_with_different_payload_is_rejected():
    api, _, handler = gateway()
    assert api.execute(command(body="one")).status == "accepted"
    result = api.execute(command(body="two"))
    assert result.status == "rejected"
    assert result.error_code == "idempotency_payload_mismatch"
    assert handler.calls == 1


def test_stale_expected_generation_returns_retry_later_without_handler_or_pointer_change():
    reader = Reader("gen-2")
    api, _, handler = gateway(reader=reader)
    result = api.execute(command(expected="gen-1"))
    assert result.status == "retry_later"
    assert result.error_code == "stale_generation"
    assert result.generation_id == "gen-2"
    assert reader.current == "gen-2"
    assert handler.calls == 0


def test_policy_denial_does_not_invoke_handler_or_change_pointer():
    reader = Reader()
    api, _, handler = gateway(reader=reader, resolver=Resolver(actions=frozenset({"memory.read"})))
    result = api.execute(command())
    assert result.status == "rejected"
    assert result.error_code == "capability_missing"
    assert reader.current == "gen-1"
    assert handler.calls == 0


def test_retry_later_handler_failure_is_not_cached():
    reader = Reader()
    handler = Handler(reader, fail=True)
    api, _, _ = gateway(reader=reader, handler=handler)
    first = api.execute(command())
    assert first.status == "retry_later"
    assert first.error_code == "handler_unavailable"
    handler.fail = False
    second = api.execute(command())
    assert second.status == "accepted"
    assert handler.calls == 2


def test_concurrent_revise_allows_one_winner_and_one_stale_loser():
    reader = Reader()
    handler = Handler(reader)
    api, _, _ = gateway(reader=reader, handler=handler)
    commands = [
        command(command_id="cmd-a", idempotency_key="idem-a"),
        command(command_id="cmd-b", idempotency_key="idem-b"),
    ]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(api.execute, commands))
    assert sorted(result.status for result in results) == ["accepted", "retry_later"]
    assert handler.calls == 1
    assert reader.current == "gen-2"


def test_invalid_sensitivity_is_rejected_before_handler():
    api, _, handler = gateway()
    bad = CommandEnvelope.create(
        command_id="cmd-bad",
        idempotency_key="idem-bad",
        workspace_id="ws-1",
        actor_id="user-1",
        command_type="memory.revise",
        expected_generation_id="gen-1",
        payload={"sensitivity": "ultra"},
    )
    result = api.execute(bad)
    assert result.error_code == "invalid_sensitivity"
    assert handler.calls == 0
