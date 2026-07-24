"""Tests for the Gate 2 dual create-only keystore
(``wiki_spike.infrastructure.keystore``).

Covers ADR-0027 §2 (dual create-only custody) and §3 (binding-aware
reconciliation partition): create-only rejects overwrite; readback proves
usability without leaking the key; destroy yields an absence receipt and
blocks later unwrap; idempotent destroy; reconciliation never destroys an
ACTIVE-bound/mismatched key (corrupt-row-safe -> QUARANTINE_UNKNOWN);
create-only accepts identical-metadata re-create but rejects
mismatched-metadata collision.
"""
from __future__ import annotations

import hashlib
import json
import os

import pytest

from wiki_spike.infrastructure import keystore as ks

NAMESPACE = "workspace-alpha"


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _dek_hex() -> str:
    return os.urandom(32).hex()


def _fresh_store(tmp_path, custodian_dir="platform") -> ks.PlatformKeyStore:
    return ks.PlatformKeyStore(tmp_path / custodian_dir)


# ---------------------------------------------------------------------------
# create_only: reject overwrite, accept identical re-create, reject
# mismatched-metadata collision.
# ---------------------------------------------------------------------------


def test_create_only_first_create_succeeds(tmp_path):
    store = _fresh_store(tmp_path)
    result = store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    assert result.created is True
    assert result.already_exists is False


def test_create_only_identical_metadata_and_dek_is_idempotent_accept(tmp_path):
    store = _fresh_store(tmp_path)
    dek_hex = _dek_hex()
    digest = _digest("intent-1")
    first = store.create_only(NAMESPACE, "handle-1", dek_hex, digest)
    second = store.create_only(NAMESPACE, "handle-1", dek_hex, digest)
    assert first.created is True
    assert second.created is False
    assert second.already_exists is True


def test_create_only_rejects_overwrite_same_intent_different_key_material(tmp_path):
    store = _fresh_store(tmp_path)
    digest = _digest("intent-1")
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)
    with pytest.raises(ks.KeyAlreadyExists):
        store.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)


def test_create_only_rejects_mismatched_metadata_collision(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    with pytest.raises(ks.KeyCollision):
        store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-2"))


def test_create_only_never_recreates_a_destroyed_key(tmp_path):
    store = _fresh_store(tmp_path)
    digest = _digest("intent-1")
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)
    store.destroy(NAMESPACE, "handle-1")
    with pytest.raises(ks.KeyAlreadyDestroyed):
        store.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)


def test_create_only_validates_opaque_namespace_and_handle(tmp_path):
    store = _fresh_store(tmp_path)
    with pytest.raises(ValueError):
        store.create_only("bad ns!", "handle-1", _dek_hex(), _digest("intent-1"))
    with pytest.raises(ValueError):
        store.create_only(NAMESPACE, "bad handle!", _dek_hex(), _digest("intent-1"))


# ---------------------------------------------------------------------------
# readback_challenge: proves usability, never leaks the key.
# ---------------------------------------------------------------------------


def test_readback_challenge_verifies_without_leaking_key_material(tmp_path):
    store = _fresh_store(tmp_path)
    dek_hex = _dek_hex()
    digest = _digest("intent-1")
    store.create_only(NAMESPACE, "handle-1", dek_hex, digest)

    receipt = store.readback_challenge(NAMESPACE, "handle-1")

    assert receipt.verified is True
    assert receipt.metadata_digest == digest
    assert len(receipt.receipt_digest) == 64
    int(receipt.receipt_digest, 16)  # hex digest, not the raw key

    receipt_mapping = receipt.to_mapping()
    serialized = repr(receipt_mapping)
    assert dek_hex not in serialized
    assert "wrapped_dek_hex" not in serialized


def test_readback_challenge_missing_handle_raises_key_not_found(tmp_path):
    store = _fresh_store(tmp_path)
    with pytest.raises(ks.KeyNotFound):
        store.readback_challenge(NAMESPACE, "never-created")


def test_readback_challenge_is_deterministically_fresh_each_call(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    first = store.readback_challenge(NAMESPACE, "handle-1")
    second = store.readback_challenge(NAMESPACE, "handle-1")
    # Each challenge uses a fresh random nonce/plaintext, so receipts differ,
    # but both independently verify usability.
    assert first.receipt_digest != second.receipt_digest
    assert first.verified is True
    assert second.verified is True


# ---------------------------------------------------------------------------
# destroy: absence receipt, blocks later unwrap, idempotent.
# ---------------------------------------------------------------------------


def test_destroy_yields_absence_receipt_and_blocks_later_readback(tmp_path):
    store = _fresh_store(tmp_path)
    digest = _digest("intent-1")
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)

    receipt = store.destroy(NAMESPACE, "handle-1")

    assert receipt.ark_handle == "handle-1"
    assert receipt.prior_metadata_digest == digest
    assert len(receipt.receipt_digest) == 64

    with pytest.raises(ks.KeyDestroyed):
        store.readback_challenge(NAMESPACE, "handle-1")


def test_destroy_is_idempotent(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))

    first = store.destroy(NAMESPACE, "handle-1")
    second = store.destroy(NAMESPACE, "handle-1")

    assert first.receipt_digest == second.receipt_digest
    assert first.destroyed_at == second.destroyed_at


def test_destroy_missing_handle_raises_key_not_found(tmp_path):
    store = _fresh_store(tmp_path)
    with pytest.raises(ks.KeyNotFound):
        store.destroy(NAMESPACE, "never-created")


def test_inventory_lists_handles_and_destroyed_status(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    store.create_only(NAMESPACE, "handle-2", _dek_hex(), _digest("intent-2"))
    store.destroy(NAMESPACE, "handle-2")

    entries = {e.ark_handle: e for e in store.inventory(NAMESPACE)}
    assert entries["handle-1"].destroyed is False
    assert entries["handle-2"].destroyed is True
    assert entries["handle-1"].metadata_digest == _digest("intent-1")

# ---------------------------------------------------------------------------
# Atomic durability: _save never leaves a torn file; corrupt/incomplete
# custody entries fail closed via KeyStoreCorrupt rather than a raw
# json.JSONDecodeError or silent skip.
# ---------------------------------------------------------------------------


def test_save_produces_complete_parseable_file_and_readback_still_works(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))

    path = ks._entry_path(store.root_dir, NAMESPACE, "handle-1")
    assert path.exists()
    # No leftover temp files from the atomic write-then-replace sequence.
    assert list(store.root_dir.glob("*.tmp-*")) == []

    on_disk = json.loads(path.read_text(encoding="utf-8"))
    assert on_disk["ark_handle"] == "handle-1"
    assert on_disk["destroyed"] is False

    receipt = store.readback_challenge(NAMESPACE, "handle-1")
    assert receipt.verified is True


def test_load_raises_keystore_corrupt_on_torn_json(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    path = ks._entry_path(store.root_dir, NAMESPACE, "handle-1")
    path.write_text('{"namespace": "workspace-alpha", "ark_ha', encoding="utf-8")

    with pytest.raises(ks.KeyStoreCorrupt):
        store.readback_challenge(NAMESPACE, "handle-1")
    with pytest.raises(ks.KeyStoreCorrupt):
        store.destroy(NAMESPACE, "handle-1")
    with pytest.raises(ks.KeyStoreCorrupt):
        store.inventory(NAMESPACE)


def test_create_only_raises_keystore_corrupt_on_torn_json(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    path = ks._entry_path(store.root_dir, NAMESPACE, "handle-1")
    path.write_text("not json at all {{{", encoding="utf-8")

    with pytest.raises(ks.KeyStoreCorrupt):
        store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))


def test_load_raises_keystore_corrupt_on_missing_required_key(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    path = ks._entry_path(store.root_dir, NAMESPACE, "handle-1")
    incomplete = json.loads(path.read_text(encoding="utf-8"))
    del incomplete["destroyed"]
    path.write_text(json.dumps(incomplete), encoding="utf-8")

    with pytest.raises(ks.KeyStoreCorrupt):
        store.readback_challenge(NAMESPACE, "handle-1")
    with pytest.raises(ks.KeyStoreCorrupt):
        store.inventory(NAMESPACE)


def test_inventory_does_not_silently_skip_corrupt_entries(tmp_path):
    store = _fresh_store(tmp_path)
    store.create_only(NAMESPACE, "handle-1", _dek_hex(), _digest("intent-1"))
    store.create_only(NAMESPACE, "handle-2", _dek_hex(), _digest("intent-2"))
    corrupt_path = ks._entry_path(store.root_dir, NAMESPACE, "handle-2")
    corrupt_path.write_text('{"broken', encoding="utf-8")

    with pytest.raises(ks.KeyStoreCorrupt):
        store.inventory(NAMESPACE)


# ---------------------------------------------------------------------------
# Two independent custodians (platform + recovery) never share storage.
# ---------------------------------------------------------------------------


def test_platform_and_recovery_stores_are_physically_independent(tmp_path):
    platform = ks.PlatformKeyStore(tmp_path / "platform")
    recovery = ks.RecoveryKeyStore(tmp_path / "recovery")

    digest = _digest("intent-1")
    platform.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)

    # The recovery store has its own independent create-only slot for the
    # same (namespace, ark_handle) — creating it there does not touch or
    # depend on the platform store's entry.
    result = recovery.create_only(NAMESPACE, "handle-1", _dek_hex(), digest)
    assert result.created is True

    platform.destroy(NAMESPACE, "handle-1")
    # Recovery custodian is unaffected by the platform custodian's destroy.
    recovery_receipt = recovery.readback_challenge(NAMESPACE, "handle-1")
    assert recovery_receipt.verified is True


# ---------------------------------------------------------------------------
# ArkKeyIntentState forward-only transitions.
# ---------------------------------------------------------------------------


def test_ark_key_intent_state_happy_path_transitions_forward():
    state = ks.ArkKeyIntentState.KEY_INTENT_PREPARED
    state = ks.transition(state, ks.ArkKeyIntentState.PLATFORM_KEY_VERIFIED)
    state = ks.transition(state, ks.ArkKeyIntentState.RECOVERY_KEY_VERIFIED)
    state = ks.transition(state, ks.ArkKeyIntentState.CAS_MATERIALIZED)
    state = ks.transition(state, ks.ArkKeyIntentState.ACTIVE)
    state = ks.transition(state, ks.ArkKeyIntentState.ORPHAN_PENDING_DESTROY)
    state = ks.transition(state, ks.ArkKeyIntentState.ORPHAN_DESTROYED)
    assert state == ks.ArkKeyIntentState.ORPHAN_DESTROYED


def test_ark_key_intent_state_rejects_backward_and_skip_transitions():
    with pytest.raises(ks.InvalidStateTransition):
        ks.transition(ks.ArkKeyIntentState.PLATFORM_KEY_VERIFIED, ks.ArkKeyIntentState.KEY_INTENT_PREPARED)
    with pytest.raises(ks.InvalidStateTransition):
        ks.transition(ks.ArkKeyIntentState.KEY_INTENT_PREPARED, ks.ArkKeyIntentState.ACTIVE)


def test_ark_key_intent_state_quarantine_reachable_from_any_nonterminal_state():
    for state in ks.ArkKeyIntentState:
        if state in (ks.ArkKeyIntentState.ORPHAN_DESTROYED, ks.ArkKeyIntentState.QUARANTINED):
            continue
        assert ks.transition(state, ks.ArkKeyIntentState.QUARANTINED) == ks.ArkKeyIntentState.QUARANTINED


def test_ark_key_intent_state_terminal_states_have_no_successors():
    with pytest.raises(ks.InvalidStateTransition):
        ks.transition(ks.ArkKeyIntentState.ORPHAN_DESTROYED, ks.ArkKeyIntentState.ACTIVE)
    with pytest.raises(ks.InvalidStateTransition):
        ks.transition(ks.ArkKeyIntentState.QUARANTINED, ks.ArkKeyIntentState.ACTIVE)


# ---------------------------------------------------------------------------
# Binding-aware reconciliation: never destroy ACTIVE-bound or mismatched
# keys; corrupt/missing rows fail closed to QUARANTINE_UNKNOWN.
# ---------------------------------------------------------------------------


def test_reconcile_destroys_only_unbound_loser_or_expired():
    bindings = {
        "h-unbound-implicit": None,
        "h-loser": ks.BindingRecord(status=ks.BindingStatus.LOSER, metadata_digest=_digest("a")),
        "h-expired": ks.BindingRecord(status=ks.BindingStatus.EXPIRED, metadata_digest=_digest("b")),
    }
    # None-valued binding entries represent "no DB row at all" — drop them
    # so `reconcile` sees them as genuinely unbound.
    bindings = {k: v for k, v in bindings.items() if v is not None}
    external = {
        "h-unbound-implicit": ks.ExternalKeyRecord(metadata_digest=_digest("z")),
        "h-loser": ks.ExternalKeyRecord(metadata_digest=_digest("a")),
        "h-expired": ks.ExternalKeyRecord(metadata_digest=_digest("b")),
    }

    outcomes = ks.reconcile(
        bindings, external,
        non_membership_verified_handles=frozenset({"h-unbound-implicit"}),
    )

    assert outcomes["h-unbound-implicit"] == ks.ReconciliationOutcome.DESTROY_UNBOUND
    assert outcomes["h-loser"] == ks.ReconciliationOutcome.DESTROY_UNBOUND
    assert outcomes["h-expired"] == ks.ReconciliationOutcome.DESTROY_UNBOUND


def test_reconcile_unbound_without_non_membership_proof_quarantines():
    """binding=None without a verified non-membership proof fails closed."""
    external = {"h-unknown": ks.ExternalKeyRecord(metadata_digest=_digest("z"))}

    outcomes = ks.reconcile({}, external)

    assert outcomes["h-unknown"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconcile_never_destroys_active_bound_matching_key():
    digest = _digest("active-intent")
    bindings = {"h-active": ks.BindingRecord(status=ks.BindingStatus.ACTIVE, metadata_digest=digest)}
    external = {"h-active": ks.ExternalKeyRecord(metadata_digest=digest)}

    outcomes = ks.reconcile(bindings, external)

    assert outcomes["h-active"] == ks.ReconciliationOutcome.RESUME_EXACT
    assert outcomes["h-active"] != ks.ReconciliationOutcome.DESTROY_UNBOUND


def test_reconcile_active_bound_metadata_mismatch_quarantines_never_destroys():
    bindings = {
        "h-active": ks.BindingRecord(status=ks.BindingStatus.ACTIVE, metadata_digest=_digest("expected"))
    }
    external = {"h-active": ks.ExternalKeyRecord(metadata_digest=_digest("different"))}

    outcomes = ks.reconcile(bindings, external)

    assert outcomes["h-active"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN
    assert outcomes["h-active"] != ks.ReconciliationOutcome.DESTROY_UNBOUND


def test_reconcile_corrupt_external_row_is_quarantined_even_if_db_says_loser():
    bindings = {"h-corrupt": ks.BindingRecord(status=ks.BindingStatus.LOSER, metadata_digest=_digest("a"))}
    external = {"h-corrupt": ks.ExternalKeyRecord(metadata_digest=None, corrupt=True)}

    outcomes = ks.reconcile(bindings, external)

    assert outcomes["h-corrupt"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconcile_missing_external_row_is_quarantined_not_destroyed():
    bindings = {"h-missing": ks.BindingRecord(status=ks.BindingStatus.UNBOUND, metadata_digest=_digest("a"))}
    external: dict[str, ks.ExternalKeyRecord] = {}

    outcomes = ks.reconcile(bindings, external)

    assert outcomes["h-missing"] == ks.ReconciliationOutcome.QUARANTINE_UNKNOWN


def test_reconcile_prepared_binding_exact_metadata_resumes_exact():
    digest = _digest("in-flight-intent")
    bindings = {"h-prepared": ks.BindingRecord(status=ks.BindingStatus.PREPARED, metadata_digest=digest)}
    external = {"h-prepared": ks.ExternalKeyRecord(metadata_digest=digest)}

    outcomes = ks.reconcile(bindings, external)

    assert outcomes["h-prepared"] == ks.ReconciliationOutcome.RESUME_EXACT
