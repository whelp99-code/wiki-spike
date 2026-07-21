import pytest

from wiki_spike.hashing import merkle_root
from wiki_spike.models import (
    ResolutionDecision,
    SourceManifest,
    StateError,
    accepted_claim_set_root,
    compute_claim_id,
)
from wiki_spike.signing import Keyring


# --- state machine -------------------------------------------------------- #
def test_legal_transition():
    m = SourceManifest("s", "c")
    m.transition("staged")
    m.transition("validated")
    m.transition("accepted")
    assert m.status == "accepted"


def test_illegal_transition_rejected():
    m = SourceManifest("s", "c")
    with pytest.raises(StateError):
        m.transition("accepted")  # cannot jump received -> accepted


def test_quarantine_is_terminal():
    m = SourceManifest("s", "c")
    m.transition("quarantined")
    with pytest.raises(StateError):
        m.transition("staged")


# --- signing -------------------------------------------------------------- #
def test_sign_verify_roundtrip():
    kr = Keyring()
    kr.generate("k1")
    sig = kr.sign("k1", b"generation-id-bytes")
    assert kr.verify("k1", b"generation-id-bytes", sig)


def test_verify_fails_wrong_payload():
    kr = Keyring()
    kr.generate("k1")
    sig = kr.sign("k1", b"payload-a")
    assert not kr.verify("k1", b"payload-b", sig)


def test_verify_fails_unknown_key():
    kr = Keyring()
    kr.generate("k1")
    sig = kr.sign("k1", b"x")
    assert not kr.verify("k2", b"x", sig)


def test_rotation_keeps_old_key_verifiable():
    kr = Keyring()
    kr.generate("k_old")
    old_sig = kr.sign("k_old", b"gen1")
    kr.generate("k_new")  # rotate; old key retained
    assert kr.verify("k_old", b"gen1", old_sig)
    assert kr.verify("k_new", b"gen2", kr.sign("k_new", b"gen2"))


# --- merkle / acyclicity -------------------------------------------------- #
def test_merkle_order_independent():
    a = ResolutionDecision("c1", "accepted", ("a1",), "p1", "r")
    b = ResolutionDecision("c2", "accepted", ("a2",), "p1", "r")
    assert accepted_claim_set_root([a, b]) == accepted_claim_set_root([b, a])


def test_merkle_empty_is_stable():
    assert accepted_claim_set_root([]) == accepted_claim_set_root([])


def test_resolution_decision_has_no_generation_id():
    # Acyclicity guarantee: a decision record cannot carry generation_id.
    d = ResolutionDecision("c1", "accepted", ("a1",), "p1", "r")
    assert "generation_id" not in d.canonical()


# --- claim identity: polarity matters ------------------------------------- #
def test_polarity_changes_claim_id():
    pos = compute_claim_id("A", "supports", "X", "positive", {"v": "2026"})
    neg = compute_claim_id("A", "supports", "X", "negative", {"v": "2026"})
    assert pos != neg


def test_scope_changes_claim_id():
    a = compute_claim_id("A", "supports", "X", "positive", {"product_version": "2025"})
    b = compute_claim_id("A", "supports", "X", "positive", {"product_version": "2026"})
    assert a != b
