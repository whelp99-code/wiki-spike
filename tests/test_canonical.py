import unicodedata

import pytest

from wiki_spike.canonical import CanonicalizationError, canonical_bytes
from wiki_spike.hashing import canonical_hash


def test_nfc_and_nfd_hash_equal():
    # "각" composed (NFC) vs decomposed (NFD) must canonicalize identically.
    nfc = unicodedata.normalize("NFC", "각")
    nfd = unicodedata.normalize("NFD", "각")
    assert nfc != nfd  # different byte sequences going in
    assert canonical_hash({"k": nfc}) == canonical_hash({"k": nfd})


def test_key_order_independent():
    assert canonical_bytes({"b": "1", "a": "2"}) == canonical_bytes({"a": "2", "b": "1"})


def test_raw_numbers_forbidden():
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"n": 1})
    with pytest.raises(CanonicalizationError):
        canonical_bytes({"n": 1.5})


def test_bool_allowed():
    # bool is a subclass of int but is a valid JSON scalar
    assert canonical_bytes({"b": True}) == b'{"b":true}'
