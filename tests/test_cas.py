import os

import pytest

from wiki_spike.cas import CASError, ContentAddressedStore
from wiki_spike.hashing import sha256_hex


def test_put_is_write_once_readonly(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    digest = cas.put(b"hello")
    path = cas.objects / digest
    mode = os.stat(path).st_mode & 0o777
    assert mode == 0o444  # read-only after commit


def test_put_idempotent(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    d1 = cas.put(b"same")
    d2 = cas.put(b"same")
    assert d1 == d2


def test_address_matches_content(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    digest = cas.put(b"payload")
    assert digest == sha256_hex(b"payload")
    assert cas.get(digest) == b"payload"


def test_get_detects_corruption(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    digest = cas.put(b"data")
    p = cas.objects / digest
    os.chmod(p, 0o644)
    p.write_bytes(b"tampered")
    with pytest.raises(CASError):
        cas.get(digest)


def test_tombstone_retains_blob(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    digest = cas.put(b"keep")
    cas.tombstone(digest, "revoked-by-policy")
    assert cas.is_tombstoned(digest)
    assert cas.exists(digest)  # blob still there (delete-via-tombstone-only)


def test_scan_flags_tampered(tmp_path):
    cas = ContentAddressedStore(tmp_path)
    digest = cas.put(b"orig")
    p = cas.objects / digest
    os.chmod(p, 0o644)
    p.write_bytes(b"changed")
    assert digest in cas.scan()
