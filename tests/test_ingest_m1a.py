"""M1a acceptance (v3.3 §14): normal source -> Claim IR + CAS storage, no publication."""
from pathlib import Path

from wiki_spike.cas import ContentAddressedStore
from wiki_spike.claims import DeterministicMockExtractor
from wiki_spike.ingest import IngestService

FIX = Path(__file__).parent / "fixtures"


def _svc(tmp_path):
    return IngestService(ContentAddressedStore(tmp_path / "cas"), DeterministicMockExtractor())


def test_m1a_normal_receive_and_compile(tmp_path):
    svc = _svc(tmp_path)
    r = svc.receive(FIX / "normal.md")
    assert r.status == "staged"
    assert not r.idempotent

    c = svc.compile(r.source_id)
    assert c.status == "validated"
    # normal.md has 3 well-formed claim lines
    assert len(c.claims) == 3

    # Every assertion is traceable to an Evidence text_span locator (round-trip).
    for claim in c.claims:
        loc = claim.evidence.locators[0]
        assert loc["type"] == "text_span"
        assert int(loc["end"]) > int(loc["start"])


def test_m1a_polarity_distinguished_end_to_end(tmp_path):
    svc = _svc(tmp_path)
    r = svc.receive(FIX / "normal.md")
    c = svc.compile(r.source_id)
    ids = {claim.identity.claim_id for claim in c.claims}
    # The two "Product A supports feature X" lines differ only in polarity ->
    # they must be distinct claims (not collapsed).
    assert len(ids) == 3


def test_m1a_idempotent_receive(tmp_path):
    svc = _svc(tmp_path)
    r1 = svc.receive(FIX / "normal.md")
    r2 = svc.receive(FIX / "normal.md")
    assert r1.content_hash == r2.content_hash
    assert r2.idempotent  # second receive is a no-op


def test_m1a_injection_string_is_data_not_quarantined(tmp_path):
    # §7 false-positive fix: an injection string in the body is inert data.
    svc = _svc(tmp_path)
    r = svc.receive(FIX / "instruction_data.md")
    assert r.status == "staged"  # NOT quarantined
    c = svc.compile(r.source_id)
    # The injection prose is ignored; only the well-formed claim line is compiled.
    assert len(c.claims) == 1
    assert c.claims[0].identity.subject_id == "Product D"


def test_m1a_no_publication_surface(tmp_path):
    # Phase 1a must expose no publish/commit path.
    svc = _svc(tmp_path)
    assert not hasattr(svc, "publish")
    assert not hasattr(svc, "commit")
